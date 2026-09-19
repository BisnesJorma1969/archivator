import shutil
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import parse_chunk
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class ShardingTests(ArchiveTest):
    def test_only_populated_data_and_metadata_shards_are_created(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        for path in self.archive.rglob("archive-*"):
            if "_complete" in path.name:
                self.assertEqual(path.parent, self.archive / "metadata")
            else:
                parity_id = path.name.split("_parity-")[1][:32]
                self.assertEqual(path.parent.name, parity_id[:2])
        self.assertFalse(list(self.archive.rglob(".tmp")))
        self.assertTrue(all(any(path.iterdir()) for path in self.archive.rglob("*") if path.is_dir()))

    def test_flat_mixed_layout_and_missing_local_manifest(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        local = next(path for path in self.archive.rglob("*_manifest.json.zst")
                     if "metadata" not in path.relative_to(self.archive).parts)
        local.unlink()
        buckets = [self.archive / "loose-a", self.archive / "loose-b"]
        for bucket in buckets:
            bucket.mkdir()
        for path in list(self.archive.rglob("archive-*")):
            bucket = buckets[1] if (buckets[0] / path.name).exists() else buckets[0]
            path.rename(bucket / path.name)
        before = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertTrue(local.is_file())

    def test_symlink_recovery_directory_is_rejected(self):
        backup(self.source, self.archive, settings=SMALL)
        local = next(path for path in self.archive.rglob("*_manifest.json.zst")
                     if "metadata" not in path.relative_to(self.archive).parts)
        displaced = self.root / "displaced"
        local.parent.rename(displaced)
        local.parent.symlink_to(displaced, target_is_directory=True)
        before = snapshot(displaced)
        with self.assertRaises(ArchiveError):
            repair(self.archive)
        self.assertEqual(snapshot(displaced), before)

    def test_existing_id_prefix_is_reused_without_extra_shard_ids(self):
        (self.source / "large").write_bytes(self.data(160000))
        ids = (f"ab{number:030x}" for number in range(1000))
        with patch("poc.archivator_lib.format.secrets.token_hex", side_effect=lambda size: next(ids)):
            backup(self.source, self.archive, settings=SMALL)
        self.assertEqual({path.name for path in self.archive.iterdir()}, {"ab", "metadata"})
        self.assertTrue((self.archive / "metadata" / "ab").is_dir())
        self.assertEqual(verify(self.archive), 0)
