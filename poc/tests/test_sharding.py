from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, sha256
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import parse_chunk
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class ShardingTests(ArchiveTest):
    def test_output_uses_only_populated_parity_prefix_directories(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        expected_shards = set()
        for path in self.archive.rglob("archive-*"):
            if "_metadata_" in path.name or "_metadata." in path.name:
                self.assertEqual(path.parent, self.archive)
            elif "_chunk-" in path.name:
                parity_id = parse_chunk(path.name)["parity"]
                expected_shards.add(parity_id[:2])
                self.assertEqual(path.parent.name, parity_id[:2])
            else:
                self.assertEqual(path.parent.name, path.name.split("_parity-")[1][:2])
        shards = [path for path in self.archive.iterdir() if path.is_dir()]
        self.assertEqual({path.name for path in shards}, expected_shards)
        self.assertTrue(all(any(path.iterdir()) for path in shards))
        self.assertFalse(list(self.archive.rglob(".tmp")))
        data_groups = {parse_chunk(path.name)["parity"] for path in self.archive.rglob("*_chunk-*.zst")}
        manifests = list(self.archive.rglob("*_manifest.json.zst"))
        self.assertEqual(len(manifests), len(data_groups))
        self.assertEqual({path.name.split("_parity-")[1].split("_")[0] for path in manifests}, data_groups)

    def test_sharded_manifest_recovers_from_metadata_parity_in_flat_archive(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        manifest = next(self.archive.rglob("*_manifest.json.zst"))
        digest = sha256(manifest)
        manifest.unlink()
        # Discovery must not depend on the stored directory layout.
        for shard in list(self.archive.iterdir()):
            if shard.is_dir():
                for path in shard.iterdir():
                    path.rename(self.archive / path.name)
                shard.rmdir()
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        with patch("shutil.copyfile", side_effect=AssertionError("No repair copies")), \
                patch("os.link", side_effect=AssertionError("No repair hard links")):
            repair(self.archive)
        self.assertEqual(sha256(manifest), digest)
        self.assertEqual(verify(self.archive), 0)
        self.assertFalse(list(self.archive.rglob(".tmp")))

    def test_missing_manifest_cannot_be_repaired_through_shard_symlink(self):
        backup(self.source, self.archive, settings=SMALL)
        manifest = next(self.archive.rglob("*_manifest.json.zst"))
        shard = manifest.parent
        displaced = self.root / "displaced"
        shard.rename(displaced)
        (displaced / manifest.name).unlink()
        shard.symlink_to(displaced, target_is_directory=True)
        before = snapshot(displaced)
        with self.assertRaisesRegex(ArchiveError, "not a link"):
            repair(self.archive)
        self.assertEqual(snapshot(displaced), before)

    def test_data_sets_share_shard_while_metadata_stays_at_root(self):
        (self.source / "large").write_bytes(self.data(160000))
        ids = (f"ab{number:030x}" for number in range(100))
        with patch("poc.archivator_lib.format.secrets.token_hex", side_effect=lambda size: next(ids)):
            backup(self.source, self.archive, settings=SMALL)
        self.assertEqual([path.name for path in self.archive.iterdir() if path.is_dir()], ["ab"])
        next(self.archive.rglob("*_metadata_streams.jsonl.zst")).unlink()
        next(self.archive.rglob("*_chunk-*.zst")).unlink()
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual([path.name for path in self.archive.iterdir() if path.is_dir()], ["ab"])
