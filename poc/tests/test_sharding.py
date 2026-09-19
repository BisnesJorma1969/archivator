import shutil
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import parse_chunk, stored_path
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class ShardingTests(ArchiveTest):
    def test_only_populated_data_and_metadata_shards_are_created(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        for path in self.archive.rglob("archive-*"):
            if "_supergroup-" not in path.name:
                self.assertEqual(path.parent, self.archive)
            else:
                datagroup_id = path.name.split("_datagroup-")[1][:20]
                self.assertEqual(path.parent.name, datagroup_id)
                self.assertEqual(path, stored_path(self.archive, path.name))
        self.assertFalse(list(self.archive.rglob(".tmp")))
        self.assertTrue(all(any(path.iterdir()) for path in self.archive.rglob("*") if path.is_dir()))

    def test_flat_layout_has_unique_names_and_recovers_missing_local_manifest(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        local = next(path for path in self.archive.rglob("*_metadata_index-chunks.json.zst")
                     if "metadata" not in path.relative_to(self.archive).parts)
        local.unlink()
        paths = list(self.archive.rglob("archive-*"))
        self.assertEqual(len(paths), len({path.name for path in paths}))
        for path in paths:
            destination = self.archive / path.name
            if path != destination:
                self.assertFalse(destination.exists())
                path.rename(destination)
        before = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertTrue(local.is_file())

    def test_symlink_recovery_directory_is_rejected(self):
        backup(self.source, self.archive, settings=SMALL)
        local = next(path for path in self.archive.rglob("*_metadata_index-chunks.json.zst")
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
        ids = (number.to_bytes(12, "big") for number in range(1000))
        with patch("poc.archivator_lib.format.secrets.token_bytes", side_effect=lambda size: next(ids)):
            backup(self.source, self.archive, settings=SMALL)
        supergroup = parse_chunk(next(self.archive.rglob("*_chunk-*")).name)["supergroup"]
        self.assertEqual({path.name for path in self.archive.iterdir() if path.is_dir()}, {"data", "metadata"})
        self.assertTrue((self.archive / "data" / supergroup[:2] / supergroup).is_dir())
        self.assertTrue((self.archive / "metadata" / supergroup[:2] / supergroup).is_dir())
        self.assertEqual(verify(self.archive), 0)

    def test_case_changed_names_restore_without_changing_source_name_case(self):
        (self.source / 'Report.txt').write_text('upper case source name')
        (self.source / 'report.txt').write_text('lower case source name')
        key, certificate = self.certificate()
        backup(self.source, self.archive, certificate, SMALL)
        for path in sorted(self.archive.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            path.rename(path.with_name(path.name.upper()))
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual(restore(self.archive, self.restored, key=key), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertTrue(all(path.name == path.name.lower() for path in self.archive.rglob('*') if path.is_file()))

    def test_case_colliding_archive_names_are_rejected(self):
        from poc.archivator_lib.recovery import discover
        backup(self.source, self.archive, settings=SMALL)
        path = next(self.archive.glob('*_catalog-root.json'))
        path.with_name(path.name.upper()).write_bytes(path.read_bytes())
        with self.assertRaisesRegex(ArchiveError, 'Duplicate archive filename'):
            discover(self.archive)
