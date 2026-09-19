import shutil
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, IntegrityError, sha256
from poc.archivator_lib.recovery import repair, verify
from poc.tests.support import ArchiveTest, SMALL, manifests


def flip(path, offset=0):
    with path.open("r+b") as output:
        output.seek(offset)
        old = output.read(1)
        output.seek(offset)
        output.write(bytes([old[0] ^ 0xff]))


def snapshot(directory):
    return {str(path.relative_to(directory)): (sha256(path), path.stat().st_mtime_ns)
            for path in directory.rglob("*") if path.is_file()}


class RecoveryTests(ArchiveTest):
    def make_archive(self):
        (self.source / "large").write_bytes(self.data(160000))
        return backup(self.source, self.archive, settings=SMALL)

    def test_in_place_data_repair_never_stages_copies_or_links(self):
        self.make_archive()
        flip(next(self.archive.rglob("*_chunk-*.zst")))
        next(self.archive.rglob("*_datagroup-*_metadata.vol*.par2")).unlink()
        with patch("shutil.copyfile", side_effect=AssertionError("No data staging copies")), \
                patch("os.link", side_effect=AssertionError("No repair hard links")):
            repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_verify_is_read_only_and_reports_repairable_damage(self):
        self.make_archive()
        self.assertEqual(verify(self.archive), 0)
        flip(next(self.archive.rglob("*_chunk-*.zst")))
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        self.assertIn("repairable", self.report.getvalue())
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_repair_missing_chunk_and_parity_only_damage(self):
        self.make_archive()
        next(self.archive.rglob("*_chunk-*.zst")).unlink()
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        volume = next(self.archive.rglob("*.vol*.par2"))
        volume.unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertTrue(volume.exists())
        self.assertEqual(verify(self.archive), 0)

    def test_all_parity_can_be_regenerated_from_intact_data(self):
        self.make_archive()
        for path in self.archive.rglob("*.par2"):
            path.unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_damage_beyond_capacity_fails(self):
        self.make_archive()
        datagroup = next(item for item in manifests(self.archive) if item["members"])
        for member in datagroup["members"]:
            next(self.archive.rglob(member["filename"])).unlink()
        for path in self.archive.rglob(f"*_datagroup-{datagroup['datagroup']}*.par2"):
            path.unlink()
        self.assertEqual(verify(self.archive), 1)
        with self.assertRaises(IntegrityError):
            repair(self.archive)

    def test_mixed_archives_require_selection_for_repair(self):
        archive_id = self.make_archive()
        other_source = self.root / "other-source"
        other_source.mkdir()
        backup(other_source, self.archive / "other-archive", settings=SMALL)
        self.assertEqual(verify(self.archive), 0)
        with self.assertRaises(ArchiveError):
            repair(self.archive)
        repair(self.archive, archive_id)

    def test_metadata_parity_damage_is_replenished(self):
        self.make_archive()
        volume = next(self.archive.rglob("*_datagroup-*_metadata.vol*.par2"))
        flip(volume)
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
