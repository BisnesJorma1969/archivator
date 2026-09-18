import contextlib
import io
import shutil
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, IntegrityError, sha256
from poc.archivator_lib.recovery import repair, verify
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json


def flip(path, offset=100):
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

    def test_in_place_repair_never_copies_or_links_archive_members(self):
        self.make_archive()
        original_names = {path.relative_to(self.archive) for path in self.archive.rglob("archive-*")}
        flip(next(self.archive.rglob("*_chunk-*.zst")))
        next(self.archive.rglob("*_metadata_streams.jsonl.zst")).unlink()
        next(self.archive.rglob("*_metadata.vol*.par2")).unlink()
        with patch("shutil.copyfile", side_effect=AssertionError("No repair copies")), \
                patch("shutil.copyfileobj", side_effect=AssertionError("No repair copies")), \
                patch("os.link", side_effect=AssertionError("No repair hard links")), \
                patch("os.symlink", side_effect=AssertionError("No repair symlinks")):
            repair(self.archive)
        self.assertEqual({path.relative_to(self.archive) for path in self.archive.rglob("archive-*")}, original_names)
        self.assertEqual(verify(self.archive), 0)

    def test_scattered_members_are_repaired_using_renames_not_copies(self):
        self.make_archive()
        bucket = self.archive / "scattered"
        bucket.mkdir()
        for path in list(self.archive.rglob("archive-*")):
            if path.is_file() and "_complete" not in path.name:
                path.rename(bucket / path.name)
        unrelated = bucket / "notes.txt"
        unrelated.write_text("leave this alone")
        flip(next(bucket.glob("*_chunk-*.zst")))
        with patch("shutil.copyfile", side_effect=AssertionError("No repair copies")), \
                patch("os.link", side_effect=AssertionError("No repair hard links")):
            repair(self.archive)
        self.assertEqual(list(bucket.iterdir()), [unrelated])
        self.assertEqual(unrelated.read_text(), "leave this alone")
        self.assertEqual(verify(self.archive), 0)

    def test_verify_intact_and_repairable_without_changing_archive(self):
        self.make_archive()
        self.assertEqual(verify(self.archive), 0)
        flip(next(self.archive.rglob("*_chunk-*.zst")))
        before = snapshot(self.archive)
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            self.assertEqual(verify(self.archive), 1)
        self.assertIn("repairable", report.getvalue())
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_repair_missing_chunk_and_parity_only_damage(self):
        self.make_archive()
        next(self.archive.rglob("*_chunk-*.zst")).unlink()
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        volume = next(path for path in self.archive.rglob("*.vol*.par2") if "_metadata." not in path.name)
        volume.unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertTrue(volume.exists())
        self.assertEqual(verify(self.archive), 0)

    def test_damaged_catalog_and_checksum_index_are_recovered_in_scratch(self):
        self.make_archive()
        for pattern in ("*_metadata_streams.jsonl.zst", "*_metadata_checksums.json.zst"):
            path = next(self.archive.rglob(pattern))
            path.unlink()
            before = snapshot(self.archive)
            self.assertEqual(verify(self.archive), 1)
            self.assertEqual(snapshot(self.archive), before)
            repair(self.archive)
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
        manifests = [read_zstd_json(path) for path in self.archive.rglob("*_parity-*_manifest.json.zst")]
        manifest = next(item for item in manifests if item["member_count"] == 8)
        largest = sorted(manifest["members"], key=lambda member: member["stored_length"], reverse=True)[:2]
        missing_blocks = sum((member["stored_length"] + manifest["slice_size"] - 1) // manifest["slice_size"]
                             for member in largest)
        self.assertGreater(missing_blocks, manifest["recovery_blocks"])
        for member in largest:
            next(self.archive.rglob(member["filename"])).unlink()
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            self.assertEqual(verify(self.archive), 1)
        self.assertIn("unrecoverable", report.getvalue())
        with self.assertRaises(IntegrityError):
            repair(self.archive)

    def test_mixed_archives_verify_all_but_repair_requires_selection(self):
        archive_id = self.make_archive()
        other_source = self.root / "other-source"
        other_source.mkdir()
        other_archive = self.root / "other-archive"
        backup(other_source, other_archive, settings=SMALL)
        for path in other_archive.rglob("archive-*"):
            shutil.copyfile(path, self.archive / path.name)
        self.assertEqual(verify(self.archive), 0)
        with self.assertRaises(ArchiveError):
            repair(self.archive)
        repair(self.archive, archive_id)

    def test_incomplete_archive_is_reported(self):
        self.make_archive()
        for path in self.archive.rglob("*_complete*.json"):
            path.unlink()
        self.assertEqual(verify(self.archive), 1)
        with self.assertRaises(IntegrityError):
            repair(self.archive)

    def test_metadata_parity_damage_is_replenished(self):
        self.make_archive()
        volume = next(self.archive.rglob("*_metadata.vol*.par2"))
        flip(volume)
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
