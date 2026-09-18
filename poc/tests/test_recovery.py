import contextlib
import io
import shutil

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
    return {path.name: (sha256(path), path.stat().st_mtime_ns) for path in directory.iterdir() if path.is_file()}


class RecoveryTests(ArchiveTest):
    def make_archive(self):
        (self.source / "large").write_bytes(self.data(160000))
        return backup(self.source, self.archive, settings=SMALL)

    def test_verify_intact_and_repairable_without_changing_archive(self):
        self.make_archive()
        self.assertEqual(verify(self.archive), 0)
        flip(next(self.archive.glob("*_chunk-*.zst")))
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
        next(self.archive.glob("*_chunk-*.zst")).unlink()
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        volume = next(path for path in self.archive.glob("*.vol*.par2") if "_metadata" not in path.name)
        volume.unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertTrue(volume.exists())
        self.assertEqual(verify(self.archive), 0)

    def test_damaged_catalog_and_checksum_index_are_recovered_in_scratch(self):
        self.make_archive()
        for pattern in ("*_streams.jsonl.zst", "*_checksums.json.zst"):
            path = next(self.archive.glob(pattern))
            path.unlink()
            before = snapshot(self.archive)
            self.assertEqual(verify(self.archive), 1)
            self.assertEqual(snapshot(self.archive), before)
            repair(self.archive)
            self.assertEqual(verify(self.archive), 0)

    def test_all_parity_can_be_regenerated_from_intact_data(self):
        self.make_archive()
        for path in self.archive.glob("*.par2"):
            path.unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_damage_beyond_capacity_fails(self):
        self.make_archive()
        manifests = [read_zstd_json(path) for path in self.archive.glob("*_manifest.json.zst")]
        manifest = next(item for item in manifests if item["member_count"] == 8)
        largest = sorted(manifest["members"], key=lambda member: member["stored_length"], reverse=True)[:2]
        missing_blocks = sum((member["stored_length"] + manifest["slice_size"] - 1) // manifest["slice_size"]
                             for member in largest)
        self.assertGreater(missing_blocks, manifest["recovery_blocks"])
        for member in largest:
            (self.archive / member["filename"]).unlink()
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
        for path in other_archive.iterdir():
            shutil.copyfile(path, self.archive / path.name)
        self.assertEqual(verify(self.archive), 0)
        with self.assertRaises(ArchiveError):
            repair(self.archive)
        repair(self.archive, archive_id)

    def test_incomplete_archive_is_reported(self):
        self.make_archive()
        for path in self.archive.glob("*_complete*.json"):
            path.unlink()
        self.assertEqual(verify(self.archive), 1)
        with self.assertRaises(IntegrityError):
            repair(self.archive)

    def test_metadata_parity_damage_is_replenished(self):
        self.make_archive()
        volume = next(self.archive.glob("*_metadata.vol*.par2"))
        flip(volume)
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
