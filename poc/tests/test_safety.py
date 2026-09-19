import contextlib
import io
import os
import tarfile
from unittest.mock import patch

from poc.archivator_lib.backup import backup, tar_info
from poc.archivator_lib.common import ArchiveError, IntegrityError
from poc.archivator_lib.filesystem import check_unchanged, restore_metadata
from poc.archivator_lib.recovery import validate_entries, verify
from poc.archivator_lib.restore import extract_tar
from poc.tests.support import ArchiveTest, SMALL


class SafetyTests(ArchiveTest):
    def test_special_file_is_rejected_before_archive_creation(self):
        os.mkfifo(self.source / "fifo")
        with self.assertRaises(ArchiveError):
            backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(self.archive.exists())

    def test_source_destination_overlap_and_symlink_destination_are_rejected(self):
        with self.assertRaises(ArchiveError):
            backup(self.source, self.source / "archive", settings=SMALL)
        self.archive.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ArchiveError):
            backup(self.source, self.archive, settings=SMALL)

    def test_tar_traversal_does_not_write_outside_target(self):
        bundle_path = self.root / "unsafe.tar"
        with tarfile.open(bundle_path, "w") as bundle:
            member = tarfile.TarInfo("../escaped")
            member.size = 1
            bundle.addfile(member, io.BytesIO(b"x"))
        self.restored.mkdir()
        with self.assertRaises(IntegrityError):
            extract_tar(bundle_path, self.restored, [])
        self.assertFalse((self.root / "escaped").exists())

    def test_symlink_ancestor_in_inventory_is_rejected(self):
        entries = [
            {"path": ".", "type": "directory", "mode": 0o755, "mtime_ns": 0},
            {"path": "escape", "type": "symlink", "mode": 0o777, "mtime_ns": 0, "symlink_target": ".."},
            {"path": "escape/file", "type": "file", "mode": 0o644, "mtime_ns": 0, "size": 0, "sha256": "0" * 64},
        ]
        with self.assertRaises(IntegrityError):
            validate_entries(entries)

    def test_tar_hardlink_cannot_masquerade_as_regular_file(self):
        bundle_path = self.root / "hardlink.tar"
        with tarfile.open(bundle_path, "w") as bundle:
            member = tarfile.TarInfo("file")
            member.type = tarfile.LNKTYPE
            member.linkname = "../outside"
            bundle.addfile(member)
        self.restored.mkdir()
        with self.assertRaises(IntegrityError):
            extract_tar(bundle_path, self.restored, [{"path": "file", "type": "file", "size": 0}])

    def test_malformed_catalog_root_is_an_integrity_failure(self):
        backup(self.source, self.archive, settings=SMALL)
        next(self.archive.rglob("*_metadata_catalog-root.json")).write_text('{"version": 1}')
        self.assertEqual(verify(self.archive), 1)

    def test_precision_loss_is_reported_without_emulation(self):
        path = self.source / "file"
        path.touch()
        entry = {"path": "file", "type": "file", "mode": 0o644, "mtime_ns": 1234567890123456789}
        real_utime = os.utime

        def coarse_utime(path, *, ns, follow_symlinks):
            rounded = tuple(value // 1000000000 * 1000000000 for value in ns)
            real_utime(path, ns=rounded, follow_symlinks=follow_symlinks)

        report = io.StringIO()
        with patch("poc.archivator_lib.filesystem.os.utime", side_effect=coarse_utime):
            with contextlib.redirect_stderr(report):
                restore_metadata(self.source, [entry])
        self.assertIn("precision/range loss", report.getvalue())
        self.assertEqual(path.stat().st_mtime_ns, 1234567890000000000)

    def test_negative_fractional_timestamp_has_correct_pax_representation(self):
        entry = {"path": "file", "type": "file", "mode": 0o644, "mtime_ns": -500000000, "size": 0}
        self.assertEqual(tar_info(entry).pax_headers["mtime"], "-0.500000000")

    def test_source_mutation_aborts_without_catalog_root(self):
        (self.source / "file").write_bytes(b"before")
        changed = False

        def change_after_check(path, entry):
            nonlocal changed
            check_unchanged(path, entry)
            if entry["path"] == "file" and not changed:
                path.write_bytes(b"changed while being archived")
                changed = True

        with patch("poc.archivator_lib.backup.check_unchanged", side_effect=change_after_check):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_metadata_catalog-root.json")))
