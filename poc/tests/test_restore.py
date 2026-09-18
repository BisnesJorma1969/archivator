import contextlib
import errno
import io
import os
import random
import shutil
import subprocess
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, Hashes, IntegrityError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import executable
from poc.archivator_lib.restore import restore, unpack_chunk
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import flip, snapshot


class RestoreTests(ArchiveTest):
    def roundtrip(self, certificate=None, key=None):
        backup(self.source, self.archive, certificate, SMALL)
        restore(self.archive, self.restored, key=key, certificate=certificate)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_empty_tree(self):
        self.roundtrip()

    def test_zstd_decoder_rejects_truncation_and_excess_plaintext(self):
        data = self.data(160000)
        compressed = subprocess.run([executable("zstd"), "-q", "-3", "--check", "-c"],
                                    input=data, capture_output=True, check=True).stdout
        hashes = Hashes()
        hashes.update(data)
        member = {"filename": "chunk.zst", "length": len(data),
                  "plaintext_sha256": hashes.values()["sha256"],
                  "plaintext_sha512": hashes.values()["sha512"]}
        path = self.root / member["filename"]
        path.write_bytes(compressed[:-1])
        with self.assertRaisesRegex(IntegrityError, "Invalid zstd chunk"):
            unpack_chunk(self.root, member, io.BytesIO(), False, None, None)
        path.write_bytes(compressed)
        member["length"] = 1024
        output = io.BytesIO()
        with self.assertRaisesRegex(IntegrityError, "exceeds its declared length"):
            unpack_chunk(self.root, member, output, False, None, None)
        self.assertLessEqual(len(output.getvalue()), member["length"])

    def test_awkward_names_symlinks_empty_files_and_metadata(self):
        (self.source / "folder").mkdir()
        (self.source / "empty directory").mkdir()
        (self.source / "folder" / "tab\tline\n café 中文").write_bytes(b"contents\x00\xff")
        (self.source / "empty").touch()
        (self.source / "relative link").symlink_to("folder/tab\tline\n café 中文")
        (self.source / "dangling").symlink_to("missing")
        (self.source / "external link").symlink_to("/not/a/real/file")
        os.chmod(self.source / "folder", 0o751)
        os.utime(self.source / "empty", ns=(1234567890123456789, 1234567890123456789))
        self.roundtrip()
        self.assertEqual((self.restored / "folder" / "tab\tline\n café 中文").read_bytes(), b"contents\x00\xff")

    def test_large_file_across_chunks_and_sets(self):
        content = self.data(160000)
        (self.source / "large").write_bytes(content)
        self.roundtrip()
        self.assertEqual((self.restored / "large").read_bytes(), content)

    def test_encrypted_corruption_and_read_only_archive(self):
        key, certificate = self.certificate()
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, certificate, SMALL)
        flip(next(self.archive.glob("*.cms")))
        before = snapshot(self.archive)
        for path in self.archive.iterdir():
            path.chmod(0o444)
        self.archive.chmod(0o555)
        try:
            restore(self.archive, self.restored, key=key, certificate=certificate)
        finally:
            self.archive.chmod(0o755)
            for path in self.archive.iterdir():
                path.chmod(0o644)
        self.assertEqual(snapshot(self.archive), before)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_missing_chunk_repaired_only_in_scratch(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        missing = next(self.archive.glob("*_chunk-*.zst"))
        missing.unlink()
        restore(self.archive, self.restored)
        self.assertFalse(missing.exists())
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_restore_copies_only_damaged_input_and_keeps_archive_unchanged(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        damaged = next(self.archive.glob("*_chunk-*.zst"))
        flip(damaged)
        before = snapshot(self.archive)
        with patch("shutil.copyfile", wraps=shutil.copyfile) as copying:
            restore(self.archive, self.restored)
        self.assertEqual([call.args[0] for call in copying.call_args_list], [damaged])
        self.assertEqual(snapshot(self.archive), before)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_restore_falls_back_to_copy_when_hardlinks_are_unavailable(self):
        (self.source / "document").write_text("content")
        backup(self.source, self.archive, settings=SMALL)
        before = snapshot(self.archive)
        with patch("os.link", side_effect=OSError(errno.EXDEV, "Different filesystem")):
            restore(self.archive, self.restored)
        self.assertEqual(snapshot(self.archive), before)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_wrong_key_is_a_hard_failure(self):
        _, certificate = self.certificate()
        wrong_key, _ = self.certificate("wrong")
        backup(self.source, self.archive, certificate, SMALL)
        with self.assertRaises(IntegrityError):
            restore(self.archive, self.restored, key=wrong_key, certificate=certificate)

    def test_moved_nested_archive_and_randomized_enumeration(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        moved = self.root / "moved" / "different" / "hierarchy"
        moved.parent.mkdir(parents=True)
        shutil.move(self.archive, moved)
        real_walk = os.walk

        def randomized_walk(*args, **kwargs):
            randomizer = random.Random(42)
            for directory, directories, files in real_walk(*args, **kwargs):
                randomizer.shuffle(directories)
                randomizer.shuffle(files)
                yield directory, directories, files

        with patch("poc.archivator_lib.recovery.os.walk", side_effect=randomized_walk):
            restore(self.root / "moved", self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_unrecoverable_damage_never_succeeds(self):
        backup(self.source, self.archive, settings=SMALL)
        for path in list(self.archive.glob("*_chunk-*.zst")) + list(self.archive.glob("*.par2")):
            path.unlink()
        with self.assertRaises(IntegrityError):
            restore(self.archive, self.restored)

    def test_compare_reports_all_differences(self):
        (self.source / "one").write_bytes(b"one")
        (self.source / "two").write_bytes(b"two")
        self.roundtrip()
        (self.restored / "one").write_bytes(b"changed")
        (self.restored / "two").unlink()
        (self.restored / "extra").touch()
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            self.assertEqual(compare(self.source, self.restored), 1)
        for word in ("Content differs", "Size differs", "Missing", "Unexpected"):
            self.assertIn(word, report.getvalue())

    def test_nonempty_target_is_not_overwritten(self):
        backup(self.source, self.archive, settings=SMALL)
        self.restored.mkdir()
        (self.restored / "keep").write_bytes(b"keep")
        with self.assertRaises(ArchiveError):
            restore(self.archive, self.restored)
        self.assertEqual((self.restored / "keep").read_bytes(), b"keep")
