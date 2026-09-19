import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import main
from poc.archivator_lib.common import ArchiveError, sha256
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import run
from poc.archivator_lib.progress import Progress, progress
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL


class ProgressTests(unittest.TestCase):
    def test_heartbeat_continues_while_external_tool_is_silent(self):
        reporter = Progress(interval=0.02)
        output = io.StringIO()
        with contextlib.redirect_stderr(output), patch("poc.archivator_lib.external.progress", reporter):
            with reporter.reporting("verify"):
                result = run([sys.executable, "-c", "import time; time.sleep(0.2); print('tool result')"],
                             activity="PAR2: checking recovery data")
        self.assertEqual(result, "tool result\n")
        self.assertGreaterEqual(output.getvalue().count("PAR2: checking recovery data"), 2)
        self.assertIn("[verify ", output.getvalue())
        self.assertIn("s elapsed]", output.getvalue())
        self.assertNotIn("%", output.getvalue())
        self.assertIsNone(reporter.thread)
        self.assertTrue(reporter.stopped.is_set())

    def test_failed_tool_stops_reporting_and_preserves_failure(self):
        reporter = Progress(interval=0.02)
        output = io.StringIO()
        with contextlib.redirect_stderr(output), patch("poc.archivator_lib.external.progress", reporter):
            with self.assertRaisesRegex(ArchiveError, "failed \\(7\\)"):
                with reporter.reporting("backup"):
                    run([sys.executable, "-c", "import sys; sys.exit(7)"])
        self.assertIsNone(reporter.thread)
        self.assertTrue(reporter.stopped.is_set())


class StatusPrivacyTests(ArchiveTest):
    def test_successful_status_hides_member_names_and_combines_tar_counters(self):
        private_names = ("private-folder", "private-large.bin", "private-letter.txt", "private-notes.txt")
        folder = self.source / private_names[0]
        folder.mkdir()
        (folder / private_names[1]).write_bytes(self.data(90000))
        (folder / private_names[2]).write_text("A letter\n" * 40)
        (folder / private_names[3]).write_text("Notes\n" * 40)
        key, certificate = self.certificate()
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                messages = []
                errors = io.StringIO()
                start = len(self.report.getvalue())
                archive = self.root / f"archive-{encrypted}"
                target = self.root / f"target-{encrypted}"
                with patch.object(progress, "update", side_effect=messages.append), contextlib.redirect_stderr(errors):
                    backup(self.source, archive, certificate if encrypted else None, SMALL)
                    self.assertEqual(verify(archive), 0)
                    repair(archive)
                    self.assertEqual(restore(archive, target, key=key if encrypted else None), 0)
                    self.assertEqual(compare(self.source, target), 0)
                    # Shared checksum helpers must not expose source basenames either.
                    sha256(folder / private_names[1])
                output = self.report.getvalue()[start:] + errors.getvalue() + "\n".join(messages)
                for name in private_names:
                    self.assertNotIn(name, output)
                tar_messages = [message for message in messages if message.startswith("Encoding TAR ")]
                self.assertTrue(tar_messages)
                for message in tar_messages:
                    self.assertIn("entry ", message)
                    self.assertIn("plaintext bytes; chunk ", message)
                self.assertFalse(any(message.startswith("Packing TAR entry") for message in messages))

    def test_comparison_diagnostics_keep_names_but_heartbeat_does_not(self):
        name = "mismatching-private-file.txt"
        self.restored.mkdir()
        (self.source / name).write_text("original")
        (self.restored / name).write_text("different")
        messages = []
        with patch.object(progress, "update", side_effect=messages.append):
            self.assertEqual(compare(self.source, self.restored), 1)
        self.assertIn(f"Content differs (SHA-256): {name!r}", self.report.getvalue())
        self.assertNotIn(name, "\n".join(messages))

    def test_operational_error_keeps_the_actionable_filename(self):
        name = "unreadable-private-file.txt"
        (self.source / name).write_text("content")
        errors = io.StringIO()
        with patch("poc.archivator_lib.backup.check_unchanged",
                   side_effect=PermissionError(13, "Permission denied", str(self.source / name))):
            with contextlib.redirect_stderr(errors):
                self.assertEqual(main(["backup", str(self.source), str(self.archive)]), 2)
        self.assertIn(name, errors.getvalue())
        self.assertIn("Permission denied", errors.getvalue())
