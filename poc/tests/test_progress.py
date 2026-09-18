import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.external import run
from poc.archivator_lib.progress import Progress


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
