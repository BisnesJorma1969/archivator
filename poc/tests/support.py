import random
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from poc.archivator_lib.common import WORK_DIR
from poc.archivator_lib.external import executable, run
from poc.archivator_lib.format import Settings

SMALL = Settings(chunk_size=16384, large_file_size=32768, tar_size=16384,
                 tar_entries=100, parity_members=8, slice_size=1024)


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        WORK_DIR.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="test-", dir=WORK_DIR)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.archive = self.root / "archive"
        self.restored = self.root / "restored"
        self.report = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.report))

    def data(self, size, seed=1):
        return random.Random(seed).randbytes(size)

    def certificate(self, name="recipient"):
        key = self.root / (name + "-key.pem")
        certificate = self.root / (name + ".pem")
        run([executable("openssl"), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=PoC test",
             "-days", "1"])
        return key, certificate
