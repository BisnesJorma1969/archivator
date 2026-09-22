import random
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from poc.archivator_lib.common import WORK_DIR
from poc.archivator_lib.external import executable, run
from poc.archivator_lib.format import Settings

SMALL = Settings(max_file_bytes=65535, max_datagroup_bytes=262144, supergroup_par2=False,
                 datagroup_loss_files=1, datagroup_bitrot_percent=10)

def read_zstd_json(path):
    return json.loads(run([executable("zstd"), "-qdc", str(path)]))


def read_zstd_jsonl(path):
    return [json.loads(line) for line in run([executable("zstd"), "-qdc", str(path)]).splitlines()
            if line.strip()]


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

    def certificate(self, name="recipient", algorithm="rsa:3072"):
        key = self.root / (name + "-key.pem")
        certificate = self.root / (name + ".pem")
        run([executable("openssl"), "req", "-x509", "-newkey", algorithm, "-noenc",
             "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=PoC test",
             "-days", "1"])
        return key, certificate


def catalog(archive, key=None):
    from poc.archivator_lib.recovery import discover, open_archive
    files = discover(archive)
    archive_id = next(iter(files))
    with open_archive(archive_id, files[archive_id], key=key) as opened:
        return opened.datasets


def manifests(archive):
    unique = {path.name: path for path in archive.rglob("*_metadata_index-datafiles.json.zst")}
    return [read_zstd_json(path) for path in unique.values()]
