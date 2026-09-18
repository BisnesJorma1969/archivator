import gzip
import hashlib
import io
import tarfile
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, read_json, read_jsonl, sha256
from poc.archivator_lib.external import check_parity, decrypt
from poc.archivator_lib.format import parse_chunk
from poc.tests.support import ArchiveTest, SMALL


class BackupTests(ArchiveTest):
    def test_empty_tree_still_has_recoverable_metadata_and_root(self):
        archive_id = backup(self.source, self.archive, settings=SMALL)
        complete = read_json(self.archive / f"archive-{archive_id}_complete.json")
        self.assertEqual(len(complete["metadata_parity"]), 5)
        self.assertEqual(check_parity(self.archive, complete["metadata_prefix"]), 0)
        inventory = read_jsonl(next(self.archive.glob("*_files.jsonl")))
        self.assertEqual([entry["path"] for entry in inventory], ["."])
        self.assertFalse((self.archive / ".tmp").exists())

    def test_direct_file_chunks_are_independent_and_cross_sets(self):
        contents = self.data(160000)
        (self.source / "large").write_bytes(contents)
        backup(self.source, self.archive, settings=SMALL)
        streams = read_jsonl(next(self.archive.glob("*_streams.jsonl")))
        direct = next(stream for stream in streams if stream["type"] == "file")
        chunks = list(self.archive.glob(f"*_stream-{direct['stream']}_*.gz"))
        chunks.sort(key=lambda path: parse_chunk(path.name)["offset"])
        self.assertEqual(b"".join(gzip.decompress(path.read_bytes()) for path in chunks), contents)
        self.assertGreater(len({parse_chunk(path.name)["parity"] for path in chunks}), 1)
        manifests = [read_json(path) for path in self.archive.glob("*_manifest.json")]
        self.assertTrue(any(len({member["stream"] for member in item["members"]}) > 1
                            for item in manifests))
        self.assertTrue(any(item["member_count"] < 8 for item in manifests))

    def test_encrypted_chunks_use_standard_cms_then_gzip(self):
        key, certificate = self.certificate()
        (self.source / "tiny").write_bytes(b"hello")
        archive_id = backup(self.source, self.archive, certificate, SMALL)
        chunks = sorted(self.archive.glob("*.cms"), key=lambda path: parse_chunk(path.name)["offset"])
        stream = bytearray()
        for chunk in chunks:
            compressed = self.root / "decrypted.gz"
            decrypt(chunk, compressed, key, certificate)
            stream.extend(gzip.decompress(compressed.read_bytes()))
        with tarfile.open(fileobj=io.BytesIO(stream)) as bundle:
            self.assertEqual(bundle.extractfile("tiny").read(), b"hello")
        self.assertNotIn(b"PRIVATE KEY", (self.archive / f"archive-{archive_id}_recipient.pem").read_bytes())

    def test_checksums_cover_metadata_and_data_parity(self):
        (self.source / "tiny").write_bytes(b"hello")
        backup(self.source, self.archive, settings=SMALL)
        checksums = read_json(next(self.archive.glob("*_checksums.json")))
        for name, digest in checksums.items():
            self.assertEqual(sha256(self.archive / name), digest)
        inventory = read_jsonl(next(self.archive.glob("*_files.jsonl")))
        file_entry = next(entry for entry in inventory if entry["type"] == "file")
        self.assertEqual(file_entry["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(len(file_entry["crc16_ccitt_false"]), 4)

    def test_failure_does_not_publish_completion_marker(self):
        with patch("poc.archivator_lib.backup.create_parity", side_effect=ArchiveError("simulated failure")):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.glob("*_complete.json")))
        self.assertFalse((self.archive / ".tmp").exists())
