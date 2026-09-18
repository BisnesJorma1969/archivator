import hashlib
import io
import subprocess
import tarfile
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, read_json, sha256
from poc.archivator_lib.external import check_parity, create_parity, decrypt, executable
from poc.archivator_lib.format import parse_chunk
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json, read_zstd_jsonl


class BackupTests(ArchiveTest):
    def test_parity_generation_reads_members_without_copies_or_links(self):
        (self.source / "large").write_bytes(self.data(160000))
        generated_sets = []

        def generate(directory, prefix, members, slice_size, blocks, output_directory):
            self.assertEqual(directory.parent, self.archive)
            self.assertEqual(directory.name, prefix.split("_parity-")[1][:2])
            self.assertEqual(list(output_directory.iterdir()), [])
            before = {name: sha256(directory / name) for name in members}
            files = create_parity(directory, prefix, members, slice_size, blocks,
                                  output_directory=output_directory)
            self.assertEqual(set(output_directory.iterdir()), set(files))
            self.assertEqual({name: sha256(directory / name) for name in members}, before)
            generated_sets.append(prefix)
            return files

        with patch("poc.archivator_lib.backup.create_parity", side_effect=generate), \
                patch("shutil.copyfile", side_effect=AssertionError("Backup must not copy PAR2 inputs")), \
                patch("os.link", side_effect=AssertionError("Backup must not hard-link PAR2 inputs")), \
                patch("os.symlink", side_effect=AssertionError("Backup must not symlink PAR2 inputs")):
            backup(self.source, self.archive, settings=SMALL)
        self.assertTrue(any("_metadata_parity-" in prefix for prefix in generated_sets))
        self.assertGreater(len(generated_sets), 2)
        self.assertFalse((self.archive / ".tmp").exists())

    def test_empty_tree_still_has_recoverable_metadata_and_root(self):
        archive_id = backup(self.source, self.archive, settings=SMALL)
        marker = next(self.archive.rglob(f"archive-{archive_id}_metadata_complete.json"))
        complete = read_json(marker)
        self.assertEqual(len(complete["metadata_parity"]), 5)
        self.assertEqual(check_parity(marker.parent, complete["metadata_prefix"]), 0)
        inventory = read_zstd_jsonl(next(self.archive.rglob("*_metadata_stream-*_inventory.jsonl.zst")))
        self.assertEqual([entry["path"] for entry in inventory], ["."])
        self.assertFalse((self.archive / ".tmp").exists())

    def test_direct_file_chunks_are_independent_and_cross_sets(self):
        contents = self.data(160000)
        (self.source / "large").write_bytes(contents)
        backup(self.source, self.archive, settings=SMALL)
        streams = read_zstd_jsonl(next(self.archive.rglob("*_metadata_streams.jsonl.zst")))
        direct = next(stream for stream in streams if stream["type"] == "file")
        chunks = list(self.archive.rglob(f"*_stream-{direct['stream']}_*.zst"))
        chunks.sort(key=lambda path: parse_chunk(path.name)["offset"])
        plaintext = [subprocess.run([executable("zstd"), "-qdc", str(path)],
                                    capture_output=True, check=True).stdout for path in chunks]
        self.assertEqual(b"".join(plaintext), contents)
        self.assertGreater(len({parse_chunk(path.name)["parity"] for path in chunks}), 1)
        manifests = [read_zstd_json(path) for path in self.archive.rglob("*_metadata_parity-*_manifest.json.zst")]
        self.assertTrue(any(len({member["stream"] for member in item["members"]}) > 1
                            for item in manifests))
        self.assertTrue(any(item["member_count"] < 8 for item in manifests))

    def test_encrypted_chunks_use_standard_cms_then_zstd(self):
        key, certificate = self.certificate()
        combined = self.root / "combined.pem"
        combined.write_bytes(certificate.read_bytes() + key.read_bytes())
        (self.source / "tiny").write_bytes(b"hello")
        archive_id = backup(self.source, self.archive, combined, SMALL)
        chunks = sorted(self.archive.rglob("*.enc"), key=lambda path: parse_chunk(path.name)["offset"])
        self.assertTrue(chunks)
        self.assertTrue(all(chunk.name.endswith(".zst.enc") for chunk in chunks))
        self.assertFalse(list(self.archive.rglob("*_chunk-*.zst")))
        stream = bytearray()
        for chunk in chunks:
            compressed = self.root / "decrypted.zst"
            decrypt(chunk, compressed, key, certificate)
            result = subprocess.run([executable("zstd"), "-qdc", str(compressed)],
                                    capture_output=True, check=True)
            stream.extend(result.stdout)
        with tarfile.open(fileobj=io.BytesIO(stream)) as bundle:
            self.assertEqual(bundle.extractfile("tiny").read(), b"hello")
        self.assertNotIn(b"PRIVATE KEY", next(self.archive.rglob(f"archive-{archive_id}_metadata_recipient.pem")).read_bytes())

    def test_checksums_cover_metadata_and_data_parity(self):
        (self.source / "tiny").write_bytes(b"hello")
        backup(self.source, self.archive, settings=SMALL)
        checksums = read_zstd_json(next(self.archive.rglob("*_metadata_checksums.json.zst")))
        for name, digest in checksums.items():
            self.assertEqual(sha256(next(self.archive.rglob(name))), digest)
        inventory = read_zstd_jsonl(next(self.archive.rglob("*_metadata_stream-*_inventory.jsonl.zst")))
        file_entry = next(entry for entry in inventory if entry["type"] == "file")
        self.assertEqual(file_entry["sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(file_entry["crc32"], "3610a686")

    def test_failure_does_not_publish_completion_marker(self):
        with patch("poc.archivator_lib.backup.create_parity", side_effect=ArchiveError("simulated failure")):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_metadata_complete.json")))
        self.assertFalse((self.archive / ".tmp").exists())

    def test_compressor_failure_aborts_backup(self):
        compressor = self.root / "failing-zstd"
        compressor.write_text("#!/bin/sh\necho compression-failed >&2\nexit 9\n")
        compressor.chmod(0o700)
        (self.source / "file").write_bytes(self.data(160000))

        def find_executable(name):
            return str(compressor) if name == "zstd" else executable(name)

        with patch("poc.archivator_lib.external.executable", side_effect=find_executable):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_metadata_complete.json")))
        self.assertFalse((self.archive / ".tmp").exists())
