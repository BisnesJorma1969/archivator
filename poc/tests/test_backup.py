import hashlib
import subprocess
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, sha256
from poc.archivator_lib.external import create_parity, decrypt, executable
from poc.archivator_lib.format import parse_chunk
from poc.tests.support import ArchiveTest, SMALL, catalog, manifests


class BackupTests(ArchiveTest):
    def test_parity_generation_reads_originals_without_staging_inputs(self):
        (self.source / "large").write_bytes(self.data(160000))
        generated = []

        def generate(directory, prefix, members, slice_size, blocks, output_directory=None, volumes=1):
            self.assertEqual(list(output_directory.iterdir()), [])
            before = {name: sha256(directory / name) for name in members}
            result = create_parity(directory, prefix, members, slice_size, blocks, output_directory, volumes)
            self.assertEqual(set(output_directory.iterdir()), set(result))
            self.assertEqual({name: sha256(directory / name) for name in members}, before)
            generated.append(prefix)
            return result

        with patch("poc.archivator_lib.backup.create_parity", side_effect=generate), \
                patch("poc.archivator_lib.metadata.create_parity", side_effect=generate), \
                patch("os.link", side_effect=AssertionError("No backup hard links")):
            backup(self.source, self.archive, settings=SMALL)
        self.assertGreater(len(generated), 2)
        self.assertFalse(list(self.archive.rglob(".tmp")))

    def test_direct_file_chunks_are_independent_and_cross_sets(self):
        contents = self.data(500000)
        (self.source / "large").write_bytes(contents)
        backup(self.source, self.archive, settings=SMALL)
        direct = next(stream for stream in catalog(self.archive) if stream["type"] == "file")
        chunks = sorted(self.archive.rglob(f"*_stream-{direct['stream']}_*.zst"),
                        key=lambda path: parse_chunk(path.name)["offset"])
        decoded = [subprocess.run([executable("zstd"), "-qdc", str(path)],
                                  capture_output=True, check=True).stdout for path in chunks]
        self.assertEqual(b"".join(decoded), contents)
        self.assertGreater(len({parse_chunk(path.name)["parity"] for path in chunks}), 1)
        self.assertEqual(direct["md5"], hashlib.md5(contents).hexdigest())

    def test_singleton_is_direct_and_encrypted_metadata_hides_its_name(self):
        key, certificate = self.certificate()
        combined = self.root / "combined.pem"
        combined.write_bytes(certificate.read_bytes() + key.read_bytes())
        (self.source / "secret-client-name").write_bytes(b"hello")
        backup(self.source, self.archive, combined, SMALL)
        streams = catalog(self.archive, key)
        self.assertEqual([stream["type"] for stream in streams], ["file"])
        chunk = next(self.archive.rglob("*_chunk-*.zst.cms"))
        compressed = self.root / "decoded.zst"
        decrypt(chunk, compressed, key, certificate)
        result = subprocess.run([executable("zstd"), "-qdc", str(compressed)], capture_output=True, check=True)
        self.assertEqual(result.stdout, b"hello")
        for path in self.archive.rglob("archive-*"):
            data = path.read_bytes()
            if path.suffix == ".zst":
                data = subprocess.run([executable("zstd"), "-qdc", str(path)], capture_output=True, check=True).stdout
            self.assertNotIn(b"secret-client-name", data)
            self.assertNotIn(b"PRIVATE KEY", data)
        self.assertTrue(list(self.archive.rglob("*_metadata_index-files*.jsonl.zst.cms")))

    def test_empty_tree_has_metadata_only_recovery_group(self):
        backup(self.source, self.archive, settings=SMALL)
        self.assertEqual(catalog(self.archive), [])
        self.assertTrue(manifests(self.archive))
        self.assertTrue(all(not manifest["members"] for manifest in manifests(self.archive)))

    def test_failure_does_not_publish_catalog_root(self):
        with patch("poc.archivator_lib.backup.create_parity", side_effect=ArchiveError("simulated failure")):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_metadata_catalog-root.json")))
        self.assertFalse((self.archive / ".tmp").exists())

    def test_compressor_failure_aborts_backup(self):
        compressor = self.root / "failing-zstd"
        compressor.write_text("#!/bin/sh\necho compression-failed >&2\nexit 9\n")
        compressor.chmod(0o700)
        (self.source / "file").write_bytes(self.data(160000))
        real = executable
        with patch("poc.archivator_lib.external.executable", side_effect=lambda name: str(compressor) if name == "zstd" else real(name)):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_metadata_catalog-root.json")))
