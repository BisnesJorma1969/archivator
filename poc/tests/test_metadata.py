import subprocess

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError, read_json, sha256, write_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import executable
from poc.archivator_lib.metadata import completion_digest, completion_names, store_metadata, unpack_metadata
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class MetadataTests(ArchiveTest):
    def test_fixed_policy_ignores_size_and_compression_ratio(self):
        for name, data, compress in (
                ("archive-id_metadata_complete.json", b"{}", False),
                ("archive-id_metadata_complete-copy.json", b"{}", False),
                ("archive-id_metadata_format.txt", b"format=archivator\n" * 10000, False),
                ("archive-id_metadata_recipient.pem", b"public certificate", False),
                ("archive-id_metadata_streams.jsonl", b"{}\n", True),
                ("archive-id_metadata_inventory_stream-sid.jsonl", b"{}\n" * 4000, True),
                ("archive-id_parity-pid_manifest.json", b"{}", True),
                ("archive-id_metadata_checksums.json", b"{}", True),
                ("other-metadata.bin", self.data(65536), True)):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(data)
                stored = self.root / store_metadata(path)
                self.assertEqual(stored.suffix == ".zst", compress)
                self.assertEqual(path.exists(), not compress)
                if compress:
                    decoded = subprocess.run([executable("zstd"), "-dc", str(stored)],
                                             capture_output=True, check=True).stdout
                    self.assertEqual(decoded, data)
                    if len(data) < 10:
                        self.assertGreater(stored.stat().st_size, len(data))
                self.assertEqual(unpack_metadata(stored).read_bytes(), data)

    def test_either_marker_copy_supports_read_only_restore_and_repair(self):
        (self.source / "document").write_text("a small document")
        archive_id = backup(self.source, self.archive, settings=SMALL)
        markers = [next(self.archive.rglob(name)) for name in completion_names(archive_id)]
        self.assertEqual(markers[0].read_bytes(), markers[1].read_bytes())
        for index, marker in enumerate(markers):
            with self.subTest(marker=marker.name):
                marker.unlink()
                before = snapshot(self.archive)
                self.assertEqual(verify(self.archive), 1)
                target = self.root / f"restored-{index}"
                restore(self.archive, target)
                self.assertEqual(compare(self.source, target), 0)
                self.assertEqual(snapshot(self.archive), before)
                repair(self.archive)
                self.assertEqual(verify(self.archive), 0)
                self.assertEqual(markers[0].read_bytes(), markers[1].read_bytes())

    def test_marker_checksum_detects_valid_json_corruption(self):
        archive_id = backup(self.source, self.archive, settings=SMALL)
        marker = next(self.archive.rglob(completion_names(archive_id)[0]))
        complete = read_json(marker)
        complete["metadata_recovery_blocks"] += 1
        write_json(marker, complete)
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_two_valid_but_conflicting_markers_are_not_guessed(self):
        archive_id = backup(self.source, self.archive, settings=SMALL)
        marker = next(self.archive.rglob(completion_names(archive_id)[0]))
        complete = read_json(marker)
        complete["metadata_recovery_blocks"] += 1
        complete["marker_sha256"] = completion_digest(complete)
        write_json(marker, complete)
        with self.assertRaisesRegex(IntegrityError, "copies disagree"):
            restore(self.archive, self.restored)

    def test_compressed_metadata_is_repaired_before_decompression(self):
        (self.source / "document").write_text("content" * 100)
        archive_id = backup(self.source, self.archive, settings=SMALL)
        complete = read_json(next(self.archive.rglob(completion_names(archive_id)[0])))
        metadata_names = [*complete["metadata_members"], *complete["metadata_parity"],
                          *completion_names(archive_id)]
        self.assertTrue(all(name.startswith(f"archive-{archive_id}_metadata")
                            or name.endswith("_manifest.json.zst") for name in metadata_names))
        self.assertTrue(all(next(self.archive.rglob(name)).is_file() for name in metadata_names))
        self.assertTrue(complete["checksum_index"].endswith(".json.zst"))
        inventories = list(self.archive.rglob("*_metadata_inventory_stream-*.jsonl.zst"))
        self.assertTrue(inventories)
        self.assertFalse(list(self.archive.rglob("*_metadata_inventory_stream-*.jsonl")))
        self.assertFalse(list(self.archive.rglob("*_metadata_checksums.json")))
        self.assertEqual(verify(self.archive), 0)
        manifest = next(self.archive.rglob("*_manifest.json.zst"))
        for name in (inventories[0].name, manifest.name, complete["checksum_index"]):
            with self.subTest(name=name):
                path = next(self.archive.rglob(name))
                original_digest = sha256(path)
                # Damage the frame header: decompression before PAR2 would fail.
                with path.open("r+b") as output:
                    output.write(b"BAD!")
                before = snapshot(self.archive)
                self.assertEqual(verify(self.archive), 1)
                target = self.root / (name + "-restore")
                restore(self.archive, target)
                self.assertEqual(compare(self.source, target), 0)
                self.assertEqual(snapshot(self.archive), before)
                repair(self.archive)
                self.assertEqual(verify(self.archive), 0)
                self.assertEqual(sha256(path), original_digest)
