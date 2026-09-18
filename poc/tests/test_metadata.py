from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError, read_json, sha256, write_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.metadata import completion_digest, completion_names, store_metadata, unpack_metadata
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class MetadataTests(ArchiveTest):
    def test_compression_keeps_only_smaller_large_representation(self):
        for name, data, compress in (
                ("tiny.json", b"x" * 100, False),
                ("large.jsonl", b'{"path":"documents/report.txt"}\n' * 4000, True),
                ("random.bin", self.data(65536), False)):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(data)
                stored = self.root / store_metadata(path)
                self.assertEqual(stored.suffix == ".zst", compress)
                self.assertEqual(path.exists(), not compress)
                if compress:
                    self.assertLess(stored.stat().st_size, len(data))
                self.assertEqual(unpack_metadata(stored).read_bytes(), data)

    def test_either_marker_copy_supports_read_only_restore_and_repair(self):
        (self.source / "document").write_text("a small document")
        archive_id = backup(self.source, self.archive, settings=SMALL)
        markers = [self.archive / name for name in completion_names(archive_id)]
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
        marker = self.archive / completion_names(archive_id)[0]
        complete = read_json(marker)
        complete["metadata_recovery_blocks"] += 1
        write_json(marker, complete)
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_two_valid_but_conflicting_markers_are_not_guessed(self):
        archive_id = backup(self.source, self.archive, settings=SMALL)
        marker = self.archive / completion_names(archive_id)[0]
        complete = read_json(marker)
        complete["metadata_recovery_blocks"] += 1
        complete["marker_sha256"] = completion_digest(complete)
        write_json(marker, complete)
        with self.assertRaisesRegex(IntegrityError, "copies disagree"):
            restore(self.archive, self.restored)

    def test_compressed_metadata_is_repaired_before_decompression(self):
        (self.source / "document").write_text("content" * 100)
        # A lower threshold exercises catalogs, manifests, and the checksum index
        # with a tiny fixture instead of generating a large backup workload.
        with patch("poc.archivator_lib.metadata.METADATA_COMPRESSION_MIN", 1):
            archive_id = backup(self.source, self.archive, settings=SMALL)
            complete = read_json(self.archive / completion_names(archive_id)[0])
            self.assertTrue(complete["checksum_index"].endswith(".json.zst"))
            inventories = list(self.archive.glob("*_files.jsonl.zst"))
            self.assertTrue(inventories)
            self.assertFalse(list(self.archive.glob("*_files.jsonl")))
            self.assertFalse(list(self.archive.glob("*_checksums.json")))
            self.assertEqual(verify(self.archive), 0)
            for name in (inventories[0].name, complete["checksum_index"]):
                with self.subTest(name=name):
                    path = self.archive / name
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
