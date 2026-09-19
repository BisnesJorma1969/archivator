import shutil

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError, read_json, sha256, write_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.metadata import completion_digest, completion_names
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class MetadataTests(ArchiveTest):
    def make_archive(self, encrypted=False):
        (self.source / "document-a").write_text("content" * 100)
        (self.source / "document-b").write_text("more content" * 100)
        self.key, certificate = self.certificate() if encrypted else (None, None)
        return backup(self.source, self.archive, certificate, SMALL)

    def test_metadata_copies_are_identical_even_when_encrypted(self):
        self.make_archive(True)
        local = [path for path in self.archive.rglob("*_inventory*.cms")
                 if "metadata" not in path.relative_to(self.archive).parts]
        for path in local:
            copies = list(self.archive.rglob(path.name))
            self.assertEqual(len(copies), 2)
            self.assertEqual(copies[0].read_bytes(), copies[1].read_bytes())
        self.assertFalse(list(self.archive.rglob("*.jsonl")))
        self.assertFalse(list(self.archive.rglob("*_inventory*.zst")))

    def test_both_damaged_metadata_copies_recover_before_decryption(self):
        self.make_archive(True)
        copies = list(self.archive.rglob("*_inventory*.cms"))
        originals = {path: sha256(path) for path in copies}
        for path in copies:
            path.write_bytes(b"bad header")
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored, key=self.key)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)  # No decryption key is needed.
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual({path: sha256(path) for path in copies}, originals)

    def test_either_marker_copy_supports_restore_and_repair(self):
        archive_id = self.make_archive()
        for index, name in enumerate(completion_names(archive_id)):
            next(self.archive.rglob(name)).unlink()
            before = snapshot(self.archive)
            self.assertEqual(verify(self.archive), 1)
            restore(self.archive, self.root / f"target-{index}")
            self.assertEqual(snapshot(self.archive), before)
            repair(self.archive)
            self.assertEqual(verify(self.archive), 0)

    def test_two_valid_but_conflicting_markers_are_not_guessed(self):
        archive_id = self.make_archive()
        path = next(self.archive.rglob(completion_names(archive_id)[0]))
        marker = read_json(path)
        marker["groups"] += 1
        marker["marker_sha256"] = completion_digest(marker)
        write_json(path, marker)
        with self.assertRaisesRegex(IntegrityError, "copies disagree"):
            restore(self.archive, self.restored)

    def test_checksum_receipt_itself_is_par2_protected(self):
        self.make_archive()
        receipt = next(self.archive.rglob("*_checksums.json.zst"))
        digest = sha256(receipt)
        receipt.unlink()
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(sha256(receipt), digest)
        self.assertEqual(verify(self.archive), 0)

    def test_independent_group_restores_without_central_metadata(self):
        self.make_archive(True)
        shutil.rmtree(self.archive / "metadata")
        self.assertEqual(restore(self.archive, self.restored, key=self.key), 1)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertIn("completeness cannot be proved", self.report.getvalue())

    def test_local_parity_recovers_missing_local_inventory(self):
        self.make_archive()
        shutil.rmtree(self.archive / "metadata")
        next(self.archive.rglob("*_inventory*.zst")).unlink()
        before = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)

    def test_data_parity_rescues_metadata_when_both_copies_and_central_parity_are_lost(self):
        self.make_archive()
        copies = list(self.archive.rglob("*_inventory*.zst"))
        for path in copies:
            path.unlink()
        for path in (self.archive / "metadata").rglob("*.par2"):
            path.unlink()
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_repair_removes_only_new_par2_backup_files_after_metadata_recovery(self):
        self.make_archive()
        central = self.archive / "metadata"
        receipt = next(central.rglob("*_checksums.json.zst"))
        inventory = next(central.rglob("*_inventory*.zst"))
        for path in (receipt, inventory):
            with path.open("r+b") as output:
                output.write(b"bad!")
        repair(self.archive)
        self.assertFalse(list(self.archive.rglob("*.1")))
        self.assertEqual(verify(self.archive), 0)
