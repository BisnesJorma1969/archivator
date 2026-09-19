import shutil

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError, read_json, sha256, write_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import spare_metadata_name
from poc.archivator_lib.metadata import catalog_root_digest, catalog_root_names
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
        local = [path for path in self.archive.rglob("*_metadata_index-files*.cms")
                 if "metadata" not in path.relative_to(self.archive).parts]
        for path in local:
            spares = list(self.archive.rglob(spare_metadata_name(path.name)))
            self.assertEqual(len(spares), 1)
            self.assertNotEqual(path.name, spares[0].name)
            self.assertEqual(path.read_bytes(), spares[0].read_bytes())
        self.assertFalse(list(self.archive.rglob("*.jsonl")))
        self.assertFalse(list(self.archive.rglob("*_metadata_index-files*.zst")))

    def test_both_damaged_metadata_copies_recover_before_decryption(self):
        self.make_archive(True)
        copies = list(self.archive.rglob("*_metadata_index-files*.cms"))
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
        for index, name in enumerate(catalog_root_names(archive_id)):
            next(self.archive.rglob(name)).unlink()
            before = snapshot(self.archive)
            self.assertEqual(verify(self.archive), 1)
            restore(self.archive, self.root / f"target-{index}")
            self.assertEqual(snapshot(self.archive), before)
            repair(self.archive)
            self.assertEqual(verify(self.archive), 0)

    def test_two_valid_but_conflicting_markers_are_not_guessed(self):
        archive_id = self.make_archive()
        path = next(self.archive.rglob(catalog_root_names(archive_id)[0]))
        marker = read_json(path)
        marker["groups"] += 1
        marker["marker_sha256"] = catalog_root_digest(marker)
        write_json(path, marker)
        with self.assertRaisesRegex(IntegrityError, "copies disagree"):
            restore(self.archive, self.restored)

    def test_both_catalog_root_copies_recover_from_their_own_par2(self):
        archive_id = self.make_archive(True)
        originals = {}
        for name in catalog_root_names(archive_id):
            path = next(self.archive.rglob(name))
            originals[name] = path.read_bytes()
            path.unlink()
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        self.assertEqual(restore(self.archive, self.restored, key=self.key), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        for name, content in originals.items():
            self.assertEqual(next(self.archive.rglob(name)).read_bytes(), content)

    def test_corrupted_roots_and_root_parity_damage_are_repaired(self):
        archive_id = self.make_archive()
        for name in catalog_root_names(archive_id):
            next(self.archive.rglob(name)).write_bytes(b"broken metadata")
        before = snapshot(self.archive)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        next(self.archive.rglob("*_metadata_catalog-root.vol*.par2")).unlink()
        self.assertEqual(verify(self.archive), 1)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

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
        next(self.archive.rglob("*_metadata_index-files*.zst")).unlink()
        before = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)

    def test_group_parity_rescues_metadata_when_both_copies_and_central_parity_are_lost(self):
        self.make_archive()
        copies = list(self.archive.rglob("*_metadata_index-files*.zst"))
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
        inventory = next(central.rglob("*_metadata_index-files*.zst"))
        for path in (receipt, inventory):
            with path.open("r+b") as output:
                output.write(b"bad!")
        repair(self.archive)
        self.assertFalse(list(self.archive.rglob("*.1")))
        self.assertEqual(verify(self.archive), 0)
