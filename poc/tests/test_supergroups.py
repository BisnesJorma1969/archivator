"""Whole-datagroup loss, two-layer recovery, and portable bounded output."""

from dataclasses import replace
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import stored_path
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.archivator_lib.scan import scan
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json
from poc.tests.test_recovery import flip, snapshot


class SupergroupTests(ArchiveTest):
    def make_archive(self, encrypted=False, bitrot_percent=2):
        self.settings = replace(SMALL, supergroup_par2=True, supergroup_datagroups=3,
                                max_datagroup_bytes=400000, supergroup_bitrot_percent=bitrot_percent)
        # Independent whole datasets remain useful if a supergroup cannot recover.
        for number in range(12):
            (self.source / f"file-{number}.bin").write_bytes(self.data(90000, number))
        key, cert = self.certificate() if encrypted else (None, None)
        backup(self.source, self.archive, cert, self.settings)
        records = [read_zstd_json(path) for path in self.archive.rglob("*_index-datagroups.json.zst")]
        self.assertGreater(len(records), 1)
        self.assertTrue(all(1 <= len(record["datagroups"]) <= 3 for record in records))
        return records, key

    def lose_datagroup(self, record, datagroup):
        # Delete this datagroup's data directory; keep its central spare metadata.
        for path in list(self.archive.rglob("archive-*")):
            if f"_datagroup-{datagroup['datagroup']}" in path.name:
                if "metadata" not in path.relative_to(self.archive).parts:
                    path.unlink()

    def test_output_is_portable_bounded_and_uses_no_par2_as_outer_input(self):
        records, _ = self.make_archive()
        for path in self.archive.rglob("*"):
            if path.is_file():
                relative = path.relative_to(self.archive).as_posix()
                self.assertTrue(relative.isascii())
                self.assertLessEqual(len(relative), 256)
                self.assertLessEqual(len(path.name), 255)
                self.assertLessEqual(path.stat().st_size, self.settings.max_file_bytes)
        for record in records:
            self.assertTrue(all(not name.endswith(".par2") for datagroup in record["datagroups"]
                                for name in datagroup["members"]))
            parity = self.archive / "data" / record["supergroup"][:2] / record["supergroup"] / "parity"
            for media in parity.iterdir():
                self.assertLessEqual(sum(path.stat().st_size for path in media.iterdir()),
                                     self.settings.max_datagroup_bytes)
        self.assertEqual(verify(self.archive), 0)

    def test_missing_datagroup_and_extra_damage_restore_read_only_then_repair_in_place(self):
        records, key = self.make_archive(encrypted=True)
        record = next(record for record in records if len(record["datagroups"]) == 3)
        self.lose_datagroup(record, record["datagroups"][0])
        other = next(name for name in record["datagroups"][1]["members"] if "_dataset-" in name)
        flip(stored_path(self.archive, other))
        # Force the extra bitrot to consume OUTER margin, rather than being
        # repairable by that datagroup's local parity first.
        for path in self.archive.rglob(f"*_datagroup-{record['datagroups'][1]['datagroup']}*.par2"):
            path.unlink()
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        self.assertEqual(restore(self.archive, self.restored, key=key), 0, self.report.getvalue())
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        import shutil
        copyfile = shutil.copyfile

        def metadata_only(source, target, *args, **kwargs):
            self.assertNotIn("_dataset-", str(source))
            self.assertNotIn("_dataset-", str(target))
            self.assertFalse(str(source).endswith(".par2"))
            return copyfile(source, target, *args, **kwargs)

        with patch("os.link", side_effect=AssertionError("In-place repair must not hardlink data")), \
                patch("shutil.copyfile", side_effect=metadata_only):
            repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_both_supergroup_indexes_are_recovered_by_standard_par2(self):
        self.make_archive()
        for path in list(self.archive.rglob("*_index-datagroups*.json.zst")):
            path.unlink()
        before = snapshot(self.archive)
        import shutil
        copyfile = shutil.copyfile

        def no_healthy_payload_copy(source, target, *args, **kwargs):
            self.assertNotIn("_dataset-", str(source))
            return copyfile(source, target, *args, **kwargs)

        with patch("shutil.copyfile", side_effect=no_healthy_payload_copy):
            self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_all_parity_regenerates_without_data_staging(self):
        self.make_archive()
        for path in self.archive.rglob("*.par2"):
            path.unlink()
        with patch("os.link", side_effect=AssertionError("In-place repair must not hardlink")), \
                patch("shutil.copyfile", side_effect=AssertionError("Intact metadata/data need no copies")):
            repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_flat_layout_recovers_a_whole_datagroup(self):
        records, _ = self.make_archive()
        self.lose_datagroup(records[0], records[0]["datagroups"][0])
        for path in list(self.archive.rglob("archive-*")):
            path.rename(self.archive / path.name)
        before = snapshot(self.archive)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_filename_only_scan_recovers_missing_datagroup_without_indexes(self):
        # Erase metadata throughout the supergroup, not just on the lost medium.
        # That is a larger loss than the default one-medium-plus-2% budget.
        records, _ = self.make_archive(bitrot_percent=10)
        self.lose_datagroup(records[0], records[0]["datagroups"][0])
        for path in list(self.archive.rglob("archive-*")):
            if "_metadata" in path.name:
                path.unlink()
        index = self.root / "scan.json"
        scan(self.archive, index)
        before = snapshot(self.archive)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 0, self.report.getvalue())
        self.assertEqual(sorted(path.read_bytes() for path in self.source.iterdir()),
                         sorted(path.read_bytes() for path in self.restored.glob("*.raw")))
        self.assertEqual(snapshot(self.archive), before)

    def test_lost_supergroup_does_not_prevent_other_datagroups_restoring(self):
        records, _ = self.make_archive()
        record = next(record for record in records if len(record["datagroups"]) == 3)
        for path in list(self.archive.rglob("archive-*")):
            if f"_supergroup-{record['supergroup']}" in path.name:
                path.unlink()
        self.assertEqual(restore(self.archive, self.restored), 1, self.report.getvalue())
        restored = list(self.restored.glob("*.bin"))
        self.assertTrue(restored)
        self.assertLess(len(restored), len(list(self.source.iterdir())))
        for path in restored:
            self.assertEqual(path.read_bytes(), (self.source / path.name).read_bytes())

    def test_case_changed_outer_recovery_and_filename_scan(self):
        records, key = self.make_archive(encrypted=True)
        self.lose_datagroup(records[0], records[0]['datagroups'][0])
        for path in sorted(self.archive.rglob('*'), key=lambda item: len(item.parts), reverse=True):
            path.rename(path.with_name(path.name.upper()))
        before = snapshot(self.archive)
        index = self.root / 'uppercase-scan.json'
        scan(self.archive, index)
        scanned = self.root / 'scanned'
        self.assertEqual(restore(self.archive, scanned, key=key, scan_index=index), 0, self.report.getvalue())
        self.assertEqual(restore(self.archive, self.restored, key=key), 0, self.report.getvalue())
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
