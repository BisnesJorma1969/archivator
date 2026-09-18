import hashlib
import json
import random
from pathlib import Path

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.demo.bitrot import DAMAGE_TYPES, apply_changes, bitrot, plan_change
from poc.demo.generate import compressed_size, generate
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import snapshot


class DemoTests(ArchiveTest):
    def test_generation_is_seeded_varied_and_does_not_overwrite(self):
        first = self.root / "first"
        second = self.root / "second"
        report = generate(first, office_files=100, log_files=200, sql_mib=2, seed=17)
        self.assertEqual(report, generate(second, office_files=100, log_files=200, sql_mib=2, seed=17))
        for number, count in ((1, 100), (2, 12), (3, 200)):
            paths = [path for path in (first / f"source{number}").rglob("*") if path.is_file()]
            self.assertEqual(len(paths), count)
            for path in paths:
                copy = second / path.relative_to(first)
                self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), hashlib.sha256(copy.read_bytes()).digest())
                self.assertEqual(path.stat().st_mtime_ns, copy.stat().st_mtime_ns)
        self.assertEqual(report["sources"]["source2"]["bytes"], 2 * 1024 * 1024)
        self.assertGreater(len(report["sources"]["source1"]["extensions"]), 4)
        with self.assertRaises(ValueError):
            generate(first, 1, 1, 1)
        log = max((first / "source3").rglob("*.txt"), key=lambda path: path.stat().st_size)
        self.assertLess(compressed_size(log.read_bytes()) / log.stat().st_size, 0.15)
        sql = next((first / "source2").rglob("*.bak")).read_bytes()
        ratio = compressed_size(sql) / len(sql)
        self.assertGreater(ratio, 0.3)
        self.assertLess(ratio, 0.7)

    def test_bitrot_byte_budget_matches_changed_bytes_then_restores(self):
        (self.source / "file").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        before = {path.name: path.read_bytes() for path in self.archive.iterdir()}
        report = bitrot([self.archive], percent=1, report_path=self.root / "damage.json", damage="bitflip")
        self.assertEqual(report["status"], "applied")
        self.assertEqual({group["category"] for group in report["groups"]},
                         {"data", "data_parity", "metadata", "metadata_parity"})
        changed_names = set()
        for group in report["groups"]:
            for change in group["changes"]:
                changed_names.add(change["filename"])
                self.assertEqual(change["xor_mask"].bit_count(), 1)
                start, length = change["offset"], change["length"]
                original = before[change["filename"]][start:start + length]
                expected = bytes(value ^ change["xor_mask"] for value in original)
                self.assertEqual(Path(change["path"]).read_bytes()[start:start + length], expected)
        budget = round(sum(map(len, before.values())) / 100)
        changed_bytes = sum(sum(left != right for left, right in zip(data, (self.archive / name).read_bytes()))
                            for name, data in before.items())
        self.assertEqual(changed_bytes, budget)
        self.assertEqual(report["archives"][0]["affected_bytes"], budget)
        self.assertFalse(any(name.endswith(("_complete.json", "_complete-copy.json")) for name in changed_names))
        self.assertEqual(verify(self.archive), 1)
        damaged = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), damaged)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_arbitrary_files_and_invalid_markers_can_be_damaged_repeatedly(self):
        self.archive.mkdir()
        for directory in (self.archive, self.archive / "nested"):
            directory.mkdir(exist_ok=True)
            (directory / "same-name.bin").write_bytes(self.data(1000))
        marker = self.archive / "archive-anything_complete.json"
        marker.write_text("not JSON or any valid archive format")
        for run_number in (1, 2):
            report = bitrot([self.archive], percent=100, damage="bitflip", seed=run_number,
                            report_path=self.root / f"random-files-{run_number}.json")
            self.assertEqual(report["archives"][0]["affected_bytes"], 2000)
            changes = [change for group in report["groups"] for change in group["changes"]]
            self.assertEqual({change["relative_path"] for change in changes},
                             {"same-name.bin", "nested/same-name.bin"})
            self.assertEqual(marker.read_text(), "not JSON or any valid archive format")
        report = bitrot([self.archive], percent=100, include_bootstrap=True,
                        report_path=self.root / "markers-too.json")
        self.assertTrue(any(group["category"] == "bootstrap" and group["changes"]
                            for group in report["groups"]))

    def test_empty_damage_directory_and_symlinks_need_no_archive_format(self):
        self.archive.mkdir()
        outside = self.root / "outside.bin"
        outside.write_bytes(b"untouched")
        (self.archive / "link").symlink_to(outside)
        (self.archive / "empty").touch()
        report = bitrot([self.archive], percent=100, report_path=self.root / "empty.json")
        self.assertEqual(report["archives"][0]["affected_bytes"], 0)
        self.assertEqual(report["archives"][0]["actual_percent"], 0)
        self.assertEqual(outside.read_bytes(), b"untouched")

    def test_bitrot_dry_run_and_zero_percent_do_not_mutate(self):
        backup(self.source, self.archive, settings=SMALL)
        before = snapshot(self.archive)
        report = bitrot([self.archive], percent=1, dry_run=True, report_path=self.root / "plan.json")
        self.assertEqual(report["status"], "dry-run")
        self.assertEqual(snapshot(self.archive), before)
        report = bitrot([self.archive], percent=0, report_path=self.root / "zero.json")
        self.assertFalse(any(group["changes"] for group in report["groups"]))
        self.assertEqual(snapshot(self.archive), before)

    def test_invalid_percent_and_overlapping_roots_fail_without_writes(self):
        backup(self.source, self.archive, settings=SMALL)
        before = snapshot(self.archive)
        for percent in (-1, 101, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                bitrot([self.archive], percent=percent)
        with self.assertRaises(ValueError):
            bitrot([self.archive, self.archive])
        with self.assertRaises(ValueError):
            bitrot([self.archive], report_path=self.archive / "report.json")
        with self.assertRaises(ValueError):
            bitrot([self.archive], damage="unknown")
        self.assertEqual(snapshot(self.archive), before)

    def test_splices_use_original_offsets_and_original_copy_sources(self):
        path = self.root / "data.bin"
        donor = self.root / "donor.bin"
        original = self.data(16000)
        donor_original = self.data(16000, seed=2)
        path.write_bytes(original)
        donor.write_bytes(donor_original)
        rng = random.Random(42)
        deletion = plan_change(path, 1024, 512, "delete", [donor], rng)
        insertion = plan_change(path, 3072, 1024, "insert", [path], rng)
        overwrite = plan_change(path, 5120, 512, "copy", [donor], rng)
        donor_flip = plan_change(donor, 0, 1024, "bitflip", [path], rng)
        overwrite["source_offset"] = donor_flip["offset"]
        copied = donor_original[overwrite["source_offset"]:overwrite["source_offset"] + overwrite["length"]]
        overwrite["source_sha256"] = hashlib.sha256(copied).hexdigest()

        expected = bytearray(original)
        # Reference splices run backwards so earlier offsets cannot move.
        for change in (overwrite, insertion, deletion):
            offset, length = change["offset"], change["length"]
            if change["operation"] == "delete":
                del expected[offset:offset + length]
            elif change["operation"] == "insert":
                start = change["source_offset"]
                expected[offset:offset] = original[start:start + length]
            else:
                expected[offset:offset + length] = copied
        # Publish the donor first to exercise copying from pre-damage bytes.
        apply_changes([{"changes": [donor_flip]}, {"changes": [overwrite, deletion, insertion]}])
        self.assertEqual(path.read_bytes(), expected)
        self.assertNotEqual(donor.read_bytes(), donor_original)
        self.assertEqual(path.stat().st_size, len(original) - deletion["length"] + insertion["length"])
        self.assertFalse(list(self.root.glob(".bitrot-*")))

    def test_include_bootstrap_and_over_capacity_are_available(self):
        (self.source / "file").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        report = bitrot([self.archive], percent=100, include_bootstrap=True,
                        report_path=self.root / "destruction.json", damage="bitflip")
        self.assertTrue(any(group["category"] == "bootstrap" and group["changes"] for group in report["groups"]))
        self.assertTrue(all(group["affected_bytes"] > 0 for group in report["groups"]))
        self.assertEqual(report["archives"][0]["affected_bytes"], report["archives"][0]["original_bytes"])
        self.assertEqual(json.loads((self.root / "destruction.json").read_text())["status"], "applied")
        self.assertEqual(verify(self.archive), 1)
        with self.assertRaises(IntegrityError):
            restore(self.archive, self.restored)

    def test_all_damage_patterns_restore(self):
        (self.source / "file").write_bytes(self.data(160000))
        for damage in (*DAMAGE_TYPES, "mixed"):
            with self.subTest(damage=damage):
                archive = self.root / f"archive-{damage}"
                target = self.root / f"target-{damage}"
                backup(self.source, archive, settings=SMALL)
                original_size = sum(path.stat().st_size for path in archive.iterdir() if path.is_file())
                report = bitrot([archive], percent=1, damage=damage,
                                report_path=self.root / f"{damage}.json")
                changes = [change for group in report["groups"] for change in group["changes"]]
                self.assertEqual(sum(change["length"] for change in changes), round(original_size / 100))
                self.assertEqual(report["archives"][0]["original_bytes"], original_size)
                inserted = sum(change["length"] for change in changes if change["operation"] == "insert")
                deleted = sum(change["length"] for change in changes if change["operation"] == "delete")
                self.assertEqual(sum(path.stat().st_size for path in archive.iterdir() if path.is_file()),
                                 original_size + inserted - deleted)
                ends = {}
                for change in sorted(changes, key=lambda item: (item["path"], item["offset"])):
                    self.assertGreaterEqual(change["offset"], ends.get(change["path"], 0))
                    ends[change["path"]] = change["offset"] + change["length"]
                before_restore = snapshot(archive)
                self.assertEqual(verify(archive), 1)
                restore(archive, target)
                self.assertEqual(compare(self.source, target), 0)
                self.assertEqual(snapshot(archive), before_restore)
                repair(archive)
                self.assertEqual(verify(archive), 0)
                operations = {change["operation"] for group in report["groups"] for change in group["changes"]}
                if damage != "mixed":
                    self.assertIn(damage, operations)
