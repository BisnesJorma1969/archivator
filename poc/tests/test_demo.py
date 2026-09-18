import hashlib
import json
from pathlib import Path

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import IntegrityError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.demo.bitrot import bitrot
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

    def test_bitrot_hits_metadata_and_both_parity_types_then_restores(self):
        (self.source / "file").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        before = {path.name: path.read_bytes() for path in self.archive.iterdir()}
        report = bitrot([self.archive], percent=1, report_path=self.root / "damage.json")
        self.assertEqual(report["status"], "applied")
        self.assertEqual({group["category"] for group in report["groups"]},
                         {"data", "data_parity", "metadata", "metadata_parity"})
        changed_names = set()
        for group in report["groups"]:
            self.assertGreater(group["selected_blocks"], 0)
            for change in group["changes"]:
                changed_names.add(change["filename"])
                self.assertEqual((change["before"] ^ change["after"]).bit_count(), 1)
                self.assertEqual(before[change["filename"]][change["offset"]], change["before"])
                self.assertEqual(Path(change["path"]).read_bytes()[change["offset"]], change["after"])
        self.assertFalse(any(name.endswith("_complete.json") for name in changed_names))
        self.assertEqual(verify(self.archive), 1)
        damaged = snapshot(self.archive)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), damaged)
        with self.assertRaises(IntegrityError):
            bitrot([self.archive], report_path=self.root / "repeat.json")
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

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
        self.assertEqual(snapshot(self.archive), before)

    def test_include_bootstrap_and_over_capacity_are_available(self):
        (self.source / "file").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        report = bitrot([self.archive], percent=100, include_bootstrap=True,
                        report_path=self.root / "destruction.json")
        self.assertTrue(any(group["category"] == "bootstrap" and group["changes"] for group in report["groups"]))
        self.assertEqual(json.loads((self.root / "destruction.json").read_text())["status"], "applied")
        self.assertEqual(verify(self.archive), 1)
        with self.assertRaises(IntegrityError):
            restore(self.archive, self.restored)
