"""Closing summaries are useful without becoming a payload restore dependency."""

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import main
from poc.archivator_lib.compare import compare
from poc.archivator_lib.common import read_json
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.archivator_lib.seal import quick_check, seal_bytes, seal_record
from poc.tests.support import ArchiveTest, SMALL
from poc.tests.test_recovery import flip, snapshot


class SealTests(ArchiveTest):
    def make_archive(self, outer=False):
        (self.source / 'original').write_bytes(self.data(100000))
        backup(self.source, self.archive, settings=replace(SMALL, supergroup_par2=outer))
        return list(self.archive.rglob('*_sealed_*.json'))

    def test_json_and_filename_counters_agree_and_all_bytes_fit(self):
        seals = self.make_archive(outer=True)
        self.assertTrue(seals)
        for path in seals:
            record = read_json(path)
            self.assertEqual(record, seal_record(path.name))
            self.assertEqual(path.read_bytes(), seal_bytes(path.name))
            others = [file for file in path.parent.iterdir() if file != path]
            self.assertEqual(sum(record[role]['files'] for role in ('data', 'metadata', 'parity')), len(others))
            self.assertEqual(sum(record[role]['bytes'] for role in ('data', 'metadata', 'parity')),
                             sum(file.stat().st_size for file in others))
            self.assertLessEqual(sum(file.stat().st_size for file in [*others, path]), SMALL.max_datagroup_bytes)
            self.assertLessEqual(len(path.relative_to(self.archive).as_posix()), 256)
        self.assertEqual(main(['quick-check', str(self.archive)]), 0)

    def test_listing_only_flat_uppercase_detects_size_loss_not_same_size_bitrot(self):
        self.make_archive()
        for path in list(self.archive.rglob('archive-*')):
            path.rename(self.archive / path.name.upper())
        with patch('builtins.open', side_effect=AssertionError('No content reads')), \
                patch.object(Path, 'open', side_effect=AssertionError('No content reads')):
            self.assertEqual(quick_check(self.archive), 0)
        payload = next(self.archive.glob('*.RAW.ZST'))
        flip(payload)
        self.assertEqual(quick_check(self.archive), 0)  # Not a checksum checker.
        self.assertEqual(verify(self.archive), 1)
        payload.unlink()
        self.assertEqual(quick_check(self.archive), 1)
        self.assertIn('Entirely absent datagroups cannot be detected', self.report.getvalue())

    def test_missing_or_damaged_seal_rebuilt_from_receipt_without_outer_parity(self):
        seals = self.make_archive()
        expected = {path.name: path.read_bytes() for path in seals}
        seals[0].unlink()
        if len(seals) > 1:
            flip(seals[1])
        before = snapshot(self.archive)
        self.assertEqual(quick_check(self.archive), 1)
        self.assertEqual(verify(self.archive), 1)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual(quick_check(self.archive), 0)
        self.assertEqual({path.name: path.read_bytes() for path in self.archive.rglob('*_sealed_*.json')}, expected)

    def test_summary_is_optional_for_isolated_datagroup_restore(self):
        self.make_archive()
        # Remove the archive-wide entry points, central metadata, and summaries.
        # Primary indexes and local PAR2 are sufficient for healthy data.
        for path in list(self.archive.rglob('archive-*')):
            if ('metadata' in path.relative_to(self.archive).parts
                    or path.parent == self.archive or '_sealed_' in path.name):
                path.unlink()
        self.assertEqual(restore(self.archive, self.restored), 1)  # Full archive completeness is unknown.
        self.assertEqual(compare(self.source, self.restored), 0)
