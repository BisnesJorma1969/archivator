"""Explicit loss budgets, independent zero settings, and cross-supergroup RAW files."""

from dataclasses import replace

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import parser
from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import check_parity, create_parity
from poc.archivator_lib.format import Settings, parse_datafile
from poc.archivator_lib.limits import parity_plan
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, manifests
from poc.tests.test_recovery import flip, snapshot


class LossPolicyTests(ArchiveTest):
    def test_defaults_and_invalid_values(self):
        args = parser().parse_args(['backup', 'source', 'archive'])
        for settings in (Settings(), args):
            self.assertEqual((settings.datagroup_loss_files, settings.datagroup_bitrot_percent,
                              settings.supergroup_loss_datagroups, settings.supergroup_bitrot_percent), (0, 2, 1, 2))
        for option in ('datagroup_loss_files', 'supergroup_loss_datagroups',
                       'datagroup_bitrot_percent', 'supergroup_bitrot_percent'):
            with self.subTest(option=option), self.assertRaises(ArchiveError):
                Settings(**{option: -1})
        with self.assertRaises(ArchiveError):
            Settings(datagroup_bitrot_percent=101)

    def test_real_par2_covers_multiple_largest_losses_and_additional_bitrot(self):
        for grouped in (False, True):
            with self.subTest(grouped=grouped):
                base = self.root / f'parity-{grouped}'
                base.mkdir()
                sizes = [65536, 49152, 32768, 16384, 8192, 4096]
                names = [f'file-{number}' for number in range(len(sizes))]
                originals = {name: self.data(size, number) for number, (name, size) in enumerate(zip(names, sizes))}
                for name, data in originals.items():
                    (base / name).write_bytes(data)
                groups = [names[:2], names[2:4], names[4:]] if grouped else None
                plan = parity_plan(dict(zip(names, sizes)), 1024**2, groups=groups,
                                   loss_count=2, bitrot_percent=2)
                create_parity(base, 'recovery', names, plan.slice_size, plan.blocks, volumes=plan.volumes)
                missing = names[:4] if grouped else names[:2]
                for name in missing:
                    (base / name).unlink()
                flip(base / names[-1])
                self.assertEqual(check_parity(base, 'recovery'), 1)
                self.assertEqual(check_parity(base, 'recovery', repair=True), 0)
                self.assertEqual({name: (base / name).read_bytes() for name in names}, originals)

    def test_zero_local_and_outer_budgets_are_independent(self):
        (self.source / 'file').write_bytes(self.data(80000))
        for local, outer in ((0, 0), (0, 2), (2, 0), (2, 2)):
            with self.subTest(local=local, outer=outer):
                settings = replace(SMALL, datagroup_loss_files=0, datagroup_bitrot_percent=local,
                                   supergroup_par2=True, supergroup_loss_datagroups=0, supergroup_bitrot_percent=outer)
                archive = self.root / f'archive-{local}-{outer}'
                target = self.root / f'target-{local}-{outer}'
                backup(self.source, archive, settings=settings)
                parity = list(archive.rglob('*.par2'))
                self.assertEqual(any('_datagroup-' in path.name for path in parity), bool(local))
                self.assertEqual(any('_supergroup-' in path.name and '_datagroup-' not in path.name for path in parity), bool(outer))
                self.assertTrue(any('_catalog-root' in path.name for path in parity))
                self.assertEqual(verify(archive), 0)
                repair(archive)
                self.assertEqual(restore(archive, target), 0)
                self.assertEqual(compare(self.source, target), 0)

    def test_outer_repair_works_when_local_parity_is_disabled_by_zero_budget(self):
        (self.source / 'file').write_bytes(self.data(80000))
        settings = replace(SMALL, datagroup_loss_files=0, datagroup_bitrot_percent=0,
                           supergroup_par2=True, supergroup_loss_datagroups=1)
        backup(self.source, self.archive, settings=settings)
        next(self.archive.rglob('*.raw.zst')).unlink()
        before = snapshot(self.archive)
        self.assertEqual(verify(self.archive), 1)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertFalse(any('_datagroup-' in path.name for path in self.archive.rglob('*.par2')))

    def test_one_raw_dataset_spans_supergroups_and_recovers_without_reordering(self):
        content = self.data(850000)
        (self.source / 'large').write_bytes(content)
        settings = replace(SMALL, datagroup_loss_files=0, datagroup_bitrot_percent=2,
                           supergroup_par2=True, supergroup_datagroups=2)
        backup(self.source, self.archive, settings=settings)
        chunks = [(path, parse_datafile(path.name)) for path in self.archive.rglob('*.raw.zst')]
        self.assertEqual(len({info['dataset'] for _, info in chunks}), 1)
        self.assertGreater(len({info['supergroup'] for _, info in chunks}), 1)
        ordered = sorted(chunks, key=lambda item: item[1]['offset'])
        end = 0
        for _, info in ordered:
            self.assertEqual(info['offset'], end)
            end += info['length']
        self.assertEqual(end, len(content))
        # Local 2% cannot replace a whole datafile: this requires the outer layer.
        lost_group = ordered[0][1]['datagroup']
        for path in list(self.archive.rglob('archive-*')):
            if f'_datagroup-{lost_group}' in path.name and 'metadata' not in path.relative_to(self.archive).parts:
                path.unlink()
        before = snapshot(self.archive)
        self.assertEqual(restore(self.archive, self.restored), 0, self.report.getvalue())
        self.assertEqual((self.restored / 'large').read_bytes(), content)
        self.assertEqual(snapshot(self.archive), before)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_more_than_64_datafiles_can_share_one_datagroup(self):
        for number in range(100):
            (self.source / f'{number:03}').write_bytes(bytes([number]) * 100)
        settings = replace(SMALL, par2=False, large_file_bytes=1, max_file_bytes=262143,
                           max_datagroup_bytes=2 * 1024**2)
        backup(self.source, self.archive, settings=settings)
        records = manifests(self.archive)
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]['members']), 100)
        self.assertTrue(all('chunk' not in member for member in records[0]['members']))
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
