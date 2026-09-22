"""Large geometry without large files; real early closure and recovery on tiny sets."""

import unittest
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import datagroup_prefix, new_id
from poc.archivator_lib.supergroups import SupergroupWriter
from poc.archivator_lib.limits import ceil_div, parity_plan, recovery_blocks, volume_plan
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, manifests, read_zstd_json
from poc.tests.test_recovery import snapshot


class GeometryTests(unittest.TestCase):
    def test_seventy_gib_supergroup_uses_practical_dynamic_slices(self):
        limit = 256 * 1024**2 - 1
        members = {f'file-{n}': limit for n in range(280)}
        groups = [list(members)[start:start + 56] for start in range(0, 280, 56)]
        plan = parity_plan(members, limit, groups=groups, loss_count=1, bitrot_percent=2)
        counts = [sum(ceil_div(members[name], plan.slice_size) for name in group) for group in groups]
        self.assertLessEqual(sum(counts), 2048 + len(members))
        self.assertEqual(plan.blocks, max(counts) + ceil_div(sum(members.values()) * 2, 100 * plan.slice_size))
        self.assertLessEqual(plan.largest_file, limit)

    def test_source_block_limit_inclusive_and_one_byte_over(self):
        members = {str(n): 4096 * 4096 for n in range(8)}
        volume_plan(members, 4096, 256 * 1024**2, 1)
        members['0'] += 1
        with self.assertRaises(ArchiveError):
            volume_plan(members, 4096, 256 * 1024**2, 1)

    def test_recovery_block_limit_and_full_bootstrap_protection(self):
        members = {'one': 4096}
        volume_plan(members, 4096, 256 * 1024**2, 32768)
        with self.assertRaises(ArchiveError):
            volume_plan(members, 4096, 256 * 1024**2, 32769)
        plan = parity_plan(members, 65535, protect_all=True)
        self.assertEqual(plan.blocks, 2)

    def test_whole_loss_and_bitrot_are_separate_budgets(self):
        members = {'a': 4097, 'b': 12289, 'c': 8193, 'd': 20000}
        # Source counts are 2, 4, 3, 5: lose the two largest, plus 2%.
        self.assertEqual(recovery_blocks(members, 4096, loss_count=2, bitrot_percent=2), 10)
        self.assertEqual(recovery_blocks(members, 4096, loss_count=0, bitrot_percent=2), 1)
        self.assertEqual(recovery_blocks(members, 4096, loss_count=2, bitrot_percent=0), 9)
        self.assertEqual(recovery_blocks(members, 4096, loss_count=99, bitrot_percent=100), 14)
        self.assertEqual(parity_plan(members, 65535, loss_count=0, bitrot_percent=0).blocks, 0)
        groups = [['a', 'b'], ['c'], ['d']]
        self.assertEqual(recovery_blocks(members, 4096, groups=groups, loss_count=2, bitrot_percent=2), 12)

    def test_redundancy_counts_each_files_partial_block(self):
        members = {str(n): 4097 for n in range(10)}
        self.assertEqual(recovery_blocks(members, 4096, loss_count=1), 3)
        self.assertEqual(parity_plan(members, 65535, loss_count=1).blocks, 3)

    def test_metadata_and_media_caps_cannot_be_bypassed_by_growing_slices(self):
        with self.assertRaises(ArchiveError):
            parity_plan({f'file-{n}': 1 for n in range(100)}, 10000)
        with self.assertRaises(ArchiveError):
            parity_plan({'one': 20000}, 65535, max_set_bytes=25000, loss_count=1)
        with self.assertRaises(ArchiveError):
            parity_plan({'one': 1}, 4096)

    def test_recorded_plan_preserves_geometry_after_metadata_compresses(self):
        upper = {'data': 50000, 'metadata': 12000}
        plan = parity_plan(upper, 65535, loss_count=1)
        actual = {'data': 50000, 'metadata': 1000}
        replay = parity_plan(actual, 65535, record=plan.record(), loss_count=1)
        self.assertEqual(replay.record(), plan.record())
        self.assertLessEqual(replay.total_bytes, plan.total_bytes)
        with self.assertRaises(ArchiveError):
            parity_plan(actual, 65535, record={**plan.record(), 'blocks': 1, 'volumes': 1}, loss_count=1)

    def test_supergroup_counts_open_reservations_before_any_group_is_finished(self):
        writer = SupergroupWriter(Path("unused"), new_id(), replace(SMALL, supergroup_par2=True))
        first, second = new_id(), new_id()
        def members(gid):
            prefix = datagroup_prefix(writer.archive_id, writer.id, gid)
            return {f"{prefix}_member-{n}.raw": 1000 for n in range(6)}
        with patch('poc.archivator_lib.limits.MAX_PAR2_BLOCKS', 8):
            self.assertTrue(writer.fits(first, members(first)))
            writer.reserve(first, members(first))
            self.assertEqual(writer.datagroups, [])
            self.assertTrue(writer.fits(second, members(second), alone=True))
            self.assertFalse(writer.fits(second, members(second)))


class EarlyClosureTests(ArchiveTest):
    def test_datagroup_closes_at_format_limit_before_media_is_full(self):
        settings = replace(SMALL, max_datagroup_bytes=1024**2, large_file_bytes=1)
        for number in range(10):
            (self.source / str(number)).write_bytes(self.data(30000, number))
        # Smaller test field limit exercises the real admission path without
        # generating tens of thousands of members or gigabytes of parity.
        with patch('poc.archivator_lib.limits.MAX_PAR2_BLOCKS', 8):
            backup(self.source, self.archive, settings=settings)
        records = manifests(self.archive)
        self.assertGreater(len(records), 1)
        for record in records:
            self.assertLessEqual(len(record['members']) + 2, 8)
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_supergroup_closes_before_count_limit_and_parity_regenerates(self):
        settings = replace(SMALL, supergroup_par2=True, large_file_bytes=1)
        for number in range(3):
            (self.source / str(number)).write_bytes(self.data(50000, number))
        with patch('poc.archivator_lib.limits.MAX_PAR2_BLOCKS', 10):
            backup(self.source, self.archive, settings=settings)
        records = [read_zstd_json(path) for path in self.archive.rglob('*_index-datagroups.json.zst')]
        self.assertGreater(len(records), 1)
        self.assertTrue(all(len(record['datagroups']) < settings.supergroup_datagroups for record in records))
        before = snapshot(self.archive)
        for path in self.archive.rglob('*.par2'):
            path.unlink()
        repair(self.archive)
        self.assertEqual({name: value[0] for name, value in snapshot(self.archive).items()},
                         {name: value[0] for name, value in before.items()})
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
