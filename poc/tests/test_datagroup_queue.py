import shutil
import contextlib
import io
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from poc.archivator_lib.backup import DatagroupQueue, backup
from poc.archivator_lib.cli import parser
from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import ZstdWriter
from poc.archivator_lib.format import Settings
from poc.archivator_lib.recovery import verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, catalog, manifests


class CapacityGroup:
    """A 100-byte budget fixture for queue policy, with no compressor or disk I/O."""

    def __init__(self, settings):
        self.settings = settings
        self.members = []
        self.sources = {}
        self.closed = False

    def budget(self, members, sources):
        return sum(members)

    def can_add(self, chunks, stream, entries):
        return sum(self.members) + sum(chunks) <= 100

    def append(self, chunks, stream, entries):
        assert not self.closed and self.can_add(chunks, stream, entries)
        self.members.extend(chunks)

    def finish_set(self):
        assert not self.closed
        self.closed = True


class QueuePolicyTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def queue(self, waiting=4, percent=95):
        settings = SimpleNamespace(max_datagroup_bytes=100, waiting_datagroups=waiting, datagroup_close_percent=percent, supergroup_datagroups=100)
        return DatagroupQueue(lambda: CapacityGroup(settings))

    def test_waiting_datagroup_is_filled_before_active_datagroup(self):
        queue = self.queue()
        queue.place([60], None, [])
        first = queue.active
        queue.place([60], None, [])
        second = queue.active
        queue.place([40], None, [])
        self.assertEqual(first.members, [60, 40])
        self.assertEqual(second.members, [60])
        queue.finish()
        self.assertTrue(first.closed and second.closed)

    def test_high_mark_closes_only_on_a_miss(self):
        queue = self.queue()
        queue.place([96], None, [])
        first = queue.active
        queue.place([2], None, [])
        self.assertFalse(first.closed)
        self.assertEqual(first.members, [96, 2])
        queue.place([3], None, [])
        self.assertTrue(first.closed)
        self.assertEqual(queue.waiting, [])

    def test_high_mark_is_configurable(self):
        for percent, closed in ((75, True), (85, False), (95, False), (100, False)):
            queue = self.queue(percent=percent)
            queue.place([80], None, [])
            first = queue.active
            queue.place([30], None, [])
            self.assertEqual(first.closed, closed)

    def test_fuller_datagroup_is_evicted_without_an_age_limit(self):
        queue = self.queue(waiting=1)
        queue.place([40], None, [])
        spacious = queue.active
        for _ in range(20):
            queue.place([80], None, [])
            self.assertEqual(queue.waiting, [spacious])
            self.assertFalse(spacious.closed)
        queue.place([50], None, [])
        self.assertEqual(spacious.members, [40, 50])

    def test_equal_fill_closes_the_older_datagroup(self):
        queue = self.queue(waiting=1)
        queue.place([60], None, [])
        first = queue.active
        queue.place([60], None, [])
        second = queue.active
        queue.place([60], None, [])
        self.assertTrue(first.closed)
        self.assertEqual(queue.waiting, [second])

    def test_waiting_limit_is_a_parameter_including_zero(self):
        for limit in (0, 1, 4, 8):
            queue = self.queue(waiting=limit)
            for _ in range(20):
                queue.place([60], None, [])
                self.assertLessEqual(len(queue.waiting), limit)
            self.assertEqual(len(queue.waiting), limit)

    def test_defaults_and_cli_validation(self):
        self.assertEqual(Settings().waiting_datagroups, 4)
        self.assertEqual(Settings().datagroup_close_percent, 95)
        args = parser().parse_args(["backup", "source", "archive", "--waiting-datagroups", "8",
                                    "--datagroup-close-percent", "100"])
        self.assertEqual((args.waiting_datagroups, args.datagroup_close_percent), (8, 100))
        for options in ({"waiting_datagroups": -1}, {"datagroup_close_percent": 0},
                        {"datagroup_close_percent": 101}, {"waiting_datagroups": 1.5}):
            with self.assertRaises(ArchiveError):
                Settings(**options)


# Short test filenames still incur real PAR2 packet repetition. Allow enough
# datagroup space to exercise multi-file placement, not only parity overhead.
QUEUE = replace(SMALL, max_datagroup_bytes=512 * 1024, large_file_bytes=1)


class WholeFilePlacementTests(ArchiveTest):
    def datagroups_by_path(self, archive=None, key=None):
        archive = archive or self.archive
        descriptions = {stream["stream"]: stream for stream in catalog(archive, key)}
        result = {}
        for datagroup in manifests(archive):
            for member in datagroup["members"]:
                stream = descriptions[member["stream"]]
                if stream["type"] == "file":
                    result.setdefault(stream["path"], set()).add(datagroup["datagroup"])
        return result

    def test_multi_chunk_whole_raw_files_can_share_one_datagroup(self):
        for name in ("a", "b"):
            (self.source / name).write_bytes(self.data(70000))
        backup(self.source, self.archive, settings=replace(QUEUE, large_file_bytes=1))
        datagroups = self.datagroups_by_path()
        self.assertEqual(datagroups["a"], datagroups["b"])
        self.assertEqual(len(datagroups["a"]), 1)
        self.assertGreater(len(list(self.archive.rglob("*.raw.zst"))), 2)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_non_fitting_file_starts_fresh_and_next_file_reuses_waiting_datagroup(self):
        key, certificate = self.certificate()
        for name, size in (("a", 180000), ("b", 180000), ("c", 10000)):
            (self.source / name).write_bytes(self.data(size))
        for encrypted in (False, True):
            archive = self.root / f"archive-{encrypted}"
            backup(self.source, archive, certificate if encrypted else None, replace(QUEUE, large_file_bytes=1))
            datagroups = self.datagroups_by_path(archive, key if encrypted else None)
            self.assertEqual(datagroups["a"], datagroups["c"])
            self.assertNotEqual(datagroups["a"], datagroups["b"])
            self.assertTrue(all(len(ids) == 1 for ids in datagroups.values()))
            target = self.root / f"target-{encrypted}"
            self.assertEqual(restore(archive, target, key=key if encrypted else None), 0)
            self.assertEqual(compare(self.source, target), 0)

    def test_fit_uses_stored_sizes_not_original_size_or_chunk_count(self):
        (self.source / "a").write_bytes(self.data(100000))
        (self.source / "b").write_bytes(b"x" * 600000)
        backup(self.source, self.archive, settings=QUEUE)
        datagroups = self.datagroups_by_path()
        self.assertEqual(datagroups["a"], datagroups["b"])
        self.assertEqual(len(datagroups["b"]), 1)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_spanning_file_starts_fresh_and_final_tail_accepts_a_whole_file(self):
        for name, size in (("a", 180000), ("b", 900000), ("c", 10000)):
            (self.source / name).write_bytes(self.data(size))
        settings = replace(QUEUE, large_file_bytes=1, waiting_datagroups=0)
        backup(self.source, self.archive, settings=settings)
        datagroups = self.datagroups_by_path()
        self.assertTrue(datagroups["a"].isdisjoint(datagroups["b"]))
        self.assertGreater(len(datagroups["b"]), 1)
        self.assertLessEqual(datagroups["c"], datagroups["b"])
        self.assertEqual(len(datagroups["c"]), 1)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)
        # An isolated last datagroup can restore C even though B is incomplete.
        tail = next(iter(datagroups["c"]))
        isolated = self.root / "isolated"
        isolated.mkdir()
        for path in self.archive.rglob(f"*_datagroup-{tail}*"):
            shutil.copyfile(path, isolated / path.name)
        target = self.root / "partial"
        self.assertEqual(restore(isolated, target), 1)
        self.assertFalse((target / "b").exists())
        self.assertEqual((target / "c").read_bytes(), (self.source / "c").read_bytes())

    def test_buffering_is_bounded_and_each_chunk_is_compressed_only_once(self):
        (self.source / "large").write_bytes(self.data(900000))
        starts = []
        original_start = DatagroupQueue.start_large_file

        def start(queue):
            sizes = [path.stat().st_size for path in queue.planner.staging.glob("buffer-*")]
            starts.append(sum(sizes))
            self.assertLessEqual(sum(sizes), QUEUE.max_datagroup_bytes + QUEUE.max_file_bytes)
            original_start(queue)

        finish = ZstdWriter.finish
        compressed = []

        def count(writer):
            finish(writer)
            compressed.append(1)

        with patch.object(DatagroupQueue, "start_large_file", start), patch.object(ZstdWriter, "finish", count), \
                patch("os.link", side_effect=AssertionError("Backup must not hardlink chunks")), \
                patch("shutil.copyfile", wraps=shutil.copyfile) as copying:
            backup(self.source, self.archive, settings=QUEUE)
        self.assertEqual(len(starts), 1)
        self.assertEqual(len(compressed), len(list(self.archive.rglob("*_chunk-*"))))
        self.assertTrue(all("_chunk-" not in str(call.args[0]) and "buffer-" not in str(call.args[0])
                            for call in copying.call_args_list))
        self.assertFalse((self.archive / ".tmp").exists())
        self.assertEqual(verify(self.archive), 0)
