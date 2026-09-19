from collections import defaultdict

from poc.archivator_lib.backup import backup
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import Settings, parse_chunk
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, catalog, manifests


class DatagroupTests(ArchiveTest):
    def test_defaults_are_exact_byte_limits(self):
        self.assertEqual(Settings().max_file_bytes, 268435455)
        self.assertEqual(Settings().max_datagroup_bytes, 15032385536)

    def test_incompressible_encrypted_and_plain_outputs_obey_every_limit(self):
        key, certificate = self.certificate()
        (self.source / "large").write_bytes(self.data(500000))
        for encrypted in (False, True):
            archive = self.root / str(encrypted)
            backup(self.source, archive, certificate if encrypted else None, SMALL)
            totals = defaultdict(int)
            for path in archive.rglob("archive-*"):
                self.assertLessEqual(path.stat().st_size, SMALL.max_file_bytes, path.name)
                if path.parent == archive:
                    datagroup = "bootstrap"
                else:
                    datagroup = ("central" if "metadata" in path.relative_to(archive).parts else "local",
                             path.parent.name, path.name.split("_datagroup-")[-1][:20])
                totals[datagroup] += path.stat().st_size
            self.assertTrue(all(size <= SMALL.max_datagroup_bytes for size in totals.values()), totals)
            chunks = list(archive.rglob("*_chunk-*"))
            self.assertGreater(len({parse_chunk(path.name)["datagroup"] for path in chunks}), 1)
            restore(archive, self.root / f"target-{encrypted}", key=key if encrypted else None)
            self.assertEqual(compare(self.source, self.root / f"target-{encrypted}"), 0)

    def test_spanning_raw_begins_fresh_and_tars_remain_whole(self):
        (self.source / "large-a").write_bytes(self.data(300000))
        (self.source / "large-b").write_bytes(self.data(300000, 2))
        for number in range(120):
            (self.source / f"small-{number}").write_bytes(self.data(1000, number))
        backup(self.source, self.archive, settings=SMALL)
        by_stream = defaultdict(set)
        descriptions = {stream["stream"]: stream for stream in catalog(self.archive)}
        for manifest in manifests(self.archive):
            ids = {member["stream"] for member in manifest["members"]}
            for sid in ids:
                members = [member for member in manifest["members"] if member["stream"] == sid]
                end = members[-1]["offset"] + members[-1]["length"]
                if end < descriptions[sid]["size"]:
                    self.assertEqual(ids, {sid})
                elif members[0]["offset"] > 0:
                    self.assertEqual(manifest["members"][0]["stream"], sid)
            for sid in ids:
                by_stream[sid].add(manifest["datagroup"])
        for stream in descriptions.values():
            if stream["type"] == "tar":
                self.assertEqual(len(by_stream[stream["stream"]]), 1)
        self.assertTrue(any(len(datagroups) > 1 for datagroups in by_stream.values()))
        self.assertTrue(any(len({member["stream"] for member in datagroup["members"]}) > 1
                            for datagroup in manifests(self.archive)))

    def test_tar_continues_across_directories_and_singleton_falls_back(self):
        for name in ("one", "two"):
            (self.source / name).mkdir()
            (self.source / name / "document").write_text(name)
        backup(self.source, self.archive, settings=SMALL)
        streams = catalog(self.archive)
        self.assertEqual([stream["type"] for stream in streams], ["tar"])
        paths = {entry["path"] for entry in streams[0]["inventory"]}
        self.assertIn("one/document", paths)
        self.assertIn("two/document", paths)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_largest_chunk_loss_can_be_repaired(self):
        (self.source / "large").write_bytes(self.data(200000))
        backup(self.source, self.archive, settings=SMALL)
        max(self.archive.rglob("*_chunk-*"), key=lambda path: path.stat().st_size).unlink()
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)

    def test_lookahead_can_use_a_companion_more_than_eight_names_ahead(self):
        for number in range(16):
            (self.source / f"a-{number:02}").write_bytes(self.data(30000, number))
        (self.source / "z-small").write_text("fits in a small gap")
        backup(self.source, self.archive, settings=SMALL)
        first = next(stream for stream in catalog(self.archive) if stream["type"] == "tar")
        paths = {entry["path"] for entry in first["inventory"]}
        self.assertIn("z-small", paths)
        self.assertNotIn("a-15", paths)

    def test_large_file_is_read_before_scanning_a_later_directory(self):
        import os
        from unittest.mock import patch
        (self.source / "a-large").write_bytes(self.data(160000))
        later = self.source / "later"
        later.mkdir()
        (later / "small").write_text("later")
        actual_scandir = os.scandir

        def inspect(path):
            if str(path) == str(later):
                self.assertTrue(list(self.archive.rglob("*_chunk-*")))
            return actual_scandir(path)

        with patch("poc.archivator_lib.filesystem.os.scandir", side_effect=inspect):
            backup(self.source, self.archive, settings=SMALL)

    def test_an_isolated_large_file_fragment_is_not_published_as_a_file(self):
        import shutil
        (self.source / "large").write_bytes(self.data(300000))
        backup(self.source, self.archive, settings=SMALL)
        datagroup = next(item for item in manifests(self.archive) if item["members"])
        isolated = self.root / "isolated"
        isolated.mkdir()
        for path in (self.archive / "data" / datagroup["supergroup"][:2] / datagroup["supergroup"] / datagroup["datagroup"]).glob(f"*_datagroup-{datagroup['datagroup']}*"):
            shutil.copyfile(path, isolated / path.name)
        self.assertEqual(restore(isolated, self.restored), 1)
        self.assertFalse((self.restored / "large").exists())

    def test_oversized_transformation_is_not_published(self):
        from unittest.mock import patch
        from poc.archivator_lib.common import ArchiveError
        from poc.archivator_lib.external import ZstdWriter
        (self.source / "file").write_text("input")
        finish = ZstdWriter.finish

        def oversized(writer):
            finish(writer)
            # The actual output descriptor has closed; append via its known
            # staging name to model an unexpected compressor-size regression.
            with (self.archive / ".tmp" / "chunk").open("ab") as output:
                output.write(bytes(SMALL.max_file_bytes + 1))

        with patch.object(ZstdWriter, "finish", oversized):
            with self.assertRaises(ArchiveError):
                backup(self.source, self.archive, settings=SMALL)
        self.assertFalse(list(self.archive.rglob("*_catalog-root.json")))
        self.assertTrue(all(path.stat().st_size <= SMALL.max_file_bytes
                            for path in self.archive.rglob("*") if path.is_file()))
