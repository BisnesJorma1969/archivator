import io
import json
import tarfile
from dataclasses import replace
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import main
from poc.archivator_lib.common import IntegrityError
from poc.archivator_lib.external import ZstdWriter
from poc.archivator_lib.format import datafile_name, parse_datafile
from poc.archivator_lib.limits import input_limit
from poc.archivator_lib.restore import restore
from poc.archivator_lib.scan import scan
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json, read_zstd_jsonl, catalog
from poc.tests.test_recovery import snapshot


class ScanTests(ArchiveTest):
    def write_chunk(self, data, offset=0, kind="raw"):
        name = datafile_name("a" * 20, "b" * 20, "c" * 20, offset, len(data), False, kind, supergroup="d" * 20)
        self.archive.mkdir(exist_ok=True)
        writer = ZstdWriter(self.archive / name)
        writer.write(data)
        writer.finish()
        return name

    def remove_metadata(self, archive):
        for path in archive.rglob("archive-*"):
            if "_metadata_" in path.name or "_metadata." in path.name or path.name.endswith("_metadata_index-datafiles.json.zst"):
                path.unlink()

    def test_scan_reads_names_not_payload_or_metadata_contents(self):
        name = self.write_chunk(b"payload")
        (self.archive / name).write_bytes(b"not even a zstd frame")
        (self.archive / ("archive-" + "a" * 20 + "_metadata_catalog-root.json")).write_bytes(b"invalid json")
        nested = self.archive / "nested" / "deeper"
        nested.mkdir(parents=True)
        (self.archive / name).rename(nested / name)
        index = self.root / "scan.json.zst"
        with patch("builtins.open", side_effect=AssertionError("Scan must not read file contents")):
            scan(self.archive, index)
        data = read_zstd_json(index)
        self.assertEqual(data["files"], [name])
        self.assertEqual(data["archive"], "a" * 20)
        with self.assertRaises(FileExistsError):
            scan(self.archive, index)

    def test_restore_without_any_metadata_in_mixed_layout_and_both_encryption_modes(self):
        key, certificate = self.certificate()
        (self.source / "document.txt").write_text("recover this document")
        (self.source / "second.txt").write_text("a TAR companion")
        content = self.data(80000)
        (self.source / "large.raw").write_bytes(content)
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                archive = self.root / f"archive-{encrypted}"
                target = self.root / f"target-{encrypted}"
                backup(self.source, archive, certificate if encrypted else None, SMALL)
                datasets = catalog(archive, key if encrypted else None)
                direct = next(item for item in datasets if item["type"] == "file")
                bundle = next(item for item in datasets if item["type"] == "tar")
                self.remove_metadata(archive)
                nested = archive / "nested" / "different"
                nested.mkdir(parents=True)
                for number, path in enumerate(list(archive.rglob("archive-*"))):
                    if number % 3 == 0:
                        path.rename(archive / path.name)
                    elif number % 3 == 1:
                        path.rename(nested / path.name)
                index = self.root / f"scan-{encrypted}.json.zst"
                before = snapshot(archive)
                scan(archive, index)
                self.assertEqual(restore(archive, target, key=key if encrypted else None, scan_index=index), 0)
                self.assertEqual((target / f"dataset-{direct['dataset']}.raw").read_bytes(), content)
                self.assertEqual((target / f"dataset-{bundle['dataset']}" / "document.txt").read_text(),
                                 "recover this document")
                self.assertTrue((target / f"dataset-{bundle['dataset']}.tar").is_file())
                self.assertEqual(snapshot(archive), before)

    def test_unrecoverable_gap_skips_entire_dataset_but_restores_other_datasets(self):
        (self.source / "small.txt").write_text("surviving file")
        (self.source / "second.txt").write_text("TAR companion")
        (self.source / "large").write_bytes(self.data(200000))
        backup(self.source, self.archive, settings=SMALL)
        chunks = list(self.archive.rglob("*_dataset-*.zst"))
        missing = next(path for path in chunks if parse_datafile(path.name)["offset"] == input_limit(SMALL.max_file_bytes))
        skipped_id = parse_datafile(missing.name)["dataset"]
        missing.unlink()
        self.remove_metadata(self.archive)
        for path in self.archive.rglob("*.par2"):
            path.unlink()
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 1)
        self.assertFalse(list(self.restored.glob(f"dataset-{skipped_id}*")))
        self.assertEqual(next(self.restored.rglob("small.txt")).read_text(), "surviving file")

    def test_par2_recovers_a_chunk_missing_before_scan(self):
        (self.source / "large").write_bytes(self.data(80000))
        backup(self.source, self.archive, settings=SMALL)
        missing = next(path for path in self.archive.rglob("*_dataset-*.zst")
                       if parse_datafile(path.name)["offset"] == input_limit(SMALL.max_file_bytes))
        dataset = parse_datafile(missing.name)["dataset"]
        missing.unlink()
        self.remove_metadata(self.archive)
        index = self.root / "scan.json.zst"
        before = snapshot(self.archive)
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 0)
        self.assertEqual((self.restored / f"dataset-{dataset}.raw").read_bytes(), (self.source / "large").read_bytes())
        self.assertEqual(snapshot(self.archive), before)

    def test_surviving_parity_can_recover_all_missing_datafile_names(self):
        # Explicitly cover all three protected files: payload and both indexes.
        content = self.data(20000)
        (self.source / "document.txt").write_bytes(content)
        backup(self.source, self.archive, settings=replace(SMALL, datagroup_loss_files=3))
        self.remove_metadata(self.archive)
        for path in self.archive.rglob("*_dataset-*.zst"):
            path.unlink()
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 0)
        self.assertEqual(next(self.restored.glob("*.raw")).read_bytes(), content)

    def test_missing_after_scan_and_bad_encryption_key_never_publish_partial_datasets(self):
        (self.source / "large").write_bytes(self.data(80000))
        key, certificate = self.certificate()
        wrong_key, _ = self.certificate("wrong")
        backup(self.source, self.archive, certificate, SMALL)
        self.remove_metadata(self.archive)
        for path in self.archive.rglob("*.par2"):
            path.unlink()
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, key=wrong_key, scan_index=index), 1)
        self.assertEqual(list(self.restored.iterdir()), [])
        chunks = sorted(self.archive.rglob("*_dataset-*.cms"), key=lambda path: parse_datafile(path.name)["offset"])
        missing = chunks[-1]
        dataset = parse_datafile(missing.name)["dataset"]
        missing.unlink()
        target = self.root / "missing-tail"
        self.assertEqual(restore(self.archive, target, key=key, scan_index=index), 1)
        self.assertFalse(list(target.glob(f"dataset-{dataset}*")))

    def test_unsafe_tar_is_skipped_without_writing_outside_target(self):
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode="w") as archive:
            member = tarfile.TarInfo("../../escaped")
            member.size = 3
            archive.addfile(member, io.BytesIO(b"bad"))
        self.write_chunk(contents.getvalue(), kind="tar")
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 1)
        self.assertFalse((self.root / "escaped").exists())
        self.assertEqual(list(self.restored.iterdir()), [])

    def test_index_cannot_introduce_paths_outside_archive(self):
        self.write_chunk(b"content")
        index = self.root / "bad-index.json.zst"
        writer = ZstdWriter(index)
        writer.write(json.dumps({"format": "archivator-scan", "version": 1,
                                 "archive": "a" * 20, "files": ["../outside"]}).encode())
        writer.finish()
        with self.assertRaises(IntegrityError):
            restore(self.archive, self.restored, scan_index=index)
        self.assertFalse(self.restored.exists())

    def test_overlapping_chunks_skip_dataset(self):
        self.write_chunk(b"first chunk")
        self.write_chunk(b"overlap", offset=1)
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 1)
        self.assertEqual(list(self.restored.iterdir()), [])

    def test_truncated_tar_is_not_published_as_a_complete_tree(self):
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode="w") as archive:
            member = tarfile.TarInfo("file.txt")
            member.size = 3
            archive.addfile(member, io.BytesIO(b"abc"))
        self.write_chunk(contents.getvalue()[:1024], kind="tar")
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 1)
        self.assertEqual(list(self.restored.iterdir()), [])

    def test_cli_scan_index_can_be_used_by_restore(self):
        self.write_chunk(b"recovered through the CLI")
        index = self.root / "scan.json.zst"
        self.assertEqual(main(["scan", str(self.archive), str(index)]), 0)
        self.assertEqual(main(["restore", str(self.archive), str(self.restored), "--scan-index", str(index)]), 0)
        self.assertEqual(next(self.restored.glob("*.raw")).read_bytes(), b"recovered through the CLI")
