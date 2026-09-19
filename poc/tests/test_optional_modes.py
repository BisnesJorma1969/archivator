"""All transform combinations, including operation without optional executables."""

import contextlib
import json
import shutil
import tarfile
from dataclasses import replace
from itertools import product
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import main, parser
from poc.archivator_lib.common import IntegrityError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import parse_chunk
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.archivator_lib.scan import scan
from poc.tests.support import ArchiveTest, SMALL, catalog
from poc.tests.test_recovery import flip, snapshot


class OptionalModeTests(ArchiveTest):
    def optional_tools(self, compression, encryption, par2):
        """Fail even a dependency lookup for a disabled feature."""
        from poc.archivator_lib.external import executable

        allowed = {name for name, enabled in (("zstd", compression), ("openssl", encryption), ("par2", par2))
                   if enabled}

        def lookup(name):
            self.assertIn(name, allowed, f"Disabled feature requested {name}")
            return executable(name)

        stack = contextlib.ExitStack()
        for module in ("backup", "metadata", "external", "restore", "scan"):
            stack.enter_context(patch(f"poc.archivator_lib.{module}.executable", side_effect=lookup))
        return stack

    def test_all_eight_modes_roundtrip_repair_and_filename_only_recovery(self):
        key, certificate = self.certificate()
        (self.source / "private-large.bin").write_bytes(self.data(190000))
        (self.source / "private-notes.txt").write_text("First note\n" * 80)
        (self.source / "private-other.txt").write_text("Second note\n" * 90)
        for compression, encryption, par2 in product((False, True), repeat=3):
            with self.subTest(compression=compression, encryption=encryption, par2=par2):
                label = f"{compression}-{encryption}-{par2}"
                archive = self.root / f"archive-{label}"
                target = self.root / f"target-{label}"
                settings = replace(SMALL, compression=compression, par2=par2)
                with self.optional_tools(compression, encryption, par2):
                    backup(self.source, archive, certificate if encryption else None, settings)
                    paths = [path for path in archive.rglob("*") if path.is_file()]
                    self.assertEqual(any(path.suffix == ".par2" for path in paths), par2)
                    chunks = [path for path in paths if "_chunk-" in path.name]
                    self.assertEqual({parse_chunk(path.name)["kind"] for path in chunks}, {"raw", "tar"})
                    for path in chunks:
                        parsed = parse_chunk(path.name)
                        self.assertEqual(parsed["compressed"], compression)
                        self.assertEqual(parsed["encrypted"], encryption)
                    for path in paths:
                        self.assertLessEqual(path.stat().st_size, settings.max_file_bytes)
                        if not compression:
                            self.assertNotIn(".zst", path.name)
                        if encryption:
                            self.assertNotIn(b"private-notes.txt", path.read_bytes())
                            self.assertNotIn(b"private-large.bin", path.read_bytes())
                    for group_id in {parse_chunk(path.name)["group"] for path in chunks}:
                        for directory in (archive / group_id[:2], archive / "metadata" / group_id[:2]):
                            group = [path for path in directory.iterdir() if group_id in path.name]
                            self.assertLessEqual(sum(path.stat().st_size for path in group), settings.max_group_bytes)
                    self.assertEqual(verify(archive), 0)
                    before = snapshot(archive)
                    self.assertEqual(restore(archive, target, key=key if encryption else None), 0)
                    self.assertEqual(compare(self.source, target), 0)
                    self.assertEqual(snapshot(archive), before)
                    repair(archive)  # No parity must stay no parity, including explicit repair.
                    self.assertEqual(snapshot(archive), before)

                    streams = catalog(archive, key if encryption else None)
                    direct = next(stream for stream in streams if stream["type"] == "file")
                    bundle = next(stream for stream in streams if stream["type"] == "tar")
                    # Leave only payloads: recovery must not depend on metadata/PAR2.
                    for path in paths:
                        if "_chunk-" not in path.name:
                            path.unlink()
                    index = self.root / f"scan-{label}.json"
                    scan(archive, index)
                    scanned = self.root / f"scanned-{label}"
                    self.assertEqual(restore(archive, scanned, key=key if encryption else None, scan_index=index), 0)
                    self.assertEqual((scanned / f"stream-{direct['stream']}.raw").read_bytes(),
                                     (self.source / "private-large.bin").read_bytes())
                    self.assertEqual((scanned / f"stream-{bundle['stream']}" / "private-notes.txt").read_bytes(),
                                     (self.source / "private-notes.txt").read_bytes())
                    if not compression and not encryption:
                        with tarfile.open(next(path for path in chunks if path.suffix == ".tar"), "r:") as tar:
                            self.assertIn("private-notes.txt", tar.getnames())

    def test_no_parity_detects_corruption_and_restores_only_intact_streams(self):
        (self.source / "large").write_bytes(self.data(190000))
        (self.source / "note1").write_text("one")
        (self.source / "note2").write_text("two")
        settings = replace(SMALL, compression=False, par2=False)
        with self.optional_tools(False, False, False):
            backup(self.source, self.archive, settings=settings)
            damaged = next(self.archive.rglob("*.raw"))
            flip(damaged)
            before = snapshot(self.archive)
            self.assertEqual(verify(self.archive), 1)
            with self.assertRaisesRegex(IntegrityError, "PAR2 is disabled"):
                repair(self.archive)
            self.assertEqual(restore(self.archive, self.restored), 1)
            self.assertFalse((self.restored / "large").exists())
            self.assertEqual((self.restored / "note1").read_text(), "one")
            self.assertEqual(snapshot(self.archive), before)

    def test_no_parity_recovers_metadata_copy_and_supports_local_group(self):
        (self.source / "note").write_text("one")
        settings = replace(SMALL, compression=False, par2=False)
        with self.optional_tools(False, False, False):
            backup(self.source, self.archive, settings=settings)
            private = next(path for path in self.archive.rglob("*_index-files-spare.jsonl")
                           if "metadata" in path.relative_to(self.archive).parts)
            original = private.read_bytes()
            private.write_bytes(b"broken")
            self.assertEqual(verify(self.archive), 1)
            repair(self.archive)
            self.assertEqual(private.read_bytes(), original)
            self.assertEqual(verify(self.archive), 0)
            shutil.rmtree(self.archive / "metadata")
            self.assertEqual(restore(self.archive, self.restored), 1)
            self.assertEqual(compare(self.source, self.restored), 0)

    def test_uncompressed_parity_repairs_lost_metadata_and_payload(self):
        key, certificate = self.certificate()
        (self.source / "note").write_text("secret content")
        settings = replace(SMALL, compression=False)
        with self.optional_tools(False, True, True):
            backup(self.source, self.archive, certificate, settings)
            next(self.archive.rglob("*.raw.cms")).unlink()
            for path in self.archive.rglob("*_index-files*.jsonl.cms"):
                path.unlink()
            self.assertEqual(verify(self.archive), 1)
            self.assertEqual(restore(self.archive, self.restored, key=key), 0)
            self.assertEqual(compare(self.source, self.restored), 0)
            repair(self.archive)
            self.assertEqual(verify(self.archive), 0)

    def test_cli_toggles_and_plain_empty_archive(self):
        args = parser().parse_args(["backup", "source", "archive"])
        self.assertTrue(args.compression)
        self.assertTrue(args.par2)
        self.assertIsNone(args.encrypt_cert)
        args = parser().parse_args(["backup", "source", "archive", "--compression", "--par2"])
        self.assertTrue(args.compression and args.par2)
        with self.optional_tools(False, False, False):
            self.assertEqual(main(["backup", str(self.source), str(self.archive),
                                   "--no-compression", "--no-par2", "--no-encryption"]), 0)
            self.assertEqual(verify(self.archive), 0)
            self.assertEqual(restore(self.archive, self.restored), 0)
            self.assertEqual(compare(self.source, self.restored), 0)
            manifest = next(self.archive.rglob("*_index-chunks.json"))
            self.assertEqual(json.loads(manifest.read_text())["compression"], "none")
