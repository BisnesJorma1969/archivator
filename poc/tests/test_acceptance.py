import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from poc.archivator_lib.backup import backup
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import executable, run
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json, read_zstd_jsonl
from poc.tests.test_recovery import flip, snapshot


class AcceptanceTests(ArchiveTest):
    def test_thousands_of_small_files_in_multiple_tar_streams(self):
        # Entry count, rather than data size, forces multiple bundles here.
        settings = replace(SMALL, chunk_size=65536, tar_entries=400, tar_size=1024 * 1024,
                           slice_size=4096)
        for index in range(2001):
            (self.source / f"tiny-{index:04d}").write_bytes(f"file {index}\n".encode())
        backup(self.source, self.archive, settings=settings)
        streams = read_zstd_jsonl(next(self.archive.rglob("*_metadata_streams.jsonl.zst")))
        self.assertGreater(len(streams), 1)
        self.assertTrue(all(stream["type"] == "tar" and stream["entry_count"] <= 400 for stream in streams))
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        for original in self.source.iterdir():
            self.assertEqual(original.read_bytes(), (self.restored / original.name).read_bytes())

    def test_combined_data_and_recovery_volume_damage_in_both_modes(self):
        key, certificate = self.certificate()
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                archive = self.root / f"archive-{encrypted}"
                target = self.root / f"restored-{encrypted}"
                (self.source / "large").write_bytes(self.data(160000))
                backup(self.source, archive, certificate if encrypted else None, SMALL)
                manifest = next(read_zstd_json(path) for path in archive.rglob("*_parity-*_manifest.json.zst")
                                if read_zstd_json(path)["member_count"] == 8)
                # Damage one data slice and lose a whole recovery volume. The
                # other three volumes retain more than enough recovery blocks.
                flip(next(archive.rglob(manifest["members"][0]["filename"])))
                volume = next(archive.rglob(f"*_parity-{manifest['parity']}.vol*.par2"))
                volume.unlink()
                before = snapshot(archive)
                self.assertEqual(verify(archive), 1)
                restore(archive, target, key=key if encrypted else None, certificate=certificate if encrypted else None)
                self.assertEqual(snapshot(archive), before)
                self.assertEqual(compare(self.source, target), 0)
                self.assertEqual((self.source / "large").read_bytes(), (target / "large").read_bytes())
                repair(archive)
                self.assertEqual(verify(archive), 0)

    def test_complete_largest_chunk_loss_in_both_modes(self):
        key, certificate = self.certificate()
        (self.source / "large").write_bytes(self.data(80000))
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted):
                archive = self.root / f"archive-{encrypted}"
                target = self.root / f"restored-{encrypted}"
                backup(self.source, archive, certificate if encrypted else None, SMALL)
                chunks = list(archive.rglob("*_chunk-*.enc" if encrypted else "*_chunk-*.zst"))
                max(chunks, key=lambda path: path.stat().st_size).unlink()
                self.assertEqual(verify(archive), 1)
                restore(archive, target, key=key if encrypted else None, certificate=certificate if encrypted else None)
                self.assertEqual(compare(self.source, target), 0)

    def test_mixed_archives_restore_only_selected_source(self):
        (self.source / "first").write_bytes(b"first")
        first_id = backup(self.source, self.archive, settings=SMALL)
        other_source = self.root / "other-source"
        other_source.mkdir()
        (other_source / "second").write_bytes(b"second")
        other_archive = self.root / "other-archive"
        backup(other_source, other_archive, settings=SMALL)
        for path in other_archive.rglob("archive-*"):
            shutil.copyfile(path, self.archive / path.name)
        restore(self.archive, self.restored, archive_id=first_id)
        self.assertEqual(compare(self.source, self.restored), 0)
        self.assertFalse((self.restored / "second").exists())

    def test_archive_filesystem_timestamps_are_irrelevant(self):
        (self.source / "tiny").write_bytes(b"tiny")
        backup(self.source, self.archive, settings=SMALL)
        for path in self.archive.rglob("archive-*"):
            os.utime(path, ns=(0, 0))
        self.assertEqual(verify(self.archive), 0)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_standard_tools_recover_an_encrypted_stream_without_restore_code(self):
        key, certificate = self.certificate()
        original = self.data(80000)
        (self.source / "large").write_bytes(original)
        backup(self.source, self.archive, certificate, SMALL)
        catalog = next(self.archive.rglob("*_metadata_streams.jsonl.zst"))
        streams = [json.loads(line) for line in run([executable("zstd"), "-dc", str(catalog)]).splitlines()]
        stream = next(entry for entry in streams if entry["type"] == "file")
        manual = self.root / "manual"
        manual.mkdir()
        for path in self.archive.rglob("archive-*"):
            shutil.copyfile(path, manual / path.name)
        chunks = list(manual.glob(f"*_stream-{stream['stream']}_*.enc"))
        missing = chunks[0]
        missing.unlink()
        prefix = missing.name.split("_chunk-", 1)[0]
        run([executable("par2"), "repair", "-q", "-t1", "-T1", prefix + ".par2"], cwd=manual)
        reconstructed = manual / "reconstructed"
        for chunk in chunks:
            compressed = manual / "chunk.zst"
            plaintext = manual / "chunk.plain"
            run([executable("openssl"), "cms", "-decrypt", "-binary", "-inform", "DER",
                 "-in", str(chunk), "-out", str(compressed), "-inkey", str(key), "-recip", str(certificate)])
            with plaintext.open("wb") as output:
                subprocess.run([executable("zstd"), "-dc", str(compressed)], stdout=output, check=True)
            offset = int(re.search(r"_offset-([0-9]+)_", chunk.name)[1])
            run(["dd", f"if={plaintext}", f"of={reconstructed}", "bs=1024", "oflag=seek_bytes",
                 f"seek={offset}", "conv=notrunc", "status=none"])
        self.assertEqual(run(["sha256sum", str(reconstructed)]).split()[0], stream["sha256"])
        self.assertEqual(reconstructed.read_bytes(), original)

    def test_actual_cli_backup_verify_restore_compare_and_repair(self):
        launcher = str(Path(__file__).resolve().parents[1] / "archivator")

        def command(*arguments):
            return subprocess.run([sys.executable, launcher, *map(str, arguments)], capture_output=True, text=True)

        (self.source / "hello").write_text("CLI acceptance\n")
        result = command("backup", self.source, self.archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(command("verify", self.archive).returncode, 0)
        next(self.archive.rglob("*_chunk-*.zst")).unlink()
        self.assertEqual(command("verify", self.archive).returncode, 1)
        result = command("restore", self.archive, self.restored)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(command("compare", self.source, self.restored).returncode, 0)
        result = command("repair", self.archive)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(command("verify", self.archive).returncode, 0)
        self.assertEqual(command("restore", self.archive, self.restored).returncode, 2)
        (self.restored / "hello").write_text("changed\n")
        self.assertEqual(command("compare", self.source, self.restored).returncode, 1)
