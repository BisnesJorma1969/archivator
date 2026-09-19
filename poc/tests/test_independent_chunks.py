import io
import subprocess
import tarfile
from dataclasses import replace

from poc.archivator_lib.backup import backup
from poc.archivator_lib.cli import parser
from poc.archivator_lib.common import ArchiveError, IntegrityError
from poc.archivator_lib.compare import compare
from poc.archivator_lib.external import decrypt, executable
from poc.archivator_lib.format import Settings, chunk_name, parse_chunk
from poc.archivator_lib.limits import input_limit
from poc.archivator_lib.restore import restore
from poc.archivator_lib.scan import scan
from poc.tests.support import ArchiveTest, SMALL, catalog, manifests
from poc.tests.test_recovery import snapshot


class IndependentChunkTests(ArchiveTest):
    def test_names_distinguish_complete_tar_from_raw_and_reject_wrong_offsets(self):
        for encrypted in (False, True):
            for kind in ("raw", "tar"):
                name = chunk_name("a" * 32, "b" * 32, 12, "c" * 32, 0, 10240, encrypted, kind)
                parsed = parse_chunk(name)
                self.assertEqual(parsed["kind"], kind)
                self.assertEqual(parsed["length"], 10240)
                self.assertEqual(parsed["offset"], 0)
                self.assertEqual("_offset-" in name, kind == "raw")
                self.assertTrue(name.endswith(f".{kind}.zst" + (".cms" if encrypted else "")))
                wrong = name.replace(".raw.zst", ".tar.zst") if kind == "raw" else name.replace(".tar.zst", ".raw.zst")
                with self.assertRaises(IntegrityError):
                    parse_chunk(wrong)

    def test_each_tar_is_independently_readable_and_compressed_units_share_group(self):
        for number in range(24):
            (self.source / f"document-{number:02}").write_bytes(bytes([number]) * 20000)
        backup(self.source, self.archive, settings=SMALL)
        groups = [group for group in manifests(self.archive) if group["members"]]
        self.assertEqual(len(groups), 1)
        chunks = list(self.archive.rglob("*.tar.zst"))
        self.assertGreaterEqual(len(chunks), 8)
        self.assertGreater(sum(parse_chunk(path.name)["length"] for path in chunks), SMALL.max_group_bytes)
        found = set()
        for chunk in chunks:
            data = subprocess.run([executable("zstd"), "-qdc", str(chunk)],
                                  capture_output=True, check=True).stdout
            self.assertEqual(len(data), parse_chunk(chunk.name)["length"])
            # GNU tar can list each decoded object without any concatenation.
            subprocess.run(["tar", "-tf", "-"], input=data, capture_output=True, check=True)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as bundle:
                files = [member for member in bundle if member.isfile()]
                self.assertGreaterEqual(len(files), 2)
                for member in files:
                    self.assertNotIn(member.name, found)
                    found.add(member.name)
                    self.assertEqual(bundle.extractfile(member).read(), (self.source / member.name).read_bytes())
        self.assertEqual(found, {path.name for path in self.source.iterdir()})
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_encrypted_tar_overhead_and_pax_names_fit_file_and_group_limits(self):
        key, certificate = self.certificate()
        for number in range(12):
            (self.source / (f"{number:02}-" + "é" * 80)).write_bytes(self.data(27000, number))
        backup(self.source, self.archive, certificate, SMALL)
        chunks = list(self.archive.rglob("*.tar.zst.cms"))
        self.assertTrue(chunks)
        compressed = self.root / "decoded.zst"
        for chunk in chunks:
            decrypt(chunk, compressed, key, certificate)
            data = subprocess.run([executable("zstd"), "-qdc", str(compressed)],
                                  capture_output=True, check=True).stdout
            self.assertEqual(len(data), parse_chunk(chunk.name)["length"])
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as bundle:
                self.assertEqual(len([member for member in bundle if member.isfile()]), 2)
            compressed.unlink()
        for path in self.archive.rglob("archive-*"):
            self.assertLessEqual(path.stat().st_size, SMALL.max_file_bytes)
        for group in manifests(self.archive):
            prefix = f"archive-{group['archive']}_parity-{group['parity']}"
            size = sum(path.stat().st_size for path in (self.archive / group["parity"][:2]).glob(prefix + "*"))
            self.assertLessEqual(size, SMALL.max_group_bytes)
        self.assertEqual(restore(self.archive, self.restored, key=key), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_lower_largefile_threshold_does_not_reduce_raw_chunk_size(self):
        for name in ("one", "two"):
            (self.source / name).write_bytes(self.data(8000))
        (self.source / "split").write_bytes(self.data(200000))
        settings = replace(SMALL, large_file_bytes=4096)
        backup(self.source, self.archive, settings=settings)
        self.assertTrue(all(stream["type"] == "file" for stream in catalog(self.archive)))
        split = next(stream for stream in catalog(self.archive) if stream["path"] == "split")
        chunks = [parse_chunk(path.name) for path in self.archive.rglob("*.raw.zst")
                  if parse_chunk(path.name)["stream"] == split["stream"]]
        self.assertEqual(max(chunk["length"] for chunk in chunks), input_limit(SMALL.max_file_bytes))
        small_ids = {stream["stream"] for stream in catalog(self.archive) if stream["path"] in ("one", "two")}
        whole = next(group for group in manifests(self.archive)
                     if small_ids <= {member["stream"] for member in group["members"]})
        self.assertEqual(len([member for member in whole["members"] if member["stream"] in small_ids]), 2)
        args = parser().parse_args(["backup", "source", "archive", "--large-file-bytes", "4096"])
        self.assertEqual(args.large_file_bytes, 4096)
        with self.assertRaises(ArchiveError):
            Settings(large_file_bytes=0)

    def test_singleton_shares_group_with_tar_but_is_stored_as_raw(self):
        for number in range(3):
            (self.source / str(number)).write_bytes(self.data(20000, number))
        backup(self.source, self.archive, settings=SMALL)
        groups = [group for group in manifests(self.archive) if group["members"]]
        self.assertEqual(len(groups), 1)
        self.assertEqual({member["kind"] for member in groups[0]["members"]}, {"raw", "tar"})
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_tar_overhead_prevents_pairing_even_when_raw_file_sizes_would_fit(self):
        size = input_limit(SMALL.max_file_bytes) // 2 - 1
        for name in ("one", "two"):
            (self.source / name).write_bytes(self.data(size))
        self.assertLess(2 * size, input_limit(SMALL.max_file_bytes))
        # An oversized routing threshold must not bypass the TAR size check.
        backup(self.source, self.archive, settings=replace(SMALL, large_file_bytes=10 * SMALL.max_file_bytes))
        self.assertFalse(list(self.archive.rglob("*.tar.zst")))
        self.assertEqual(len(list(self.archive.rglob("*.raw.zst"))), 2)
        self.assertEqual(restore(self.archive, self.restored), 0)
        self.assertEqual(compare(self.source, self.restored), 0)

    def test_unrecoverable_tar_does_not_prevent_restoring_healthy_siblings(self):
        for number in range(8):
            (self.source / str(number)).write_bytes(self.data(20000, number))
        backup(self.source, self.archive, settings=SMALL)
        missing = next(self.archive.rglob("*.tar.zst"))
        lost_id = parse_chunk(missing.name)["stream"]
        lost = next(stream for stream in catalog(self.archive) if stream["stream"] == lost_id)
        lost_paths = {entry["path"] for entry in lost["inventory"] if entry["type"] == "file"}
        prefix = missing.name.split("_chunk-", 1)[0]
        for path in missing.parent.glob(prefix + "*.par2"):
            path.unlink()
        missing.unlink()
        before = snapshot(self.archive)
        self.assertEqual(restore(self.archive, self.restored), 1)
        for path in self.source.iterdir():
            if path.name in lost_paths:
                self.assertFalse((self.restored / path.name).exists())
            else:
                self.assertEqual((self.restored / path.name).read_bytes(), path.read_bytes())
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        scanned = self.root / "scanned"
        restore(self.archive, scanned, scan_index=index)
        self.assertFalse(list(scanned.glob(f"stream-{lost_id}*")))
        self.assertTrue(list(scanned.glob("*.tar")))
        self.assertEqual(snapshot(self.archive), before)

    def test_filename_only_restore_never_unpacks_raw_source_that_is_itself_tar(self):
        contents = io.BytesIO()
        with tarfile.open(fileobj=contents, mode="w") as bundle:
            member = tarfile.TarInfo("original-document")
            member.size = 5
            bundle.addfile(member, io.BytesIO(b"hello"))
        (self.source / "original.tar").write_bytes(contents.getvalue())
        backup(self.source, self.archive, settings=SMALL)
        index = self.root / "scan.json.zst"
        scan(self.archive, index)
        self.assertEqual(restore(self.archive, self.restored, scan_index=index), 0)
        outputs = list(self.restored.iterdir())
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0].suffix, ".raw")
        self.assertEqual(outputs[0].read_bytes(), contents.getvalue())
