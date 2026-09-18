import hashlib

from poc.archivator_lib.backup import ParityWriter, backup
from poc.archivator_lib.common import read_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import new_id
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL, read_zstd_json


class ParityGroupTests(ArchiveTest):
    def test_group_boundaries_use_stored_sizes_and_member_limits(self):
        cases = (
            ("short", [1000] * 7, False),
            ("balanced", [1000] * 8, True),
            ("small-tails", [10000] + [1] * 7 + [10000] * 6, True),
            ("capped", [10000] + [1] * 63, True),
        )
        for label, lengths, closes_automatically in cases:
            with self.subTest(label=label):
                archive = self.root / label
                archive.mkdir()
                (archive / ".tmp").mkdir()
                writer = ParityWriter(archive, new_id(), SMALL)
                stream = new_id()
                for index, length in enumerate(lengths):
                    # ParityWriter receives already transformed bytes. The
                    # plaintext length is fixed to catch grouping by input size.
                    data = self.data(length, seed=index)
                    path = writer.staging / "chunk.zst"
                    path.write_bytes(data)
                    hashes = {"sha256": hashlib.sha256(data).hexdigest(),
                              "sha512": hashlib.sha512(data).hexdigest()}
                    writer.add(path, stream, index * SMALL.chunk_size,
                               SMALL.chunk_size, hashes, encrypted=False)
                    expected_sets = int(closes_automatically and index == len(lengths) - 1)
                    self.assertEqual(len(writer.manifests), expected_sets)
                writer.finish_set()
                self.assertEqual(len(writer.manifests), 1)
                manifest = read_json(next(archive.rglob("*_manifest.json")))
                self.assertEqual(manifest["member_count"], len(lengths))
                self.assertEqual([member["stored_length"] for member in manifest["members"]], lengths)

    def test_64_member_set_and_short_tail_repair_and_restore(self):
        # One incompressible chunk followed by many tiny compressed chunks
        # reaches the cap without satisfying the stored-size balance target.
        contents = self.data(SMALL.chunk_size) + bytes(SMALL.chunk_size * 63)
        (self.source / "large").write_bytes(contents)
        backup(self.source, self.archive, settings=SMALL)
        manifests = [read_zstd_json(path) for path in self.archive.rglob("*_manifest.json.zst")]
        self.assertEqual(sorted(manifest["member_count"] for manifest in manifests), [1, 64])
        capped = next(manifest for manifest in manifests if manifest["member_count"] == 64)
        largest = max(capped["members"], key=lambda member: member["stored_length"])
        next(self.archive.rglob(largest["filename"])).unlink()
        self.assertEqual(verify(self.archive), 1)
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
