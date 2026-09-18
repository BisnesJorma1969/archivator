from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import read_json
from poc.archivator_lib.compare import compare
from poc.archivator_lib.format import parse_chunk
from poc.archivator_lib.recovery import repair, verify
from poc.archivator_lib.restore import restore
from poc.tests.support import ArchiveTest, SMALL


class ShardingTests(ArchiveTest):
    def test_output_uses_only_populated_parity_prefix_directories(self):
        (self.source / "large").write_bytes(self.data(160000))
        backup(self.source, self.archive, settings=SMALL)
        marker = next(self.archive.rglob("*_complete.json"))
        metadata_id = read_json(marker)["metadata_prefix"].split("_parity-")[1]
        expected_shards = {metadata_id[:2]}
        for path in self.archive.rglob("archive-*"):
            if "_metadata_" in path.name:
                self.assertEqual(path.parent.name, metadata_id[:2])
            elif "_chunk-" in path.name:
                parity_id = parse_chunk(path.name)["parity"]
                expected_shards.add(parity_id[:2])
                self.assertEqual(path.parent.name, parity_id[:2])
            else:
                self.assertEqual(path.parent.name, path.name.split("_parity-")[1][:2])
        self.assertEqual({path.name for path in self.archive.iterdir()}, expected_shards)
        self.assertTrue(all(path.is_dir() and any(path.iterdir()) for path in self.archive.iterdir()))
        self.assertFalse(list(self.archive.rglob(".tmp")))

    def test_data_and_metadata_sets_can_share_one_shard(self):
        (self.source / "large").write_bytes(self.data(160000))
        ids = (f"ab{number:030x}" for number in range(100))
        with patch("poc.archivator_lib.format.secrets.token_hex", side_effect=lambda size: next(ids)):
            backup(self.source, self.archive, settings=SMALL)
        self.assertEqual([path.name for path in self.archive.iterdir()], ["ab"])
        next(self.archive.rglob("*_metadata_streams.jsonl.zst")).unlink()
        next(self.archive.rglob("*_chunk-*.zst")).unlink()
        restore(self.archive, self.restored)
        self.assertEqual(compare(self.source, self.restored), 0)
        repair(self.archive)
        self.assertEqual(verify(self.archive), 0)
        self.assertEqual([path.name for path in self.archive.iterdir()], ["ab"])
