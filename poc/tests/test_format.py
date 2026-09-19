import unittest
import io
import zipfile

from poc.archivator_lib.common import Hashes, IntegrityError
from poc.archivator_lib.format import Settings, chunk_name, new_id, parse_chunk
from poc.archivator_lib.limits import recovery_blocks


class FormatTests(unittest.TestCase):
    def test_chunk_numbers_can_grow_beyond_four_digits(self):
        archive, parity, stream = new_id(), new_id(), new_id()
        for number in (0, 9999, 10000, 1234567):
            with self.subTest(number=number):
                name = chunk_name(archive, parity, number, stream, 0, 256, False)
                self.assertEqual(parse_chunk(name)["chunk"], number)
        self.assertIn("_chunk-0000_", chunk_name(archive, parity, 0, stream, 0, 256, False))

    def test_independent_filename_contains_recovery_coordinates(self):
        archive, parity, stream = new_id(), new_id(), new_id()
        name = chunk_name(archive, parity, 3, stream, 512, 256, True)
        self.assertEqual(parse_chunk(name), {
            "archive": archive, "parity": parity, "stream": stream,
            "chunk": 3, "offset": 512, "length": 256, "encrypted": True, "kind": "raw",
        })
        with self.assertRaises(IntegrityError):
            parse_chunk("../" + name)

    def test_standard_checksum_vectors(self):
        hashes = Hashes(lookup=True)
        hashes.update(b"1234")
        hashes.update(b"56789")
        self.assertEqual(hashes.values()["crc32"], "cbf43926")
        self.assertEqual(hashes.values()["md5"], "25f9e794323b453885f5181f1b624d0b")
        with zipfile.ZipFile(io.BytesIO(), "w") as archive:
            archive.writestr("sample.txt", b"123456789")
            self.assertEqual(hashes.values()["crc32"], f"{archive.getinfo('sample.txt').CRC:08x}")

    def test_redundancy_accounts_for_short_sets_and_block_rounding(self):
        self.assertEqual(recovery_blocks([1], 1024), 2)
        self.assertEqual(recovery_blocks([3175], 1024), 5)
        self.assertEqual(recovery_blocks([10240] * 8, 1024), 16)
