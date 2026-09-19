import unittest
import io
import zipfile

from poc.archivator_lib.common import Hashes, IntegrityError
from poc.archivator_lib.format import Settings, chunk_name, new_id, parse_chunk, stored_path
from poc.archivator_lib.limits import recovery_blocks


class FormatTests(unittest.TestCase):
    def test_ids_and_full_paths_fit_portable_volume_root_limits(self):
        self.assertEqual(len(new_id()), 20)
        name = chunk_name("a" * 20, "b" * 20, 32767, "c" * 20,
                          2**64 - 1, 4294967295, True, supergroup="d" * 20)
        relative = stored_path(".", name).as_posix()
        self.assertTrue(relative.isascii())
        self.assertLessEqual(len(name), 255)
        self.assertLessEqual(len(relative), 256)
        self.assertLessEqual(len("X:\\") + len(relative) + 1, 260)
    def test_chunk_numbers_can_grow_beyond_four_digits(self):
        archive, datagroup, stream = new_id(), new_id(), new_id()
        for number in (0, 9999, 10000, 1234567):
            with self.subTest(number=number):
                name = chunk_name(archive, datagroup, number, stream, 0, 256, False, supergroup="d" * 20)
                self.assertEqual(parse_chunk(name)["chunk"], number)
        self.assertIn("_chunk-0000_", chunk_name(archive, datagroup, 0, stream, 0, 256, False, supergroup="d" * 20))

    def test_independent_filename_contains_recovery_coordinates(self):
        archive, datagroup, stream = new_id(), new_id(), new_id()
        name = chunk_name(archive, datagroup, 3, stream, 512, 256, True, supergroup="d" * 20)
        self.assertEqual(parse_chunk(name), {
            "archive": archive, "supergroup": "d" * 20, "datagroup": datagroup, "stream": stream,
            "chunk": 3, "offset": 512, "length": 256, "encrypted": True, "kind": "raw", "compressed": True,
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
        self.assertEqual(recovery_blocks({"file": 1}, 4096), 2)
        self.assertEqual(recovery_blocks({"file": 12700}, 4096), 5)
        self.assertEqual(recovery_blocks({str(n): 40960 for n in range(8)}, 4096), 16)
