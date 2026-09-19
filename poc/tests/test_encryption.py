import os
import re
import stat
from unittest.mock import patch

from poc.archivator_lib.backup import backup
from poc.archivator_lib.common import ArchiveError, IntegrityError
from poc.archivator_lib.external import decrypt, encrypt, executable, run
from poc.tests.support import ArchiveTest, SMALL


class EncryptionTests(ArchiveTest):
    def test_backup_rejects_weak_or_non_encryption_recipient_keys(self):
        (self.source / "private.txt").write_bytes(b"private content")
        for number, algorithm in enumerate(("rsa:2048", "ed25519", "rsa-pss:3072")):
            with self.subTest(algorithm=algorithm):
                _, certificate = self.certificate(str(number), algorithm)
                archive = self.root / f"archive-{number}"
                with patch("poc.archivator_lib.backup.ZstdWriter",
                           side_effect=AssertionError("Do not pack data with a rejected key")):
                    with self.assertRaisesRegex(ArchiveError, "3072"):
                        backup(self.source, archive, certificate, SMALL)
                self.assertEqual(list(archive.iterdir()), [])

    def test_plaintext_permissions_are_private_even_with_permissive_umask(self):
        key, certificate = self.certificate()
        (self.source / "private.txt").write_bytes(b"private content")
        encrypted_chunks = []

        def check_and_encrypt(source, target, recipient):
            self.assertEqual(stat.S_IMODE(source.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            encrypt(source, target, recipient)
            encrypted_chunks.append(target.name)

        previous_umask = os.umask(0)
        try:
            with patch("poc.archivator_lib.backup.encrypt", side_effect=check_and_encrypt):
                backup(self.source, self.archive, certificate, SMALL)
            self.assertTrue(encrypted_chunks)
            chunk = next(self.archive.rglob("*.zst.cms"))
            decoded = self.root / "decoded.zst"
            for reuse_output in (False, True):
                with self.subTest(reuse_output=reuse_output):
                    if reuse_output:
                        decoded.chmod(0o666)
                    decrypt(chunk, decoded, key, certificate)
                    self.assertEqual(stat.S_IMODE(decoded.stat().st_mode), 0o600)
        finally:
            os.umask(previous_umask)

    def test_cms_uses_oaep_sha256_mgf1_sha256_and_aes256_gcm(self):
        key, certificate = self.certificate()
        plaintext = self.root / "plaintext"
        plaintext.write_bytes(b"independent chunk" * 100)
        encrypted = self.root / "chunk.zst.cms"
        encrypt(plaintext, encrypted, certificate)
        structure = run([executable("openssl"), "asn1parse", "-inform", "DER",
                         "-in", str(encrypted)])
        algorithms = re.findall(r"OBJECT\s+:([^\n]+)", structure)
        self.assertIn("id-smime-ct-authEnvelopedData", algorithms)
        start = algorithms.index("rsaesOaep")
        self.assertEqual(algorithms[start:start + 4], ["rsaesOaep", "sha256", "mgf1", "sha256"])
        self.assertIn("aes-256-gcm", algorithms)
        decoded = self.root / "decoded"
        decrypt(encrypted, decoded, key, certificate)
        self.assertEqual(decoded.read_bytes(), plaintext.read_bytes())

    def test_bad_gcm_tag_rejects_and_removes_unauthenticated_plaintext(self):
        key, certificate = self.certificate()
        plaintext = self.root / "plaintext"
        plaintext.write_bytes(b"private chunk" * 100)
        encrypted = self.root / "chunk.zst.cms"
        encrypt(plaintext, encrypted, certificate)
        structure = run([executable("openssl"), "asn1parse", "-inform", "DER",
                         "-in", str(encrypted)])
        # The AuthEnvelopedData MAC is a top-level 16-byte OCTET STRING.
        tag = re.search(r"^\s*(\d+):d=3\s+hl=(\d+)\s+l=\s*16\s+prim: OCTET STRING",
                        structure, re.MULTILINE)
        self.assertIsNotNone(tag)
        tag_offset = int(tag[1]) + int(tag[2])
        damaged = bytearray(encrypted.read_bytes())
        damaged[tag_offset] ^= 1
        encrypted.write_bytes(damaged)
        decoded = self.root / "decoded"
        with self.assertRaises(IntegrityError):
            decrypt(encrypted, decoded, key, certificate)
        self.assertFalse(decoded.exists())
