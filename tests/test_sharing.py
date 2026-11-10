"""Behavioral checks for optional single-entry asymmetric sharing."""

import base64
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sharing import (
    MAX_PACKAGE_BYTES, SharingError, decrypt_entry, encrypt_entry, generate_keypair,
)


class SharingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key_folder = tempfile.TemporaryDirectory()
        cls.root = Path(cls.key_folder.name)
        cls.passphrase = b"separate sharing key passphrase"
        cls.private = cls.root / "recipient-private.pem"
        cls.public = cls.root / "recipient-public.pem"
        generate_keypair(cls.private, cls.public, cls.passphrase)
        cls.other_private = cls.root / "other-private.pem"
        cls.other_public = cls.root / "other-public.pem"
        generate_keypair(cls.other_private, cls.other_public, cls.passphrase)

    @classmethod
    def tearDownClass(cls):
        cls.key_folder.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.directory = Path(self.folder.name)
        self.package = self.directory / "shared-entry.json"
        self.entry = {
            "site": "example.test/\u5b66\u4e60", "username": "alice@example.test",
            "password": "screenshot-demo-only-!42",
        }

    def tearDown(self):
        self.folder.cleanup()

    def make_share(self):
        encrypt_entry(self.entry, self.public, self.package)

    def change_package(self, mutation):
        data = json.loads(self.package.read_text(encoding="ascii"))
        mutation(data)
        self.package.write_text(json.dumps(data), encoding="ascii")

    def test_single_entry_round_trip_and_ciphertext_only(self):
        self.make_share()
        self.assertEqual(decrypt_entry(self.package, self.private, self.passphrase), self.entry)
        raw = self.package.read_bytes()
        self.assertNotIn(self.entry["password"].encode(), raw)
        self.assertNotIn(self.entry["username"].encode(), raw)

    def test_private_key_is_encrypted_and_uses_3072_bits(self):
        encoded = self.private.read_bytes()
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", encoded)
        with self.assertRaises(TypeError):
            serialization.load_pem_private_key(encoded, password=None)
        key = serialization.load_pem_private_key(encoded, password=self.passphrase)
        self.assertEqual(key.key_size, 3072)

    def test_wrong_recipient_cannot_decrypt(self):
        self.make_share()
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.other_private, self.passphrase)

    def test_wrong_private_key_passphrase_cannot_decrypt(self):
        self.make_share()
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, b"wrong long passphrase")

    def test_ciphertext_byte_flip_is_rejected(self):
        self.make_share()
        def flip(data):
            ciphertext = bytearray(base64.b64decode(data["ciphertext"]))
            ciphertext[0] ^= 1
            data["ciphertext"] = base64.b64encode(ciphertext).decode()
        self.change_package(flip)
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_nonce_byte_flip_is_rejected(self):
        self.make_share()
        def flip(data):
            nonce = bytearray(base64.b64decode(data["nonce"]))
            nonce[-1] ^= 1
            data["nonce"] = base64.b64encode(nonce).decode()
        self.change_package(flip)
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_wrapped_key_byte_flip_is_rejected(self):
        self.make_share()
        def flip(data):
            wrapped = bytearray(base64.b64decode(data["wrapped_key"]))
            wrapped[-1] ^= 1
            data["wrapped_key"] = base64.b64encode(wrapped).decode()
        self.change_package(flip)
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_header_version_change_is_rejected(self):
        self.make_share()
        self.change_package(lambda data: data.update(version=2))
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_duplicate_json_fields_are_rejected(self):
        self.make_share()
        raw = self.package.read_text(encoding="ascii")
        self.package.write_text('{"version": 1,' + raw[1:], encoding="ascii")
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_unknown_field_is_rejected(self):
        self.make_share()
        self.change_package(lambda data: data.update(extra="not part of the format"))
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_oversized_package_is_rejected(self):
        self.package.write_bytes(b" " * (MAX_PACKAGE_BYTES + 1))
        with self.assertRaises(SharingError):
            decrypt_entry(self.package, self.private, self.passphrase)

    def test_existing_output_is_not_overwritten(self):
        self.make_share()
        before = self.package.read_bytes()
        with self.assertRaises(SharingError):
            encrypt_entry(self.entry, self.public, self.package)
        self.assertEqual(self.package.read_bytes(), before)

    def test_existing_key_is_not_overwritten(self):
        before = self.private.read_bytes()
        new_public = self.directory / "new-public.pem"
        with self.assertRaises(SharingError):
            generate_keypair(self.private, new_public, self.passphrase)
        self.assertEqual(self.private.read_bytes(), before)
        self.assertFalse(new_public.exists())

    def test_same_key_output_paths_are_rejected(self):
        path = self.directory / "both.pem"
        with self.assertRaises(SharingError):
            generate_keypair(path, path, self.passphrase)
        self.assertFalse(path.exists())

    def test_weak_rsa_public_key_is_rejected(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path = self.directory / "weak-public.pem"
        path.write_bytes(weak.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with self.assertRaises(SharingError):
            encrypt_entry(self.entry, path, self.package)
        self.assertFalse(self.package.exists())

    def test_only_one_well_formed_entry_can_be_shared(self):
        with self.assertRaises(SharingError):
            encrypt_entry({**self.entry, "notes": "not in this format"}, self.public, self.package)
        with self.assertRaises(SharingError):
            encrypt_entry({**self.entry, "password": ""}, self.public, self.package)
        self.assertFalse(self.package.exists())

    def test_short_sharing_key_passphrase_is_rejected(self):
        with self.assertRaises(SharingError):
            generate_keypair(self.directory / "a.pem", self.directory / "b.pem", b"short")

    def test_overlong_sharing_key_passphrase_is_rejected(self):
        with self.assertRaises(SharingError):
            generate_keypair(self.directory / "a.pem", self.directory / "b.pem", b"x" * 1024)


if __name__ == "__main__":
    unittest.main()
