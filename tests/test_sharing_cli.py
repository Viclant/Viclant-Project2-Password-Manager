"""Sharing command integration with real crypto and disposable demo credentials."""

import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import vault as cli
import vault_core as core
from sharing import encrypt_entry, generate_keypair


MASTER = "CLI-only demonstration master 2026!"
KEY_PASSPHRASE = "Separate CLI sharing passphrase 2026!"
ENTRY = {
    "site": "sharing.example/学习",
    "username": "demo-alice",
    "password": "Demo-only-selected-entry!42",
}
OTHER_PASSWORD = "Demo-only-unshared-entry!84"


class SharingCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixtures.cleanup)
        directory = Path(cls.fixtures.name)
        cls.private = directory / "recipient-private.pem"
        cls.public = directory / "recipient-public.pem"
        cls.other_private = directory / "other-private.pem"
        generate_keypair(cls.private, cls.public, KEY_PASSPHRASE.encode())
        generate_keypair(
            cls.other_private, directory / "other-public.pem", KEY_PASSPHRASE.encode()
        )
        source = directory / "source.vault.json"
        core.initialize(source, MASTER)
        with core.open_vault(source, MASTER) as vault:
            vault.add(ENTRY["site"], ENTRY["username"], ENTRY["password"])
            vault.add("unshared.example", "demo-bob", OTHER_PASSWORD)
            vault.save()
        cls.source_bytes = source.read_bytes()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.vault = self.root / "source.vault.json"
        self.vault.write_bytes(self.source_bytes)
        self.package = self.root / "entry.share.json"
        self.missing_vault = self.root / "does-not-exist.vault.json"

    def run_cli(self, arguments, secrets=(), vault_path=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("vault.ask_secret", side_effect=secrets) as prompt:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = cli.main([
                    "--vault", str(vault_path or self.vault), *map(str, arguments)
                ])
        self.assertEqual(prompt.call_count, len(secrets))
        return result, stdout.getvalue(), stderr.getvalue(), [
            call.args[0] for call in prompt.call_args_list
        ]

    def share(self, site=None, master=MASTER):
        return self.run_cli([
            "share", site or ENTRY["site"], "--recipient", self.public,
            "--out", self.package,
        ], [master])

    def receive(self, private=None, passphrase=KEY_PASSPHRASE):
        return self.run_cli([
            "open-share", self.package, "--private", private or self.private,
        ], [passphrase], vault_path=self.missing_vault)

    def assert_safe_failure(self, result):
        status, stdout, stderr, _ = result
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Error: "))
        for secret in (MASTER, KEY_PASSPHRASE, ENTRY["password"], OTHER_PASSWORD):
            self.assertNotIn(secret, stderr)

    def test_keygen_share_open_share_round_trip_preserves_source_and_one_entry(self):
        private, public = self.root / "new-private.pem", self.root / "new-public.pem"
        status, stdout, stderr, prompts = self.run_cli([
            "keygen", "--private", private, "--public", public,
        ], [KEY_PASSPHRASE, KEY_PASSPHRASE], vault_path=self.missing_vault)
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Created sharing keys", stdout)
        self.assertIn("sharing-key passphrase", prompts[0])
        self.assertEqual(prompts[1], "Confirm: ")
        self.assertIn(b"ENCRYPTED PRIVATE KEY", private.read_bytes())
        self.assertFalse(self.missing_vault.exists())

        status, stdout, stderr, prompts = self.run_cli([
            "share", ENTRY["site"], "--recipient", public, "--out", self.package,
        ], [MASTER])
        self.assertEqual((status, stderr), (0, ""))
        self.assertIn("Encrypted one entry", stdout)
        self.assertEqual(prompts, ["Master passphrase: "])
        self.assertEqual(self.vault.read_bytes(), self.source_bytes)
        self.assertFalse(self.vault.with_name(self.vault.name + ".lock").exists())
        for secret in (MASTER, ENTRY["password"], OTHER_PASSWORD):
            self.assertNotIn(secret.encode(), self.package.read_bytes())

        status, stdout, stderr, prompts = self.receive(private=private)
        self.assertEqual((status, stderr), (0, ""))
        self.assertEqual(json.loads(stdout), ENTRY)
        self.assertNotIn(OTHER_PASSWORD, stdout)
        self.assertEqual(prompts, ["Sharing-key passphrase: "])
        self.assertFalse(self.missing_vault.exists())

    def test_open_share_reports_wrong_passphrase_and_recipient_without_plaintext(self):
        encrypt_entry(ENTRY, self.public, self.package)
        for private, passphrase in (
            (self.private, "Wrong separate sharing passphrase!"),
            (self.other_private, KEY_PASSPHRASE),
        ):
            with self.subTest(private=private.name, passphrase_correct=passphrase == KEY_PASSPHRASE):
                self.assert_safe_failure(self.receive(private, passphrase))
        self.assertFalse(self.missing_vault.exists())

    def test_open_share_reports_tampering_without_returning_plaintext(self):
        encrypt_entry(ENTRY, self.public, self.package)
        document = json.loads(self.package.read_text())
        ciphertext = bytearray(base64.b64decode(document["ciphertext"]))
        ciphertext[-1] ^= 1
        document["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        self.package.write_text(json.dumps(document), encoding="ascii")
        self.assert_safe_failure(self.receive())

    def test_share_rejects_wrong_master_and_missing_site_without_writing_output(self):
        for site, master in (
            (ENTRY["site"], "Wrong CLI demonstration master!"),
            ("missing.example", MASTER),
        ):
            with self.subTest(site=site):
                self.assert_safe_failure(self.share(site, master))
                self.assertFalse(self.package.exists())
                self.assertEqual(self.vault.read_bytes(), self.source_bytes)

    def test_existing_share_and_key_outputs_are_not_overwritten_by_cli(self):
        self.package.write_bytes(b"existing output must survive")
        self.assert_safe_failure(self.share())
        self.assertEqual(self.package.read_bytes(), b"existing output must survive")

        private = self.root / "existing-private.pem"
        public = self.root / "not-created-public.pem"
        private.write_bytes(b"existing private file must survive")
        result = self.run_cli([
            "keygen", "--private", private, "--public", public,
        ], [KEY_PASSPHRASE, KEY_PASSPHRASE], vault_path=self.missing_vault)
        self.assert_safe_failure(result)
        self.assertEqual(private.read_bytes(), b"existing private file must survive")
        self.assertFalse(public.exists())

    def test_keygen_requires_confirmed_long_passphrase_before_creating_files(self):
        private, public = self.root / "private.pem", self.root / "public.pem"
        for passphrases in (
            [KEY_PASSPHRASE, "Different confirmed passphrase!"],
            ["short", "short"],
        ):
            with self.subTest(short=len(passphrases[0]) < 12):
                result = self.run_cli([
                    "keygen", "--private", private, "--public", public,
                ], passphrases, vault_path=self.missing_vault)
                self.assert_safe_failure(result)
                self.assertFalse(private.exists())
                self.assertFalse(public.exists())

    def test_share_respects_existing_gui_vault_lock(self):
        with core.vault_lock(self.vault):
            self.assert_safe_failure(self.share())
            self.assertFalse(self.package.exists())
            self.assertEqual(self.vault.read_bytes(), self.source_bytes)
        self.assertFalse(self.vault.with_name(self.vault.name + ".lock").exists())


if __name__ == "__main__":
    unittest.main()
