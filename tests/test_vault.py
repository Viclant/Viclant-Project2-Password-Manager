"""Security and CLI checks using temporary vaults and real cryptographic calls.

All passwords below are fixed test fixtures, never a user's real credentials.
"""

import base64
from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import string
import tempfile
import unittest
from unittest import mock

import vault_core as core
import vault as cli


MASTER = "Demo-only master passphrase 2026!"
WRONG = "Wrong-demo-only passphrase 2026!"
SITE = "demo-private-site-unique.example"
USER = "demo-private-user-unique"
ENTRY_PASSWORD = "Demo-only-entry-secret-unique!42"


class VaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.path = self.root / "vault.json"
        core.initialize(self.path, MASTER)

    def tearDown(self):
        self.folder.cleanup()

    def document(self):
        return json.loads(self.path.read_bytes())

    def write_document(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")

    def add_fixture(self):
        with core.open_vault(self.path, MASTER) as vault:
            vault.add(SITE, USER, ENTRY_PASSWORD)
            vault.save()

    def assert_clean_directory(self):
        self.assertEqual({p.name for p in self.root.iterdir()}, {"vault.json"})

    def test_real_crypto_crud_and_unicode_survive_reopening(self):
        site = "例子.example/🔐"
        username = "用户-é"
        password = "测试用密码-🔑-é-42!"
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})
            vault.add(site, username, password)
            vault.save()
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.get(site), {
                "site": site, "username": username, "password": password,
            })
            vault.delete(site)
            vault.save()
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})
            with self.assertRaises(core.VaultError):
                vault.get(site)
        self.assert_clean_directory()

    def test_wrong_master_rejected_without_changing_file(self):
        self.add_fixture()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(core.VaultError, "Wrong master"):
            with core.open_vault(self.path, WRONG):
                self.fail("Wrong password must never yield an unlocked vault")
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_clean_directory()

    def test_key_derivation_is_deterministic_and_bound_to_password_and_salt(self):
        salt = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        changed_salt = bytes.fromhex("000102030405060708090a0b0c0d0e0e")
        key = core.derive_key(MASTER, salt)
        repeated_key = core.derive_key(MASTER, salt)
        changed_password_key = core.derive_key(WRONG, salt)
        changed_salt_key = core.derive_key(MASTER, changed_salt)

        for derived_key in (key, repeated_key, changed_password_key, changed_salt_key):
            self.assertIsInstance(derived_key, bytes)
            self.assertEqual(len(derived_key), 32)
        self.assertEqual(key, repeated_key)
        self.assertNotEqual(key, changed_password_key)
        self.assertNotEqual(key, changed_salt_key)

    def test_verifier_and_ciphertext_present_but_no_plaintext_or_key_file(self):
        self.add_fixture()
        raw = self.path.read_bytes()
        for secret in (MASTER, SITE, USER, ENTRY_PASSWORD):
            self.assertNotIn(secret.encode("utf-8"), raw)
        document = self.document()
        self.assertEqual(set(document), {"header", "nonce", "ciphertext"})
        verifier = document["header"]["password_hash"]
        self.assertTrue(verifier.startswith("$argon2id$"))
        verifier_salt = base64.b64decode(verifier.split("$")[-2] + "==")
        derivation_salt = core.unb64(document["header"]["kdf"]["salt"])
        self.assertEqual(len(verifier_salt), 16)
        self.assertEqual(len(derivation_salt), 16)
        self.assertNotEqual(verifier_salt, derivation_salt)
        self.assert_clean_directory()

    def test_ciphertext_tag_nonce_and_valid_kdf_salt_tampering_fail(self):
        self.add_fixture()
        original = self.document()
        for part in ("ciphertext", "tag", "nonce", "kdf_salt"):
            with self.subTest(part=part):
                damaged = copy.deepcopy(original)
                if part == "kdf_salt":
                    raw = bytearray(core.unb64(damaged["header"]["kdf"]["salt"]))
                    raw[0] ^= 1
                    damaged["header"]["kdf"]["salt"] = core.b64(bytes(raw))
                else:
                    field = "ciphertext" if part in ("ciphertext", "tag") else "nonce"
                    raw = bytearray(core.unb64(damaged[field]))
                    raw[-1 if part == "tag" else 0] ^= 1
                    damaged[field] = core.b64(bytes(raw))
                self.write_document(damaged)
                damaged_bytes = self.path.read_bytes()
                with self.assertRaisesRegex(core.VaultError, "authentication failed"):
                    with core.open_vault(self.path, MASTER):
                        self.fail("Authenticated corruption must not return entries")
                self.assertEqual(self.path.read_bytes(), damaged_bytes)
                self.assert_clean_directory()

    def test_valid_same_password_rehashed_verifier_is_authenticated_metadata(self):
        document = self.document()
        document["header"]["password_hash"] = core.PH.hash(MASTER)
        self.write_document(document)
        with self.assertRaisesRegex(core.VaultError, "authentication failed"):
            with core.open_vault(self.path, MASTER):
                self.fail("Changing a valid verifier must break authenticated metadata")

    def test_exactly_one_raw_file_byte_changed_fails_authentication(self):
        self.add_fixture()
        original = self.path.read_bytes()
        prefix = b'"ciphertext":"'
        index = original.index(prefix) + len(prefix)
        damaged = bytearray(original)
        damaged[index] = ord("B") if original[index] == ord("A") else ord("A")
        self.assertEqual(len(damaged), len(original))
        self.assertEqual(sum(a != b for a, b in zip(original, damaged)), 1)
        self.path.write_bytes(damaged)
        with self.assertRaisesRegex(core.VaultError, "authentication failed"):
            with core.open_vault(self.path, MASTER):
                self.fail("A one-byte file modification must never yield decrypted entries")
        self.assertEqual(self.path.read_bytes(), bytes(damaged))
        self.assert_clean_directory()

    def assert_rejected_before_expensive_work(self, raw):
        self.path.write_bytes(raw)
        fake_hasher = mock.Mock()
        fake_hasher.verify.side_effect = AssertionError("Verifier must not run")
        with mock.patch.object(core, "PH", fake_hasher), mock.patch.object(
            core, "derive_key", side_effect=AssertionError("KDF must not run"),
        ):
            with self.assertRaises(core.VaultError):
                with core.open_vault(self.path, MASTER):
                    self.fail("Malformed data must not unlock")
        fake_hasher.verify.assert_not_called()
        self.assertEqual(self.path.read_bytes(), raw)
        self.assert_clean_directory()

    def test_oversized_and_duplicate_json_rejected_before_crypto(self):
        original = self.document()
        oversized = b" " * (core.MAX_FILE_BYTES + 1)
        duplicate = (
            '{"header":' + json.dumps(original["header"]) +
            ',"header":' + json.dumps(original["header"]) +
            ',"nonce":' + json.dumps(original["nonce"]) +
            ',"ciphertext":' + json.dumps(original["ciphertext"]) + '}'
        ).encode("utf-8")
        for raw in (oversized, duplicate, b"not-json", b"[]"):
            with self.subTest(case="oversized" if len(raw) > 10000 else raw[:30]):
                self.assert_rejected_before_expensive_work(raw)

    def test_attacker_selected_kdf_and_verifier_costs_are_rejected_before_crypto(self):
        original = self.document()
        cases = []
        for field, value in (("memory_kib", 2**30), ("iterations", 10**9),
                             ("parallelism", True)):
            damaged = copy.deepcopy(original)
            damaged["header"]["kdf"][field] = value
            cases.append(damaged)
        for segment in ("m=1073741824,t=3,p=4", "m=65536,t=999999999,p=4",
                        "m=65536,t=3,p=999999999"):
            damaged = copy.deepcopy(original)
            damaged["header"]["password_hash"] = damaged["header"]["password_hash"].replace(
                "m=65536,t=3,p=4", segment,
            )
            cases.append(damaged)
        for damaged in cases:
            with self.subTest(header=damaged["header"]["kdf"]):
                self.assert_rejected_before_expensive_work(json.dumps(damaged).encode())

    def test_invalid_nonce_and_ciphertext_encodings_rejected_before_crypto(self):
        original = self.document()
        for field, value in (("nonce", "!!!"), ("nonce", core.b64(b"short")),
                             ("ciphertext", core.b64(b"short"))):
            damaged = copy.deepcopy(original)
            damaged[field] = value
            self.assert_rejected_before_expensive_work(json.dumps(damaged).encode())

    def test_initialization_refuses_to_overwrite_existing_vault(self):
        original = self.path.read_bytes()
        with self.assertRaisesRegex(core.VaultError, "already exists"):
            core.initialize(self.path, "Another demo master passphrase!")
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_clean_directory()

    def test_every_save_uses_a_fresh_nonce_and_keeps_derivation_metadata(self):
        first = self.document()
        nonces = {first["nonce"]}
        with core.open_vault(self.path, MASTER) as vault:
            for _ in range(3):
                vault.save()
                document = self.document()
                nonces.add(document["nonce"])
                self.assertEqual(document["header"], first["header"])
                self.assertEqual(len(core.unb64(document["nonce"])), 12)
        self.assertEqual(len(nonces), 4)

    def test_atomic_replace_failure_preserves_original_and_cleans_temp_and_lock(self):
        original = self.path.read_bytes()
        with self.assertRaisesRegex(OSError, "simulated disk failure"):
            with core.open_vault(self.path, MASTER) as vault:
                vault.add(SITE, USER, ENTRY_PASSWORD)
                with mock.patch.object(core.os, "replace", side_effect=OSError("simulated disk failure")):
                    vault.save()
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_clean_directory()
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_existing_lock_is_not_deleted_or_silently_broken(self):
        lock = self.path.with_name(self.path.name + ".lock")
        lock.write_bytes(b"other-process-fixture")
        original = self.path.read_bytes()
        with self.assertRaisesRegex(core.VaultError, "locked"):
            with core.open_vault(self.path, MASTER):
                self.fail("Must not bypass a lock")
        self.assertEqual(lock.read_bytes(), b"other-process-fixture")
        self.assertEqual(self.path.read_bytes(), original)

    def test_update_sync_failure_preserves_original_and_releases_lock(self):
        original = self.path.read_bytes()
        with self.assertRaisesRegex(OSError, "simulated sync failure"):
            with core.open_vault(self.path, MASTER) as vault:
                vault.add(SITE, USER, ENTRY_PASSWORD)
                with mock.patch.object(core.os, "fsync", side_effect=OSError("simulated sync failure")):
                    vault.save()
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_clean_directory()
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_initial_creation_sync_failure_removes_incomplete_file_and_lock(self):
        fresh = self.root / "fresh.json"
        original = self.path.read_bytes()
        with mock.patch.object(core.os, "fsync", side_effect=OSError("simulated sync failure")):
            with self.assertRaisesRegex(OSError, "simulated sync failure"):
                core.initialize(fresh, MASTER)
        self.assertFalse(fresh.exists())
        self.assertEqual(self.path.read_bytes(), original)
        self.assert_clean_directory()
        core.initialize(fresh, MASTER)
        with core.open_vault(fresh, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_duplicate_entry_and_missing_deletion_do_not_modify_stored_vault(self):
        self.add_fixture()
        original = self.path.read_bytes()
        with core.open_vault(self.path, MASTER) as vault:
            with self.assertRaisesRegex(core.VaultError, "already exists"):
                vault.add(SITE, "other-user", "other-test-secret")
            with self.assertRaisesRegex(core.VaultError, "No entry"):
                vault.delete("missing.example")
        self.assertEqual(self.path.read_bytes(), original)

    def test_session_discards_its_references_after_context_exit(self):
        self.add_fixture()
        with core.open_vault(self.path, MASTER) as unlocked:
            self.assertTrue(unlocked.key)
            self.assertTrue(unlocked.entries)
        self.assertEqual(unlocked.key, b"")
        self.assertEqual(unlocked.entries, {})


class PasswordGeneratorTests(unittest.TestCase):
    def test_length_boundaries_and_all_four_character_classes(self):
        for length in (12, 20, 128):
            with self.subTest(length=length):
                password = core.generate_password(length)
                self.assertEqual(len(password), length)
                self.assertLessEqual(set(password), set(core.ALPHABET))
                for group in (string.ascii_lowercase, string.ascii_uppercase,
                              string.digits, string.punctuation):
                    self.assertTrue(set(password) & set(group))

    def test_invalid_lengths_rejected(self):
        for length in (0, 11, 129, -1, True, 20.0, "20"):
            with self.subTest(length=length):
                with self.assertRaises(core.VaultError):
                    core.generate_password(length)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "vault.json"

    def tearDown(self):
        self.folder.cleanup()

    def command(self, arguments, secrets):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "ask_secret", side_effect=secrets), \
                redirect_stdout(out), redirect_stderr(err):
            status = cli.main(["--vault", str(self.path), *arguments])
        return status, out.getvalue(), err.getvalue()

    def initialize(self):
        status, out, err = self.command(["init"], [MASTER, MASTER])
        self.assertEqual(status, 0, err)
        self.assertIn("Vault created", out)

    def test_full_cli_init_add_list_get_unlock_delete_lifecycle(self):
        self.initialize()
        status, out, err = self.command(["add", SITE, "--user", USER],
                                        [MASTER, ENTRY_PASSWORD, ENTRY_PASSWORD])
        self.assertEqual(status, 0, err)
        self.assertNotIn(ENTRY_PASSWORD, out)
        status, out, err = self.command(["list"], [MASTER])
        self.assertEqual(status, 0, err)
        self.assertEqual(json.loads(out), {"site": SITE, "username": USER})
        self.assertNotIn(ENTRY_PASSWORD, out)
        status, out, err = self.command(["get", SITE], [MASTER])
        self.assertEqual(status, 0, err)
        self.assertEqual(json.loads(out), {
            "site": SITE, "username": USER, "password": ENTRY_PASSWORD,
        })
        status, out, err = self.command(["unlock"], [MASTER])
        self.assertEqual(status, 0, err)
        self.assertIn("Unlocked successfully: 1 entries", out)
        status, out, err = self.command(["delete", SITE], [MASTER])
        self.assertEqual(status, 0, err)
        self.assertIn("Entry deleted", out)
        status, out, err = self.command(["list"], [MASTER])
        self.assertEqual(status, 0, err)
        self.assertIn("Vault is empty", out)

    def test_cli_wrong_master_returns_nonzero_and_prints_no_secret(self):
        self.initialize()
        self.command(["add", SITE, "--user", USER], [MASTER, ENTRY_PASSWORD, ENTRY_PASSWORD])
        original = self.path.read_bytes()
        status, out, err = self.command(["get", SITE], [WRONG])
        self.assertNotEqual(status, 0)
        self.assertEqual(out, "")
        self.assertIn("Error:", err)
        for value in (MASTER, WRONG, ENTRY_PASSWORD):
            self.assertNotIn(value, out + err)
        self.assertEqual(self.path.read_bytes(), original)

    def test_cli_init_confirmation_mismatch_creates_nothing(self):
        status, out, err = self.command(["init"], [MASTER, WRONG])
        self.assertNotEqual(status, 0)
        self.assertIn("do not match", err)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(Path(self.folder.name).iterdir()), [])

    def test_cli_generated_entry_is_saved_without_printing_its_password(self):
        self.initialize()
        status, out, err = self.command(["add", SITE, "--user", USER, "--generate", "--length", "24"],
                                        [MASTER])
        self.assertEqual(status, 0, err)
        with core.open_vault(self.path, MASTER) as vault:
            generated = vault.get(SITE)["password"]
            self.assertEqual(len(generated), 24)
            self.assertNotIn(generated, out + err)

    def test_cli_generator_does_not_need_a_master_password_or_create_files(self):
        status, out, err = self.command(["gen", "--length", "30"], [])
        self.assertEqual(status, 0, err)
        self.assertEqual(len(out.rstrip("\n")), 30)
        self.assertEqual(list(Path(self.folder.name).iterdir()), [])

    def test_cli_save_failure_reports_error_without_success_or_secrets(self):
        self.initialize()
        original = self.path.read_bytes()
        with mock.patch.object(core.os, "replace", side_effect=OSError("simulated save failure")):
            status, out, err = self.command(
                ["add", SITE, "--user", USER], [MASTER, ENTRY_PASSWORD, ENTRY_PASSWORD],
            )
        self.assertNotEqual(status, 0)
        self.assertNotIn("Entry saved", out)
        self.assertIn("simulated save failure", err)
        for secret in (MASTER, ENTRY_PASSWORD):
            self.assertNotIn(secret, out + err)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual({p.name for p in self.path.parent.iterdir()}, {"vault.json"})
        with core.open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_hidden_input_unavailable_does_not_create_vault(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.getpass, "getpass", side_effect=cli.getpass.GetPassWarning("no terminal")), \
                redirect_stdout(out), redirect_stderr(err):
            status = cli.main(["--vault", str(self.path), "init"])
        self.assertNotEqual(status, 0)
        self.assertIn("hidden password input is unavailable", err.getvalue())
        self.assertNotIn("Vault created", out.getvalue())
        self.assertEqual(list(Path(self.folder.name).iterdir()), [])

    def test_cli_invalid_new_master_password_creates_no_files(self):
        for master in ("", "short-test!", "密" * 342):
            with self.subTest(utf8_bytes=len(master.encode("utf-8"))):
                status, out, err = self.command(["init"], [master, master])
                self.assertNotEqual(status, 0)
                self.assertIn("Error:", err)
                self.assertNotIn("Vault created", out)
                if master:
                    self.assertNotIn(master, out + err)
                self.assertEqual(list(Path(self.folder.name).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
