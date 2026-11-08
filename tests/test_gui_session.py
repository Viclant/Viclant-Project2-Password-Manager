"""Desktop-session behavior with real encryption and disposable data."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from gui_session import VaultSession
from vault_core import VaultError, initialize, open_vault


MASTER = "Only a desktop-session test passphrase 2026!"


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class GuiSessionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "vault.json"
        self.clock = FakeClock()
        self.session = VaultSession(timeout_seconds=120, clock=self.clock)

    def tearDown(self):
        self.session.lock()
        self.folder.cleanup()

    def create(self):
        self.session.create(self.path, MASTER)

    def test_create_unlock_and_lock_do_not_retain_master_password(self):
        self.create()
        self.assertTrue(self.session.unlocked)
        self.assertEqual(self.session.path, self.path.absolute())
        self.assertEqual(self.session.last_activity, 100.0)
        self.assertNotIn(MASTER, vars(self.session).values())
        # A suspended context-manager generator must not retain its password
        # argument for the whole unlocked desktop session.
        self.assertNotIn("password", self.session._context.gen.gi_frame.f_locals)
        self.assertTrue(self.path.with_name("vault.json.lock").exists())
        vault = self.session._vault
        self.session.lock()
        self.assertFalse(self.session.unlocked)
        self.assertIsNone(self.session.path)
        self.assertIsNone(self.session.last_activity)
        self.assertEqual(vault.key, b"")
        self.assertEqual(vault.entries, {})
        self.assertFalse(self.path.with_name("vault.json.lock").exists())

    def test_wrong_unlock_rejects_and_releases_lock(self):
        initialize(self.path, MASTER)
        original = self.path.read_bytes()
        with self.assertRaisesRegex(VaultError, "Wrong master"):
            self.session.unlock(self.path, "Wrong desktop demonstration password!")
        self.assertFalse(self.session.unlocked)
        self.assertIsNone(self.session._context)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(self.path.with_name("vault.json.lock").exists())
        self.session.unlock(self.path, MASTER)
        self.assertTrue(self.session.unlocked)

    def test_create_refuses_existing_vault_without_replacing_it(self):
        initialize(self.path, MASTER)
        original = self.path.read_bytes()
        with self.assertRaisesRegex(VaultError, "already exists"):
            self.create()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(self.session.unlocked)
        self.assertFalse(self.path.with_name("vault.json.lock").exists())

    def test_crud_edit_and_rename_persist_without_leaking_passwords_into_rows(self):
        self.create()
        self.session.save_entry("Example.com", "Alice", "First test password!")
        self.session.save_entry("第二站点", "用户", "中文测试密码!")
        rows = self.session.rows()
        self.assertEqual(rows[0], {"site": "Example.com", "username": "Alice"})
        self.assertTrue(all(set(row) == {"site", "username"} for row in rows))
        entry = self.session.get("Example.com")
        entry["password"] = "Caller mutation must not change the entry"
        self.assertEqual(self.session.get("Example.com")["password"], "First test password!")
        self.session.save_entry("Example.com", "Alice2", "Changed test password!", original_site="Example.com")
        self.session.save_entry("renamed.example", "Alice2", "Changed test password!", original_site="Example.com")
        self.assertEqual(self.session.get("renamed.example")["username"], "Alice2")
        with self.assertRaises(VaultError):
            self.session.get("Example.com")
        self.session.delete("第二站点")
        self.session.lock()
        with open_vault(self.path, MASTER) as vault:
            self.assertEqual(list(vault.entries), ["renamed.example"])
            self.assertEqual(vault.get("renamed.example")["password"], "Changed test password!")

    def test_search_is_case_insensitive_and_checks_site_or_username(self):
        self.create()
        self.session.save_entry("GitHub", "Alice", "Test-only password!")
        self.session.save_entry("mail.example", "Bob", "Other test-only password!")
        self.assertEqual(self.session.rows("GITHUB"), [{"site": "GitHub", "username": "Alice"}])
        self.assertEqual(self.session.rows("bOB"), [{"site": "mail.example", "username": "Bob"}])
        self.assertEqual(self.session.rows("not present"), [])

    def test_duplicate_new_or_renamed_site_preserves_memory_and_file(self):
        self.create()
        self.session.save_entry("first", "alice", "Test-only first password!")
        self.session.save_entry("second", "bob", "Test-only second password!")
        original = self.path.read_bytes()
        for arguments in [("first", "changed", "Changed duplicate password!", None),
                          ("second", "changed", "Changed duplicate password!", "first")]:
            with self.assertRaises(VaultError):
                self.session.save_entry(*arguments)
            self.assertEqual(self.path.read_bytes(), original)
            self.assertEqual(self.session.get("first")["username"], "alice")
            self.assertEqual(self.session.get("second")["username"], "bob")

    def test_write_failure_restores_unsaved_add_edit_and_delete(self):
        self.create()
        self.session.save_entry("original", "alice", "Test-only original password!")
        original = self.path.read_bytes()
        operations = [
            lambda: self.session.save_entry("new", "bob", "Test-only new password!"),
            lambda: self.session.save_entry("renamed", "changed", "Changed test password!", "original"),
            lambda: self.session.delete("original"),
        ]
        for operation in operations:
            with mock.patch("vault_core.os.replace", side_effect=OSError("Simulated disk error")):
                with self.assertRaises(OSError):
                    operation()
            self.assertEqual(self.path.read_bytes(), original)
            self.assertEqual(self.session.rows(), [{"site": "original", "username": "alice"}])
            self.assertFalse(list(self.path.parent.glob("*.tmp")))
        self.session.lock()
        self.assertFalse(self.path.with_name("vault.json.lock").exists())

    def test_idle_timeout_locks_and_does_not_revive_on_touch(self):
        self.create()
        self.session.save_entry("example", "alice", "Test-only password!")
        self.clock.value = 219.9
        self.assertFalse(self.session.expire_if_idle())
        self.clock.value = 220.0
        self.assertTrue(self.session.expire_if_idle())
        self.assertFalse(self.session.unlocked)
        self.assertFalse(self.session.touch())
        self.assertFalse(self.session.expire_if_idle())
        self.assertFalse(self.path.with_name("vault.json.lock").exists())
        with self.assertRaisesRegex(VaultError, "Unlock"):
            self.session.rows()

    def test_touch_extends_only_a_current_unexpired_session(self):
        self.create()
        self.clock.value = 200.0
        self.assertTrue(self.session.touch())
        self.clock.value = 319.0
        self.assertFalse(self.session.expire_if_idle())
        self.clock.value = 320.0
        self.assertFalse(self.session.touch())
        self.assertFalse(self.session.unlocked)

    def test_operations_enforce_timeout_even_before_timer_callback(self):
        self.create()
        self.session.save_entry("example", "alice", "Test-only password!")
        original = self.path.read_bytes()
        self.clock.value = 220.0
        with self.assertRaisesRegex(VaultError, "auto-locked"):
            self.session.delete("example")
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(self.session.unlocked)

    def test_invalid_save_after_deadline_still_discards_session_first(self):
        self.create()
        original = self.path.read_bytes()
        self.clock.value = 220.0
        with self.assertRaisesRegex(VaultError, "auto-locked"):
            self.session.save_entry("", "", "")
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(self.session.unlocked)

    def test_unlocked_gui_holds_lock_until_close_so_cli_cannot_race(self):
        self.create()
        with self.assertRaisesRegex(VaultError, "locked"):
            with open_vault(self.path, MASTER):
                self.fail("CLI should not obtain another session")
        self.session.lock()
        with open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_locked_actions_are_rejected_without_creating_files(self):
        for action in [self.session.rows, lambda: self.session.get("site"),
                       lambda: self.session.delete("site"),
                       lambda: self.session.save_entry("site", "user", "Password!")]:
            with self.assertRaisesRegex(VaultError, "Unlock"):
                action()
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_unlocking_another_path_closes_the_previous_context_first(self):
        self.create()
        other = self.path.parent / "other.json"
        initialize(other, MASTER)
        previous = self.session._vault
        self.session.unlock(other, MASTER)
        self.assertEqual(previous.key, b"")
        self.assertEqual(self.session.path, other.absolute())
        with open_vault(self.path, MASTER):
            pass

    def test_invalid_timeouts_are_rejected(self):
        for value in [0, -1, True, "120", float("inf"), float("nan")]:
            with self.assertRaises(ValueError):
                VaultSession(value)


if __name__ == "__main__":
    unittest.main()
