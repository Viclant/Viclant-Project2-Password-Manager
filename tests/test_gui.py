"""Tk widget/controller integration; no real credentials or OS clipboard writes."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

try:
    import tkinter as tk
except ImportError:
    tk = None

from gui_session import VaultSession
from vault_core import open_vault
if tk is not None:
    from vault_gui import ClipboardGuard, VaultApp


MASTER = "GUI demonstration master 2026!"


class FakeClipboard:
    def __init__(self):
        self.value, self.jobs, self.next_id = "", {}, 0

    def clipboard_clear(self): self.value = ""
    def clipboard_append(self, value): self.value += value
    def clipboard_get(self): return self.value
    def after(self, delay, function):
        self.next_id += 1
        self.jobs[self.next_id] = (delay, function)
        return self.next_id
    def after_cancel(self, identifier): self.jobs.pop(identifier, None)


@unittest.skipIf(tk is None, "Optional GUI requires Tkinter.")
class ClipboardTests(unittest.TestCase):
    def test_clears_own_copy_after_30_seconds(self):
        owner = FakeClipboard()
        guard = ClipboardGuard(owner)
        guard.copy("invented-demo-password")
        delay, callback = owner.jobs[guard.timer]
        self.assertEqual(delay, 30000)
        self.assertNotIn("invented-demo-password", guard.__dict__.values())
        callback()
        self.assertEqual(owner.value, "")
        self.assertIsNone(guard.token)

    def test_does_not_clear_replacement_clipboard_content(self):
        owner = FakeClipboard()
        guard = ClipboardGuard(owner)
        guard.copy("invented-demo-password")
        owner.value = "user copied something else"
        guard.clear_if_unchanged()
        self.assertEqual(owner.value, "user copied something else")
        self.assertEqual(owner.jobs, {})

    def test_recopy_cancels_old_timer(self):
        owner = FakeClipboard()
        guard = ClipboardGuard(owner)
        guard.copy("first invented password")
        first = guard.timer
        guard.copy("second invented password")
        self.assertNotIn(first, owner.jobs)
        self.assertEqual(len(owner.jobs), 1)
        self.assertEqual(owner.value, "second invented password")

    def test_temporary_clipboard_contention_retries_without_losing_tracking(self):
        owner = FakeClipboard()
        guard = ClipboardGuard(owner)
        guard.copy("invented-demo-password")
        with patch.object(owner, "clipboard_get", side_effect=tk.TclError("clipboard busy")):
            guard.clear_if_unchanged()
        self.assertIsNotNone(guard.token)
        delay, callback = owner.jobs[guard.timer]
        self.assertEqual(delay, 1000)
        callback()
        self.assertEqual(owner.value, "")
        self.assertIsNone(guard.token)

    def test_clipboard_retries_are_bounded_and_preserve_new_content(self):
        owner = FakeClipboard()
        guard = ClipboardGuard(owner)
        guard.copy("invented-demo-password")
        with patch.object(owner, "clipboard_get", side_effect=tk.TclError("clipboard busy")):
            guard.clear_if_unchanged(retries=1)
            owner.jobs[guard.timer][1]()
        self.assertEqual(owner.jobs, {})
        self.assertIsNone(guard.timer)
        owner.value = "new user content"
        guard.clear_if_unchanged()
        self.assertEqual(owner.value, "new user content")


@unittest.skipIf(tk is None, "Optional GUI requires Tkinter.")
class GuiIntegrationTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"GUI widget tests need a display: {error}")
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "gui.vault.json"
        self.now = [0.0]
        self.session = VaultSession(clock=lambda: self.now[0])
        self.root.withdraw()
        self.app = VaultApp(self.root, self.path, self.session)
        self.clipboard = FakeClipboard()
        self.app.clipboard = ClipboardGuard(self.clipboard)
        self.messages = patch("vault_gui.messagebox.showerror")
        self.error = self.messages.start()

    def tearDown(self):
        self.app.close()
        self.messages.stop()
        self.folder.cleanup()

    def create(self):
        self.app.mode.set("create")
        self.app._mode_changed()
        self.app.master.set(MASTER)
        self.app.confirm.set(MASTER)
        self.app.unlock()
        self.assertTrue(self.session.unlocked)

    def test_create_clears_master_inputs_and_uses_shared_format(self):
        self.create()
        self.assertEqual(self.app.master.get(), "")
        self.assertEqual(self.app.confirm.get(), "")
        self.assertEqual(self.app.badge.cget("text"), "UNLOCKED")
        self.app.lock()
        with open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_add_select_edit_and_delete_through_widgets(self):
        self.create()
        self.app.site.set("demo.example")
        self.app.username.set("demo-user")
        self.app.password.set("dummy-password-123!")
        self.app.save_entry()
        self.assertEqual(self.app.password.get(), "")
        self.assertEqual(len(self.app.tree.get_children()), 1)
        self.app.tree.selection_set(self.app.tree.get_children()[0])
        self.app.select_entry()
        self.assertEqual(self.app.password.get(), "dummy-password-123!")
        self.assertEqual(self.app.password_entry.cget("show"), "\u2022")
        self.app.site.set("renamed.example")
        self.app.password.set("dummy-password-edited!")
        self.app.save_entry()
        self.assertEqual(self.session.get("renamed.example")["password"], "dummy-password-edited!")
        self.app.tree.selection_set(self.app.tree.get_children()[0])
        self.app.select_entry()
        with patch("vault_gui.messagebox.askyesno", return_value=True):
            self.app.delete_entry()
        self.assertEqual(self.session.rows(), [])
        self.app.lock()
        with open_vault(self.path, MASTER) as vault:
            self.assertEqual(vault.entries, {})

    def test_wrong_unlock_clears_inputs_and_leaves_no_lock(self):
        self.create()
        self.app.lock()
        self.app.mode.set("unlock")
        self.app.master.set("not the correct passphrase")
        self.app.unlock()
        self.assertFalse(self.session.unlocked)
        self.assertEqual(self.app.master.get(), "")
        self.assertFalse(self.path.with_name(self.path.name + ".lock").exists())
        self.error.assert_called_once()

    def test_failed_ui_setup_after_unlock_closes_the_session(self):
        self.create()
        self.app.lock()
        self.app.mode.set("unlock")
        self.app.master.set(MASTER)
        with patch.object(self.app, "new_entry", side_effect=ValueError("UI setup failed")):
            self.app.unlock()
        self.assertFalse(self.session.unlocked)
        self.assertEqual(self.app.master.get(), "")
        self.assertFalse(self.path.with_name(self.path.name + ".lock").exists())
        self.error.assert_called_once()

    def test_reveal_schedules_masking_and_hiding_cancels_it(self):
        self.create()
        self.app.password.set("dummy-password!")
        self.app.toggle_reveal()
        self.assertEqual(self.app.password_entry.cget("show"), "")
        timer = self.app.reveal_timer
        self.assertIn(timer, self.root.tk.call("after", "info"))
        self.app._hide_password()
        self.assertEqual(self.app.password_entry.cget("show"), "\u2022")
        self.assertIsNone(self.app.reveal_timer)
        self.assertNotIn(timer, self.root.tk.call("after", "info"))

    def test_lock_erases_form_rows_generator_and_own_clipboard(self):
        self.create()
        self.session.save_entry("demo.example", "demo", "dummy-password!")
        self.app.refresh_rows()
        self.app.password.set("dummy-password!")
        self.app.copy_password()
        self.app.open_generator(use_entry=True)
        generated = self.app.generators[0][1]
        self.assertTrue(generated.get())
        self.app.lock()
        self.assertEqual(self.app.password.get(), "")
        self.assertEqual(self.app.tree.get_children(), ())
        self.assertEqual(self.app.generators, [])
        self.assertEqual(generated.get(), "")
        self.assertEqual(self.clipboard.value, "")
        self.assertFalse(self.session.unlocked)

    def test_expired_session_cannot_copy_or_reveal_stale_password(self):
        self.create()
        self.app.password.set("dummy-password!")
        self.now[0] = 121
        self.app.copy_password()
        self.assertEqual(self.clipboard.value, "")
        self.assertEqual(self.app.password.get(), "")
        self.assertFalse(self.session.unlocked)
        self.app.toggle_reveal()
        self.assertEqual(self.app.password_entry.cget("show"), "\u2022")

    def test_popup_cleanup_error_does_not_leave_session_unlocked(self):
        self.create()
        self.app.open_generator(use_entry=True)
        secret = self.app.generators[0][1]
        with patch.object(secret, "set", side_effect=tk.TclError("popup already closed")):
            self.app.lock()
        self.assertFalse(self.session.unlocked)
        self.assertFalse(self.path.with_name(self.path.name + ".lock").exists())
        self.assertEqual(self.app.badge.cget("text"), "LOCKED")

    def test_search_omits_passwords_and_filters_sites(self):
        self.create()
        self.session.save_entry("mail.example", "Alice", "dummy-one!")
        self.session.save_entry("git.example", "Bob", "dummy-two!")
        self.app.search.set("ALICE")
        values = [self.app.tree.item(i, "values") for i in self.app.tree.get_children()]
        self.assertEqual(values, [("mail.example", "Alice")])
        self.assertNotIn("dummy-one!", str(values))


if __name__ == "__main__":
    unittest.main()
