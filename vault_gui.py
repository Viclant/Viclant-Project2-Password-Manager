"""Optional offline Tkinter interface; the required CLI still uses vault.py."""

import argparse
import hashlib
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from gui_session import VaultSession
from vault_core import VaultError, generate_password


BG = "#F3F6F8"
WHITE = "#FFFFFF"
INK = "#192F3A"
MUTED = "#667B87"
LINE = "#DDE5E9"
ACCENT = "#11796F"
NAVY = "#142C36"


class ClipboardGuard:
    """Clear only our last copy, and only if the user has not replaced it."""
    def __init__(self, owner):
        self.owner, self.token, self.timer = owner, None, None

    def copy(self, value):
        if not value:
            raise VaultError("There is no password to copy.")
        self.clear_if_unchanged()
        self.owner.clipboard_clear()
        self.owner.clipboard_append(value)
        self._cancel_timer()
        self.token = hashlib.sha256(value.encode("utf-8")).digest()
        self.timer = self.owner.after(30000, self.clear_if_unchanged)

    def _cancel_timer(self):
        if self.timer is not None:
            try:
                self.owner.after_cancel(self.timer)
            except tk.TclError:
                pass
            self.timer = None

    def clear_if_unchanged(self, retries=3):
        self._cancel_timer()
        if self.token is not None:
            try:
                current = self.owner.clipboard_get()
                if hashlib.sha256(current.encode("utf-8")).digest() == self.token:
                    self.owner.clipboard_clear()
            except tk.TclError:
                # Windows can briefly deny clipboard access while another app uses it.
                if retries > 0:
                    try:
                        self.timer = self.owner.after(1000, lambda: self.clear_if_unchanged(retries - 1))
                    except tk.TclError:
                        pass  # The window may already be closing.
                return
        self.token = None


class VaultApp:
    def __init__(self, root, path=None, session=None):
        self.root = root
        self.session = session or VaultSession(timeout_seconds=120)
        self.clipboard = ClipboardGuard(root)
        self.original_site = None
        self.generators = []
        self.reveal_timer = None
        self.path = tk.StringVar(value=str(path or Path(__file__).with_name("vault.json")))
        self.master = tk.StringVar()
        self.confirm = tk.StringVar()
        self.mode = tk.StringVar(value="unlock")
        self.search = tk.StringVar()
        self.site = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.status = tk.StringVar(value="Choose a vault to get started.")
        root.title("Vault | Project 2 Password Manager")
        root.geometry("1180x820")
        root.minsize(1000, 800)
        root.configure(bg=BG)
        self._styles()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.bind_all("<KeyPress>", self._activity, add="+")
        root.bind_all("<ButtonPress>", self._activity, add="+")
        self.search.trace_add("write", lambda *_: self.refresh_rows())
        self.tick_timer = root.after(1000, self._tick)
        self.show_locked()

    def _styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("Primary.TButton", foreground=WHITE, background=ACCENT, borderwidth=0)
        style.map("Primary.TButton", background=[("active", "#0B655D"), ("disabled", "#9DBCB8")])
        style.configure("Quiet.TButton", background=WHITE, foreground=INK, borderwidth=1)
        style.configure("Field.TEntry", padding=(9, 8), font=("Segoe UI", 10))
        style.configure("Vault.Treeview", rowheight=42, font=("Segoe UI", 10),
                        background=WHITE, fieldbackground=WHITE, foreground=INK, borderwidth=0)
        style.configure("Vault.Treeview.Heading", font=("Segoe UI", 9, "bold"),
                        background="#EEF3F5", foreground=MUTED, padding=(10, 12), relief="flat")
        style.map("Vault.Treeview", background=[("selected", "#DCEFEA")],
                  foreground=[("selected", INK)])

    def label(self, parent, text, size=10, color=INK, bold=False, **kwargs):
        return tk.Label(parent, text=text, font=("Segoe UI", size, "bold" if bold else "normal"),
                        fg=color, bg=parent.cget("bg"), anchor="w", **kwargs)

    def _build(self):
        sidebar = tk.Frame(self.root, bg=NAVY, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=NAVY)
        brand.pack(fill="x", padx=24, pady=(32, 30))
        self.label(brand, "V", 27, WHITE, True).pack(anchor="w")
        self.label(brand, "Vault", 23, WHITE, True).pack(anchor="w", pady=(6, 0))
        self.label(brand, "LOCAL PASSWORD MANAGER", 8, "#8EAAB5").pack(anchor="w", pady=(4, 0))
        self.label(sidebar, "WORKSPACE", 8, "#8EAAB5", True).pack(anchor="w", padx=24, pady=(6, 10))
        for text, command in [("All passwords", self._focus_vault),
                              ("Password generator", self.open_generator)]:
            tk.Button(sidebar, text=text, command=command, anchor="w", padx=24, pady=12,
                      bg=NAVY, fg=WHITE, activebackground="#22434E", activeforeground=WHITE,
                      bd=0, relief="flat", font=("Segoe UI", 10), cursor="hand2").pack(fill="x")
        footer = tk.Frame(sidebar, bg=NAVY)
        footer.pack(side="bottom", fill="x", padx=24, pady=26)
        self.label(footer, "PROJECT 2 / EPITA", 8, "#8EAAB5", True).pack(anchor="w", pady=(0, 10))
        for name in ("Wu Yanlan", "Chen Ziming", "Liu Yunfei"):
            self.label(footer, name, 10, "#D4E2E8").pack(anchor="w", pady=2)
        self.label(footer, "Offline. Stored on your device.", 8, "#8EAAB5").pack(anchor="w", pady=(16, 0))

        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True, padx=28, pady=26)
        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", pady=(0, 22))
        title = tk.Frame(header, bg=BG)
        title.pack(side="left")
        self.label(title, "Your vault", 23, bold=True).pack(anchor="w")
        self.label(title, "A private place for your logins.", 10, MUTED).pack(anchor="w", pady=(4, 0))
        self.lock_button = ttk.Button(header, text="Lock vault", command=self.lock, style="Quiet.TButton")
        self.lock_button.pack(side="right", padx=(12, 0))
        self.badge = tk.Label(header, text="LOCKED", bg="#E5EBEF", fg=MUTED,
                             padx=12, pady=7, font=("Segoe UI", 9, "bold"))
        self.badge.pack(side="right")
        self.body = tk.Frame(main, bg=BG)
        self.body.pack(fill="both", expand=True)
        self.auth = tk.Frame(self.body, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
        self._build_auth()
        self.workspace = tk.Frame(self.body, bg=BG)
        self._build_workspace()
        tk.Label(main, textvariable=self.status, anchor="w", bg=BG, fg=MUTED,
                 font=("Segoe UI", 9), wraplength=850).pack(fill="x", pady=(14, 0))

    def _build_auth(self):
        card = tk.Frame(self.auth, bg=WHITE)
        card.pack(fill="both", expand=True, padx=36, pady=30)
        self.label(card, "Keep your passwords close.", 20, bold=True).pack(anchor="w")
        self.label(card, "Open an existing vault or create your first one.", 10, MUTED).pack(anchor="w", pady=(7, 24))
        modes = tk.Frame(card, bg=WHITE)
        modes.pack(fill="x", pady=(0, 22))
        for name, value in [("Unlock vault", "unlock"), ("Create vault", "create")]:
            ttk.Radiobutton(modes, text=name, variable=self.mode, value=value,
                            command=self._mode_changed).pack(side="left", padx=(0, 26))
        self.label(card, "VAULT FILE", 8, MUTED, True).pack(anchor="w", pady=(0, 6))
        row = tk.Frame(card, bg=WHITE)
        row.pack(fill="x", pady=(0, 20))
        ttk.Entry(row, textvariable=self.path, style="Field.TEntry").pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", command=self.browse, style="Quiet.TButton").pack(side="right", padx=(8, 0))
        self.label(card, "MASTER PASSPHRASE", 8, MUTED, True).pack(anchor="w", pady=(0, 6))
        self.master_entry = ttk.Entry(card, textvariable=self.master, show="\u2022", style="Field.TEntry")
        self.master_entry.pack(fill="x", pady=(0, 17))
        self.master_entry.bind("<Return>", lambda _: self.unlock())
        self.confirm_frame = tk.Frame(card, bg=WHITE)
        self.label(self.confirm_frame, "CONFIRM PASSPHRASE", 8, MUTED, True).pack(anchor="w", pady=(0, 6))
        confirm = ttk.Entry(self.confirm_frame, textvariable=self.confirm, show="\u2022", style="Field.TEntry")
        confirm.pack(fill="x", pady=(0, 17))
        confirm.bind("<Return>", lambda _: self.unlock())
        self.submit = ttk.Button(card, text="Unlock vault", command=self.unlock, style="Primary.TButton")
        self.submit.pack(fill="x", pady=(7, 16))
        self.label(card, "Your master passphrase is never saved in plain text.", 9, MUTED).pack(anchor="w")
        self.label(card, "Use a long passphrase you can remember. There is no recovery key.",
                   9, MUTED, wraplength=650, justify="left").pack(anchor="w", pady=(5, 0))

    def _build_workspace(self):
        tools = tk.Frame(self.workspace, bg=BG)
        tools.pack(fill="x", pady=(0, 16))
        search = ttk.Entry(tools, textvariable=self.search, style="Field.TEntry", width=30)
        search.pack(side="left", fill="x", expand=True)
        self.label(tools, "Search site or username", 9, MUTED).pack(side="left", padx=10)
        ttk.Button(tools, text="+ New entry", command=self.new_entry, style="Primary.TButton").pack(side="right")
        panes = tk.Frame(self.workspace, bg=BG)
        panes.pack(fill="both", expand=True)
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, minsize=305)
        panes.rowconfigure(0, weight=1)
        listing = tk.Frame(panes, bg=WHITE, highlightbackground=LINE, highlightthickness=1)
        listing.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        self.count = self.label(listing, "All passwords", 12, bold=True)
        self.count.pack(anchor="w", padx=16, pady=(18, 13))
        self.tree = ttk.Treeview(listing, columns=("site", "username"), show="headings",
                                 style="Vault.Treeview", selectmode="browse")
        self.tree.heading("site", text="SITE", anchor="w")
        self.tree.heading("username", text="USERNAME", anchor="w")
        self.tree.column("site", width=180, minwidth=100)
        self.tree.column("username", width=150, minwidth=100)
        scrollbar = ttk.Scrollbar(listing, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(fill="both", expand=True, padx=(8, 0), pady=(0, 10))
        self.tree.bind("<<TreeviewSelect>>", self.select_entry)
        detail = tk.Frame(panes, bg=WHITE, width=305, highlightbackground=LINE, highlightthickness=1)
        detail.grid(row=0, column=1, sticky="nsew")
        form = tk.Frame(detail, bg=WHITE)
        form.pack(fill="both", expand=True, padx=20, pady=18)
        self.form_title = self.label(form, "New entry", 14, bold=True)
        self.form_title.pack(anchor="w", pady=(0, 23))
        for label, variable in [("SITE", self.site), ("USERNAME", self.username), ("PASSWORD", self.password)]:
            self.label(form, label, 8, MUTED, True).pack(anchor="w", pady=(0, 6))
            field = ttk.Entry(form, textvariable=variable, style="Field.TEntry", width=25,
                              show="\u2022" if label == "PASSWORD" else "")
            field.pack(fill="x", pady=(0, 17))
            if label == "SITE": self.site_entry = field
            if label == "PASSWORD": self.password_entry = field
        actions = tk.Frame(form, bg=WHITE)
        actions.pack(fill="x", pady=(0, 12))
        self.reveal_button = ttk.Button(actions, text="Show", command=self.toggle_reveal, style="Quiet.TButton")
        self.reveal_button.pack(side="left")
        ttk.Button(actions, text="Copy", command=self.copy_password, style="Quiet.TButton").pack(side="left", padx=6)
        ttk.Button(form, text="Generate password", command=lambda: self.open_generator(use_entry=True),
                   style="Quiet.TButton").pack(fill="x", pady=(0, 18))
        ttk.Button(form, text="Save entry", command=self.save_entry, style="Primary.TButton").pack(fill="x", pady=(0, 8))
        self.delete_button = ttk.Button(form, text="Delete entry", command=self.delete_entry, style="Quiet.TButton")
        self.delete_button.pack(fill="x")
        self.label(form, "Auto-locks after 2 minutes of inactivity.", 8, MUTED,
                   wraplength=260, justify="left").pack(anchor="w", side="bottom", pady=(15, 0))

    def _mode_changed(self):
        self.master.set("")
        self.confirm.set("")
        if self.mode.get() == "create":
            self.confirm_frame.pack(fill="x", before=self.submit)
            self.submit.configure(text="Create encrypted vault")
        else:
            self.confirm_frame.pack_forget()
            self.submit.configure(text="Unlock vault")

    def browse(self):
        picker = filedialog.asksaveasfilename if self.mode.get() == "create" else filedialog.askopenfilename
        value = picker(parent=self.root, title="Choose your vault file", defaultextension=".vault.json",
                       filetypes=[("Vault files", "*.json"), ("All files", "*.*")])
        if value: self.path.set(value)

    def unlock(self):
        password = self.master.get()
        try:
            if not self.path.get().strip():
                raise VaultError("Choose a vault file first.")
            if self.mode.get() == "create":
                if password != self.confirm.get():
                    raise VaultError("The two master passphrases do not match.")
                self.session.create(Path(self.path.get()).expanduser(), password)
            else:
                self.session.unlock(Path(self.path.get()).expanduser(), password)
            self.auth.pack_forget()
            self.workspace.pack(fill="both", expand=True)
            self.lock_button.state(["!disabled"])
            self.badge.configure(text="UNLOCKED", bg="#DCEFE8", fg=ACCENT)
            self.new_entry()
            self.refresh_rows()
            self.status.set(f"Unlocked: {self.session.path}   |   Changes are saved to this device.")
        except (VaultError, OSError, ValueError) as error:
            self.lock("Could not open the vault. Check the file and passphrase.")
            messagebox.showerror("Could not open vault", str(error), parent=self.root)
        finally:
            self.master.set("")
            self.confirm.set("")
            password = ""

    def _clear_form(self):
        self.original_site = None
        self.site.set("")
        self.username.set("")
        self.password.set("")
        self._hide_password()

    def show_locked(self, message=None):
        self._clear_form()
        self.master.set("")
        self.confirm.set("")
        self.search.set("")
        self.tree.delete(*self.tree.get_children())
        self.workspace.pack_forget()
        self.auth.pack(fill="x", pady=6)
        self.lock_button.state(["disabled"])
        self.badge.configure(text="LOCKED", bg="#E5EBEF", fg=MUTED)
        if message: self.status.set(message)

    def lock(self, message="Vault locked. Your session has ended."):
        try:
            self.session.lock()
        finally:
            self.clipboard.clear_if_unchanged()
            for window, secret in self.generators[:]:
                try:
                    secret.set("")
                    if window.winfo_exists(): window.destroy()
                except tk.TclError:
                    pass  # A closed popup must never keep the vault unlocked.
            self.generators.clear()
            self.show_locked(message)

    def _activity(self, _event=None):
        if self.session.expire_if_idle():
            self.lock("Auto-locked after 2 minutes of inactivity.")
        else:
            self.session.touch()

    def _tick(self):
        if self.session.expire_if_idle():
            self.lock("Auto-locked after 2 minutes of inactivity.")
        self.tick_timer = self.root.after(1000, self._tick)

    def _focus_vault(self):
        (self.tree if self.session.unlocked else self.master_entry).focus_set()

    def _ensure_session(self):
        if self.session.expire_if_idle():
            self.lock("Auto-locked after 2 minutes of inactivity.")
        if not self.session.unlocked:
            return False
        self.session.touch()
        return True

    def refresh_rows(self):
        if not self.session.unlocked: return
        selected = self.original_site
        try:
            rows = self.session.rows(self.search.get())
            self.tree.delete(*self.tree.get_children())
            for row in rows:
                self.tree.insert("", "end", values=(row["site"], row["username"]))
            self.count.configure(text=f"All passwords  /  {len(rows)}")
            if selected and not any(row["site"] == selected for row in rows): self.new_entry()
        except (VaultError, OSError) as error:
            self._error(error)

    def new_entry(self):
        self._clear_form()
        self.form_title.configure(text="New entry")
        self.delete_button.state(["disabled"])
        self.tree.selection_remove(*self.tree.selection())
        self.site_entry.focus_set()

    def select_entry(self, _event=None):
        selected = self.tree.selection()
        if not selected or not self.session.unlocked: return
        try:
            entry = self.session.get(str(self.tree.item(selected[0], "values")[0]))
            self.original_site = entry["site"]
            self.site.set(entry["site"])
            self.username.set(entry["username"])
            self.password.set(entry["password"])
            self._hide_password()
            self.form_title.configure(text="Entry details")
            self.delete_button.state(["!disabled"])
        except (VaultError, OSError) as error:
            self._error(error)

    def _error(self, error):
        if not self.session.unlocked: self.lock("Vault locked. Unlock it to continue.")
        messagebox.showerror("Vault", str(error), parent=self.root)

    def save_entry(self):
        try:
            self.session.save_entry(self.site.get(), self.username.get(), self.password.get(),
                                    original_site=self.original_site)
            self.new_entry()
            self.refresh_rows()
            self.status.set("Entry saved to the encrypted vault.")
        except (VaultError, OSError, ValueError) as error:
            self._error(error)

    def delete_entry(self):
        if self.original_site is None: return
        if not messagebox.askyesno("Delete entry?", "Delete this entry from the vault? This cannot be undone here.", parent=self.root):
            return
        try:
            self.session.delete(self.original_site)
            self.new_entry()
            self.refresh_rows()
            self.status.set("Entry deleted. Old backups may still contain earlier versions.")
        except (VaultError, OSError) as error:
            self._error(error)

    def _hide_password(self):
        if self.reveal_timer is not None:
            self.root.after_cancel(self.reveal_timer)
            self.reveal_timer = None
        self.password_entry.configure(show="\u2022")
        self.reveal_button.configure(text="Show")

    def toggle_reveal(self):
        if not self._ensure_session(): return
        if self.password_entry.cget("show"):
            self.password_entry.configure(show="")
            self.reveal_button.configure(text="Hide")
            self.reveal_timer = self.root.after(15000, self._hide_password)
        else:
            self._hide_password()

    def copy_password(self):
        if not self._ensure_session(): return
        try:
            self.clipboard.copy(self.password.get())
            self.status.set("Password copied. It is cleared after 30 seconds if the clipboard is unchanged.")
        except (VaultError, tk.TclError) as error:
            self._error(error)

    def open_generator(self, use_entry=False):
        window = tk.Toplevel(self.root)
        window.title("Password generator")
        window.configure(bg=WHITE)
        window.geometry("470x315")
        window.resizable(False, False)
        window.transient(self.root)
        panel = tk.Frame(window, bg=WHITE)
        panel.pack(fill="both", expand=True, padx=24, pady=22)
        self.label(panel, "Generate a strong password", 16, bold=True).pack(anchor="w", pady=(0, 16))
        length = tk.StringVar(value="24")
        secret = tk.StringVar()
        self.generators.append((window, secret))
        row = tk.Frame(panel, bg=WHITE)
        row.pack(fill="x", pady=(0, 14))
        self.label(row, "Length (12-128)", 10, MUTED).pack(side="left")
        ttk.Spinbox(row, from_=12, to=128, textvariable=length, width=6).pack(side="right")
        value = ttk.Entry(panel, textvariable=secret, show="\u2022", style="Field.TEntry")
        value.pack(fill="x", pady=(0, 12))
        def make():
            try: secret.set(generate_password(int(length.get())))
            except (ValueError, VaultError) as error: messagebox.showerror("Password generator", str(error), parent=window)
        def copy():
            try: self.clipboard.copy(secret.get())
            except (VaultError, tk.TclError) as error: messagebox.showerror("Password generator", str(error), parent=window)
        def close():
            secret.set("")
            self.generators[:] = [(w, v) for w, v in self.generators if w is not window]
            window.destroy()
        def use():
            if not self._ensure_session():
                if window.winfo_exists(): close()
                return
            self.password.set(secret.get())
            self._hide_password()
            close()
        buttons = tk.Frame(panel, bg=WHITE)
        buttons.pack(fill="x", pady=(0, 12))
        ttk.Button(buttons, text="Generate", command=make, style="Primary.TButton").pack(side="left")
        ttk.Button(buttons, text="Copy", command=copy, style="Quiet.TButton").pack(side="left", padx=6)
        ttk.Button(buttons, text="Show / hide", command=lambda: value.configure(show="" if value.cget("show") else "\u2022"),
                   style="Quiet.TButton").pack(side="left")
        if use_entry:
            ttk.Button(panel, text="Use in entry", command=use, style="Primary.TButton").pack(fill="x")
        self.label(panel, "Copy clears after 30 seconds if unchanged.", 8, MUTED).pack(anchor="w", pady=(8, 0))
        window.protocol("WM_DELETE_WINDOW", close)
        make()

    def close(self):
        self.root.after_cancel(self.tick_timer)
        try:
            self.lock()
        finally:
            self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="Optional local desktop interface for Project 2.")
    parser.add_argument("--vault", type=Path, default=Path(__file__).with_name("vault.json"))
    args = parser.parse_args()
    root = tk.Tk()
    VaultApp(root, args.vault)
    root.mainloop()


if __name__ == "__main__":
    main()
