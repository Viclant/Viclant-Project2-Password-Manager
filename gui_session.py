"""Short-lived unlocked state for the desktop UI, using the existing vault format.

This module contains no widgets, clipboard integration or stored master password.
The core context manager owns the file lock and clears its references on close.
"""

from copy import deepcopy
import math
from pathlib import Path
import time

from vault_core import VaultError, initialize, open_vault, validate_entries


class VaultSession:
    def __init__(self, timeout_seconds=120, clock=time.monotonic):
        if (isinstance(timeout_seconds, bool) or
                not isinstance(timeout_seconds, (int, float)) or
                not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ValueError("The session timeout must be a positive number.")
        self.timeout_seconds = timeout_seconds
        self._clock = clock
        self._context = None
        self._vault = None
        self.path = None
        self.last_activity = None

    @property
    def unlocked(self):
        return self._vault is not None

    def create(self, path, master):
        self.lock()
        target = Path(path).expanduser().absolute()
        initialize(target, master)
        self.unlock(target, master)

    def unlock(self, path, master):
        self.lock()
        target = Path(path).expanduser().absolute()
        context = open_vault(target, master)
        # Do not retain a failed context or the supplied master password.
        vault = context.__enter__()
        self._context = context
        self._vault = vault
        self.path = target
        self.last_activity = self._clock()

    def lock(self):
        context = self._context
        self._context = None
        self._vault = None
        self.path = None
        self.last_activity = None
        if context is not None:
            context.__exit__(None, None, None)

    def expire_if_idle(self):
        if (self.unlocked and
                self._clock() - self.last_activity >= self.timeout_seconds):
            self.lock()
            return True
        return False

    def touch(self):
        # An event arriving after the deadline cannot revive an expired session.
        if self.expire_if_idle() or not self.unlocked:
            return False
        self.last_activity = self._clock()
        return True

    def _require_unlocked(self):
        if self.expire_if_idle():
            raise VaultError("Vault auto-locked after inactivity. Unlock it again.")
        if not self.unlocked:
            raise VaultError("Unlock the vault first.")
        self.last_activity = self._clock()
        return self._vault

    def rows(self, query=""):
        vault = self._require_unlocked()
        if not isinstance(query, str):
            raise VaultError("Search text must be a string.")
        needle = query.casefold()
        return [
            {"site": site, "username": item["username"]}
            for site, item in sorted(vault.entries.items(), key=lambda pair: pair[0].casefold())
            if needle in site.casefold() or needle in item["username"].casefold()
        ]

    def get(self, site):
        # Core get() returns a new dictionary, not a mutable stored entry.
        return self._require_unlocked().get(site)

    def _mutate_and_save(self, mutation):
        vault = self._require_unlocked()
        before = deepcopy(vault.entries)
        try:
            mutation(vault)
            vault.save()
        except BaseException:
            # Core writes are atomic. Keep the UI's memory consistent if saving fails.
            vault.entries.clear()
            vault.entries.update(before)
            raise
        self.last_activity = self._clock()

    def save_entry(self, site, username, password, original_site=None):
        self._require_unlocked()
        if not isinstance(site, str):
            raise VaultError("Site must be a string.")
        validate_entries({site: {"username": username, "password": password}})

        def save(vault):
            if original_site is not None:
                vault.get(original_site)
                if site != original_site and site in vault.entries:
                    raise VaultError("Site already exists. Choose a different name.")
                del vault.entries[original_site]
            vault.add(site, username, password)

        self._mutate_and_save(save)

    def delete(self, site):
        self._mutate_and_save(lambda vault: vault.delete(site))
