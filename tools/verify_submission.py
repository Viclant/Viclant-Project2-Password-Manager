"""Run the teacher's acceptance checks on disposable, invented data."""

from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vault_core import VaultError, b64, derive_key, generate_password, initialize, open_vault, unb64
from sharing import SharingError, decrypt_entry, encrypt_entry, generate_keypair


def main():
    print("Project 2 acceptance run")
    print("UTC:", datetime.now(timezone.utc).isoformat())
    print("Python:", platform.python_version())
    print("Only disposable directories and invented credentials are used.")
    checks = []

    def passed(name):
        checks.append(name)
        print("PASS:", name)

    with tempfile.TemporaryDirectory(prefix="project2-check-") as directory:
        folder = Path(directory)
        path = folder / "demo.vault.json"
        master = "Demo-only master phrase 2026!"
        entry_password = "Demo-only-entry-password!"
        initialize(path, master)
        doc = json.loads(path.read_text())
        assert doc["header"]["password_hash"].startswith("$argon2id$")
        passed("master verifier is an Argon2id string")
        before = path.read_bytes()
        try:
            with open_vault(path, "definitely wrong password"):
                raise AssertionError("wrong password accepted")
        except VaultError:
            pass
        assert path.read_bytes() == before
        passed("wrong master password rejected without changing the file")
        with open_vault(path, master) as vault:
            vault.add("demo.example", "demo-user", entry_password)
            vault.save()
        with open_vault(path, master) as vault:
            entry = vault.get("demo.example")
            assert entry["password"] == entry_password
        passed("add/list/get persist after a separate unlock")
        raw = path.read_bytes()
        doc = json.loads(raw)
        key = derive_key(master, unb64(doc["header"]["kdf"]["salt"]))
        for secret in [master.encode(), b"demo.example", b"demo-user", entry_password.encode(), key, b64(key).encode()]:
            assert secret not in raw
        assert {p.name for p in folder.iterdir()} == {"demo.vault.json"}
        passed("no plaintext entries/master, stored AES key, or key file")
        changed = bytearray(raw)
        index = raw.index(b'"ciphertext":"') + len(b'"ciphertext":"')
        changed[index] = ord("A") if changed[index] != ord("A") else ord("B")
        assert sum(a != b for a, b in zip(raw, changed)) == 1
        damaged = folder / "damaged.vault.json"
        damaged.write_bytes(changed)
        try:
            with open_vault(damaged, master):
                raise AssertionError("tampered ciphertext accepted")
        except VaultError as error:
            assert "authentication failed" in str(error)
        passed("exactly one changed vault-file byte fails AES-GCM authentication loudly")
        with open_vault(path, master) as vault:
            vault.delete("demo.example")
            vault.save()
        with open_vault(path, master) as vault:
            assert not vault.entries
        passed("delete persists after reopening")
        assert len(generate_password(24)) == 24
        passed("secrets generator produces the requested length")
        private, public = folder / "recipient-private.pem", folder / "recipient-public.pem"
        package = folder / "entry.share.json"
        passphrase = b"Separate-demo-sharing-passphrase!"
        generate_keypair(private, public, passphrase)
        encrypt_entry(entry, public, package)
        assert decrypt_entry(package, private, passphrase) == entry
        assert b"ENCRYPTED PRIVATE KEY" in private.read_bytes()
        assert entry_password.encode() not in package.read_bytes()
        passed("bonus: one entry shared with RSA-OAEP + AES-GCM; private PEM is encrypted")
        altered = json.loads(package.read_text())
        value = bytearray(unb64(altered["ciphertext"]))
        value[-1] ^= 1
        altered["ciphertext"] = b64(bytes(value))
        package.write_text(json.dumps(altered), encoding="utf-8")
        try:
            decrypt_entry(package, private, passphrase)
            raise AssertionError("tampered share accepted")
        except SharingError:
            pass
        passed("bonus: changed shared ciphertext is rejected")
    print(f"Result: {len(checks)}/{len(checks)} acceptance checks passed.")


if __name__ == "__main__":
    main()
