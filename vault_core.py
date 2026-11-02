"""Small local vault: Argon2id verification/KDF and AES-256-GCM storage."""

import base64
import binascii
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import string
import tempfile

from argon2 import PasswordHasher, Type, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


PARAMETERS = {"name": "argon2id", "memory_kib": 65536, "iterations": 3,
              "parallelism": 4, "key_bytes": 32}
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                    hash_len=32, salt_len=16, type=Type.ID)
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 1024 * 1024
ALPHABET = string.ascii_letters + string.digits + string.punctuation


class VaultError(Exception):
    """A safe, user-facing error: no secrets in exception messages."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VaultError("Invalid file: duplicate JSON key.")
        result[key] = value
    return result


def parse_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise VaultError("Invalid or damaged vault JSON.") from error


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def unb64(value, length=None):
    if not isinstance(value, str):
        raise VaultError("Invalid vault encoding.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise VaultError("Invalid vault encoding.") from error
    if b64(raw) != value or (length is not None and len(raw) != length):
        raise VaultError("Invalid vault field length or encoding.")
    return raw


def check_password(password, *, creating=False):
    if not isinstance(password, str) or not password or len(password.encode("utf-8")) > 1024:
        raise VaultError("Password must contain 1-1024 UTF-8 bytes.")
    if creating and len(password) < 12:
        raise VaultError("Use a master passphrase of at least 12 characters.")


def derive_key(password, salt):
    # This is separate from the stored verification hash, with its own salt.
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4,
                    memory_cost=65536).derive(password.encode("utf-8"))


def validate_header(header):
    if not isinstance(header, dict) or set(header) != {"format", "version", "cipher", "password_hash", "kdf"}:
        raise VaultError("Invalid vault header.")
    if (header["format"] != "epita-password-vault" or
            type(header["version"]) is not int or header["version"] != 1 or
            header["cipher"] != "aes-256-gcm"):
        raise VaultError("Unsupported vault format/version.")
    kdf = header["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != set(PARAMETERS) | {"salt"}:
        raise VaultError("Invalid KDF settings.")
    for name, expected in PARAMETERS.items():
        if type(kdf[name]) is not type(expected) or kdf[name] != expected:
            raise VaultError("Unsupported KDF settings; no expensive operation was started.")
    unb64(kdf["salt"], 16)
    encoded = header["password_hash"]
    if not isinstance(encoded, str) or len(encoded) > 200:
        raise VaultError("Invalid master-password verifier.")
    try:
        p = extract_parameters(encoded)
    except (InvalidHashError, ValueError) as error:
        raise VaultError("Invalid master-password verifier.") from error
    if (p.type != Type.ID or p.version != 19 or p.memory_cost != 65536 or
            p.time_cost != 3 or p.parallelism != 4 or p.salt_len != 16 or p.hash_len != 32):
        raise VaultError("Unsupported verifier parameters; no expensive operation was started.")


def validate_entries(entries):
    if not isinstance(entries, dict) or len(entries) > 1000:
        raise VaultError("Invalid entries or too many entries (maximum 1000).")
    for site, item in entries.items():
        if (not isinstance(site, str) or not site.strip() or len(site) > 255 or
                not isinstance(item, dict) or set(item) != {"username", "password"}):
            raise VaultError("Invalid entry.")
        for field, maximum in [("username", 255), ("password", 4096)]:
            if not isinstance(item[field], str) or not item[field] or len(item[field]) > maximum:
                raise VaultError("Invalid entry field.")


@contextmanager
def vault_lock(path):
    path = Path(path)
    if not path.parent.is_dir() or path.is_symlink():
        raise VaultError("Use a regular vault file in an existing directory.")
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise VaultError("Vault is locked. Close the other process; see README for stale-lock recovery.") from error
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        lock.unlink(missing_ok=True)


def write_encrypted(path, raw, *, creating=False):
    """Entries reach disk as ciphertext; the header and nonce remain public."""
    path = Path(path)
    if len(raw) > MAX_FILE_BYTES:
        raise VaultError("Vault is too large.")
    if creating:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return
    fd, temporary = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Vault:
    def __init__(self, path, header, key, entries):
        self.path, self.header, self.key, self.entries = Path(path), header, key, entries

    def save(self, *, creating=False):
        validate_entries(self.entries)
        plain = canonical({"entries": self.entries})
        if len(plain) > MAX_PLAINTEXT_BYTES:
            raise VaultError("Vault plaintext is too large (maximum 1 MiB).")
        nonce = secrets.token_bytes(12)  # A fresh nonce for every write.
        encrypted = AESGCM(self.key).encrypt(nonce, plain, canonical(self.header))
        document = {"header": self.header, "nonce": b64(nonce), "ciphertext": b64(encrypted)}
        write_encrypted(self.path, canonical(document) + b"\n", creating=creating)

    def add(self, site, username, password):
        item = {"username": username, "password": password}
        validate_entries({site: item})
        if site in self.entries:
            raise VaultError("Site already exists. Delete it first if you want to replace it.")
        self.entries[site] = item

    def get(self, site):
        if site not in self.entries:
            raise VaultError("No entry for that site.")
        return {"site": site, **self.entries[site]}

    def delete(self, site):
        self.get(site)
        del self.entries[site]


def initialize(path, password):
    check_password(password, creating=True)
    with vault_lock(path):
        if Path(path).exists():
            raise VaultError("Vault already exists; init will not overwrite it.")
        salt = secrets.token_bytes(16)
        header = {"format": "epita-password-vault", "version": 1, "cipher": "aes-256-gcm",
                  "password_hash": PH.hash(password), "kdf": {**PARAMETERS, "salt": b64(salt)}}
        key = derive_key(password, salt)
        Vault(path, header, key, {}).save(creating=True)


@contextmanager
def open_vault(path, password):
    check_password(password)
    with vault_lock(path):
        if Path(path).is_symlink():
            raise VaultError("Refusing a symbolic-link vault.")
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise VaultError("Vault exceeds the 2 MiB file limit.")
        document = parse_json(raw)
        if not isinstance(document, dict) or set(document) != {"header", "nonce", "ciphertext"}:
            raise VaultError("Invalid vault document.")
        header = document["header"]
        validate_header(header)  # Check bounds BEFORE either Argon2 call.
        nonce = unb64(document["nonce"], 12)
        ciphertext = unb64(document["ciphertext"])
        if not 16 <= len(ciphertext) <= MAX_PLAINTEXT_BYTES + 16:
            raise VaultError("Invalid ciphertext length.")
        try:
            PH.verify(header["password_hash"], password)
        except (VerificationError, InvalidHashError) as error:
            raise VaultError("Wrong master password or damaged verifier. Vault was not changed.") from error
        key = derive_key(password, unb64(header["kdf"]["salt"], 16))
        del password  # A GUI may keep this context alive; do not retain the master.
        try:
            plain = AESGCM(key).decrypt(nonce, ciphertext, canonical(header))
        except InvalidTag as error:
            raise VaultError("Vault authentication failed: file was modified or damaged. Nothing was decrypted.") from error
        payload = parse_json(plain)
        if not isinstance(payload, dict) or set(payload) != {"entries"}:
            raise VaultError("Invalid decrypted vault structure.")
        validate_entries(payload["entries"])
        vault = Vault(path, header, key, payload["entries"])
        try:
            yield vault
        finally:
            # Python cannot promise physical zeroization of immutable objects.
            vault.entries.clear()
            vault.key = b""


def generate_password(length=20):
    if type(length) is not int or not 12 <= length <= 128:
        raise VaultError("Generated password length must be between 12 and 128.")
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation)
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if all(any(char in group for char in password) for group in groups):
            return password
