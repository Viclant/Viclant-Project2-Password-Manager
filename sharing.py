"""Optional offline sharing of one entry with RSA-OAEP and AES-GCM.

The RSA files belong to the sharing recipient. They are not the vault's AES key:
the vault encryption key is still derived from its master password in memory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import Any

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_PACKAGE_BYTES = 1024 * 1024
MAX_ENTRY_BYTES = 64 * 1024
MAX_KEY_BYTES = 64 * 1024
_FORMAT = "epita-password-share"
_SUITE = "RSA-OAEP-SHA256+AES-256-GCM"
_OAEP_LABEL = b"epita-password-share/v1/key"
_PACKAGE_FIELDS = {
    "format", "version", "suite", "recipient_sha256", "wrapped_key", "nonce", "ciphertext"
}


class SharingError(Exception):
    """A safe, user-facing failure of an optional sharing operation."""


def _read_limited(path: str | Path, limit: int) -> bytes:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as exc:
        raise SharingError("Cannot read the requested sharing file.") from exc
    if len(data) > limit:
        raise SharingError("Sharing file exceeds the allowed size.")
    return data


def _check_output(path: str | Path) -> Path:
    destination = Path(path)
    if destination.exists() or destination.is_symlink():
        raise SharingError("Output already exists; choose a different path.")
    if not destination.parent.is_dir():
        raise SharingError("The output folder must already exist.")
    return destination


def _write_exclusive(path: str | Path, data: bytes) -> None:
    """Publish a complete file atomically without replacing an existing path.

    A same-directory temporary file is linked to the final name only after it
    has been flushed. On POSIX its mode is 0600; Windows uses the user's ACLs.
    The operation fails closed if the filesystem does not support hard links.
    """
    destination = _check_output(path)
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".share-", suffix=".tmp", dir=destination.parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination)
    except FileExistsError as exc:
        raise SharingError("Output already exists; choose a different path.") from exc
    except OSError as exc:
        raise SharingError("Could not safely write the sharing output.") from exc
    finally:
        if temporary is not None:
            try:
                Path(temporary).unlink()
            except OSError:
                pass


def _check_passphrase(passphrase: bytes) -> None:
    if not isinstance(passphrase, bytes) or not 12 <= len(passphrase) <= 1023:
        raise SharingError("Use a separate sharing-key passphrase between 12 and 1023 bytes.")


def _fingerprint(key: rsa.RSAPublicKey) -> str:
    encoded = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(encoded).hexdigest()


def _check_rsa_key(key: Any, private: bool = False) -> None:
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key, expected) or not 3072 <= key.key_size <= 8192:
        raise SharingError("Sharing requires an RSA key between 3072 and 8192 bits.")


def _entry_bytes(entry: Any) -> bytes:
    if not isinstance(entry, dict) or set(entry) != {"site", "username", "password"}:
        raise SharingError("Share exactly one site, username and password entry.")
    for field in ("site", "username", "password"):
        if not isinstance(entry[field], str) or len(entry[field]) > 4096:
            raise SharingError("Entry fields must be strings of at most 4096 characters.")
    if not entry["site"] or not entry["password"]:
        raise SharingError("The entry must have a site and a password.")
    try:
        encoded = json.dumps(
            entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except UnicodeError as exc:
        raise SharingError("Entry contains invalid text.") from exc
    if len(encoded) > MAX_ENTRY_BYTES:
        raise SharingError("Entry exceeds the allowed size.")
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise ValueError("Non-finite JSON constant")


def _json_load(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SharingError("Invalid sharing data.") from exc


def _header(recipient_sha256: str) -> dict[str, Any]:
    return {
        "format": _FORMAT, "version": 1, "suite": _SUITE,
        "recipient_sha256": recipient_sha256,
    }


def _aad(header: dict[str, Any]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
        label=_OAEP_LABEL,
    )


def _decode64(value: Any, minimum: int, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise SharingError("Invalid sharing data.")
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SharingError("Invalid sharing data.") from exc
    if not minimum <= len(result) <= maximum:
        raise SharingError("Invalid sharing data.")
    return result


def generate_keypair(
    private_path: str | Path, public_path: str | Path, passphrase: bytes
) -> None:
    """Make a recipient's RSA-3072 pair; never write an unencrypted private key.

    Each file is published atomically. The two files are not one filesystem
    transaction; an I/O failure after the first publication can leave one new
    (complete) key file. Existing output paths are never replaced.
    """
    _check_passphrase(passphrase)
    private_destination = _check_output(private_path)
    public_destination = _check_output(public_path)
    if private_destination.resolve() == public_destination.resolve():
        raise SharingError("Private and public key paths must be different.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_exclusive(private_destination, private_pem)
    _write_exclusive(public_destination, public_pem)


def encrypt_entry(
    entry: dict[str, str], recipient_public_path: str | Path, output_path: str | Path
) -> None:
    """Encrypt one entry for a verified recipient public key, without networking."""
    destination = _check_output(output_path)
    plaintext = _entry_bytes(entry)
    try:
        recipient = serialization.load_pem_public_key(
            _read_limited(recipient_public_path, MAX_KEY_BYTES)
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SharingError("Cannot read an RSA public key.") from exc
    _check_rsa_key(recipient)
    header = _header(_fingerprint(recipient))
    entry_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(entry_key).encrypt(nonce, plaintext, _aad(header))
    wrapped = recipient.encrypt(entry_key, _oaep())
    package = {
        **header, "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    _write_exclusive(
        destination, (json.dumps(package, indent=2, sort_keys=True) + "\n").encode("ascii")
    )


def decrypt_entry(
    package_path: str | Path, recipient_private_path: str | Path, passphrase: bytes
) -> dict[str, str]:
    """Return the one entry only if its recipient, wrapped key and GCM tag verify."""
    _check_passphrase(passphrase)
    package = _json_load(_read_limited(package_path, MAX_PACKAGE_BYTES))
    if not isinstance(package, dict) or set(package) != _PACKAGE_FIELDS:
        raise SharingError("Invalid sharing package fields.")
    if (package["format"] != _FORMAT or type(package["version"]) is not int
            or package["version"] != 1 or package["suite"] != _SUITE):
        raise SharingError("Unsupported sharing package version or algorithm.")
    fingerprint = package["recipient_sha256"]
    if (not isinstance(fingerprint, str) or len(fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint)):
        raise SharingError("Invalid recipient fingerprint.")
    nonce = _decode64(package["nonce"], 12, 12)
    ciphertext = _decode64(package["ciphertext"], 16, MAX_ENTRY_BYTES + 16)
    wrapped = _decode64(package["wrapped_key"], 384, 1024)
    try:
        recipient = serialization.load_pem_private_key(
            _read_limited(recipient_private_path, MAX_KEY_BYTES), password=passphrase,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SharingError("Cannot open the encrypted private key; check its passphrase.") from exc
    _check_rsa_key(recipient, private=True)
    if _fingerprint(recipient.public_key()) != fingerprint:
        raise SharingError("This package is addressed to a different recipient key.")
    if len(wrapped) != recipient.key_size // 8:
        raise SharingError("Invalid wrapped-key length.")
    try:
        entry_key = recipient.decrypt(wrapped, _oaep())
        if len(entry_key) != 32:
            raise ValueError("Invalid AES key length")
        plaintext = AESGCM(entry_key).decrypt(
            nonce, ciphertext, _aad(_header(fingerprint)),
        )
    except (ValueError, InvalidTag) as exc:
        raise SharingError("Cannot decrypt share: the wrapped key or ciphertext was damaged.") from exc
    entry = _json_load(plaintext)
    _entry_bytes(entry)
    return entry
