# Project 2 - Local password manager

Group: **Wu Yanlan / Chen Ziming / Liu Yunfei**

Course: EPITA Computer Security

Due: **12 November 2026, end of day**

This is a small local Python password manager with a command-line interface and
an optional desktop interface. It supports master password verification, key
derivation, authenticated encryption and strong password generation.
There is no server, cloud storage or network request.

## Run it

### Command-line interface (required by the project)

Python **3.11 or later** is required. On a fresh Windows checkout, open PowerShell
in the project folder and run `.\Setup.cmd` to create `.venv` and install the
dependencies. The manual installation steps below also work.

```powershell
.\vault.cmd init
.\vault.cmd add github --user alice
.\vault.cmd list
.\vault.cmd get github
.\vault.cmd gen --length 24
.\vault.cmd delete github
.\vault.cmd unlock
```

`init` asks twice for a master passphrase of at least 12 characters. Use a long,
unpredictable passphrase; the length check does not make a predictable password
safe. Password input is hidden. `add` also asks twice for the entry password.

`get` deliberately displays the selected password, so use it on a private screen.
`list` prints one JSON object per entry with its site and username. Use
`add --generate` to generate and store a password. The password is displayed only
when you explicitly retrieve it with `get`. The standalone `gen` command prints
a password without adding it to a vault.

```powershell
.\vault.cmd add example --user alice --generate --length 24
.\vault.cmd get example
```

The default file is `vault.json` in the current working directory. Put
`--vault PATH` **before** the command and use the same path for subsequent
operations on that vault.

```powershell
.\vault.cmd --vault personal.vault.json init
.\vault.cmd --vault personal.vault.json add mail --user alice
```

Each CLI command is a short session. `unlock` checks and decrypts once, then exits;
it does not leave the next command unlocked. Read/write commands ask for the
master password again. The vault is not overwritten if `init` is run twice.
To replace an existing site, delete that entry and add it again.

If `init` reports that the vault already exists, use `unlock` to check that
vault or pick a new path with `--vault`. If the password or verifier is rejected,
check the path and master passphrase before trying again. For a locked vault,
close the process using it and follow the [stale lock instructions](FORMAT.md)
if the lock remains.

### Desktop interface on Windows

Use Python 3.11 or later with Tcl/Tk. In PowerShell, run these commands from the
project folder.

```powershell
.\Setup.cmd
.\GUI.cmd
```

Choose **Create vault** for a new file or **Unlock vault** for an existing one.
The launcher defaults to `vault.json` in the project folder. Use the file picker
to select a different vault, or pass its path directly to the desktop script.

```powershell
.\.venv\Scripts\python.exe .\vault_gui.py --vault .\personal.vault.json
```

The desktop interface and CLI share the same encrypted file format. Click
**Lock vault** or close the desktop window before opening the same vault with
the CLI. The desktop interface locks after two minutes of inactivity.

### Install on another computer

Copy the source repository, not the Windows `.venv`, to the other computer.
In a terminal at the repository root:

```text
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\vault.cmd --help
```

Linux/macOS:

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python vault.py init
.venv/bin/python vault.py add github --user alice
```

## Why these cryptographic choices?

### 1. Argon2id verifies the master password

`argon2-cffi.PasswordHasher` stores a salted `$argon2id$...` verification string.
Unlock calls `verify()`; the master password itself is never saved. Argon2id
requires both memory and time for each guess. SHA-256 is intentionally fast, so
a thief could test many more guesses against a SHA-256 password hash. AES is
reversible encryption, so it is the wrong tool for storing a login verifier.

We use Argon2id version 19, **64 MiB**, **3 iterations**, **4 lanes**, a **16-byte
random salt**, and a **32-byte hash**. These match the low-memory settings used
in our Class 5 work. They are an explicit setting for this teaching tool, not
a claim that every computer should use exactly these costs.

### 2. The vault key is derived, not saved beside the vault

`cryptography.hazmat.primitives.kdf.argon2.Argon2id` derives a **32-byte AES key**
from the entered master password. The KDF uses its own random 16-byte salt and
the same memory/time settings. The verifier and KDF have **independent salts**:
we do not use the public verification hash as the encryption key.

The salt and algorithm settings are public and stay in the vault header. The
master password and derived key do not. If we saved a random vault key in a file
next to the ciphertext, a thief copying both files could decrypt without knowing
the master password. Deriving it avoids that second secret file. Losing the
master password also means losing access; this project has no recovery key.

Unlock performs verification and key derivation separately. This is not twice
the offline protection: an attacker can test guesses using the stored verifier
alone. A weak master password is still a weakness.

### 3. AES-GCM provides encryption and tamper detection

`cryptography.hazmat.primitives.ciphers.aead.AESGCM` encrypts the entire entries
object, including site names, usernames and passwords. We use AES-256, a fresh
random **12-byte nonce for every save**, and the library's full **16-byte tag**.
GCM's authentication tag detects changes. Encryption without authentication could
let changed data be accepted without any warning.

The format/version, cipher, KDF settings, salt and verifier are authenticated as
**associated data (AAD)**. They are visible but cannot be changed while preserving
a valid tag. A changed ciphertext, nonce, or authenticated header is rejected;
no unauthenticated plaintext is returned. A nonce is public, but reusing one
with the same key would be dangerous. The program requests a new nonce each time.

### 4. `secrets` generates passwords

`secrets.choice` draws from the operating system's cryptographic random source.
Python's usual `random` generator is for simulation and can be predictable, so
it is unsuitable here. The generator uses the 94 printable ASCII letters, digits
and punctuation characters, with selectable length **12-128**, default **20**.
It retries until the result contains lower/uppercase letters, digits and a symbol.
Length matters more than making a short password look complicated.

## Vault file

The file has a public authenticated header and encrypted entries. Entry contents
reach disk only as ciphertext, including in temporary files; the header and nonce
remain public. Size/parameter checks happen before
expensive work. Updates use an atomic replacement and a no-overwrite process lock.
See [FORMAT.md](FORMAT.md) for the exact structure, size limits, crash behavior
and stale-lock recovery. There is no secret vault-key file.

## Security model and limits

The tool protects saved entries if somebody steals a **locked vault file**:
they obtain ciphertext and public metadata rather than the saved passwords.
The verifier and KDF slow down offline guessing; they do not prevent it.

It does **not** protect against:

- A keylogger, malware or an administrator reading the running process.
- A weak or reused master password.
- Someone reading the screen, terminal output or history after `get`, or seeing
  a password revealed in the desktop interface.
- Clipboard history. The desktop interface tries to clear an unchanged copied
  password after 30 seconds. Operating system clipboard history can retain it.
- Deleting the vault, restoring an older authentic copy, or changing the whole
  file into a different valid vault. GCM detects modifications to a protected
  record; it does not prove freshness or guarantee availability.
- Secrets left in Python-managed memory, swap or crash dumps. Python cannot
  guarantee physical zeroization. CLI sessions end after each command. The
  desktop interface keeps the decrypted session in memory while unlocked.
- Users sharing an operating-system account. POSIX new files use mode `0600`;
  Windows files inherit the directory ACL. This app does not create Windows ACLs.
  Store the vault in your private user directory on an encrypted disk.

The vault file still reveals its size, format, cryptographic settings and hash.
There is no password recovery, automatic cloud backup or breach-check API.
Network access is not needed after installing dependencies.

## Check the implementation

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe vault.py --help
```

The tests use disposable vaults and invented passwords. They check the four
required building blocks, CLI behavior, persistence, wrong passwords, tampering,
input bounds, write failures and desktop behavior. The desktop widget tests
need Tcl/Tk and a graphical session.

`vault.py` handles the CLI and `vault_core.py` handles encryption and storage.
`vault_gui.py` handles the desktop interface and `gui_session.py` manages its
vault session. See `FORMAT.md` for the file format.

See the [core and CLI review notes](docs/reviews/core-cli.md) for dated checks
and their limits.

## References

- [Project 2 requirements](https://kristenpire.github.io/epita-security-labs/project2/)
- [argon2-cffi password hashing and verification](https://argon2-cffi.readthedocs.io/en/stable/howto.html)
- [cryptography Argon2id KDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#argon2id)
- [cryptography AES-GCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Python secrets](https://docs.python.org/3/library/secrets.html)
