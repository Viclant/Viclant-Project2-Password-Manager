# Sharing security review - 10 November 2026

Requested scope: Liu Yunfei's sharing integration and the ten task scopes in the
supplied `DAILY_TASKS.txt`, `RESPONSIBILITY.txt` and `timeline.json`.

Base: remote `main` at `22d3c79e1ba38404e42dfda58ab9a6681221647a`, including
the existing core, GUI and core review history. Working branch: `liuyunfei`.
All work described here was performed on **10 November 2026 (Europe/Paris)**.
The October/November dates below identify planned scopes, not execution dates.
This is a Codex-assisted integration and review requested by the user; it does
not claim that a named member independently authored the supplied code or has
personally demonstrated their understanding. The existing configured Git
identity and authenticated GitHub SSH account are both `abrgrar`.

## Changes and provenance

- Imported `sharing.py`, `tests/test_sharing.py` and
  `tools/verify_submission.py` from the supplied stage-two `payload/`.
- Added `keygen`, `share` and `open-share` to the current `vault.py`. Preserved
  all seven original commands, prompts, JSON output and error handling.
- Extended the current README with sharing usage, public-key verification,
  private-key passphrase guidance, cryptographic rationale and acceptance checks.
  Preserved the current CLI, GUI, installation and security-limit documentation.
- Added seven CLI integration tests in `tests/test_sharing_cli.py` using real
  RSA/GCM and disposable files. Only their secret-input prompts are mocked.
- Left `vault_core.py`, the GUI, dependency pins and other members' notes unchanged.
- Recorded current file hashes and reference-file provenance separately in
  [integration-files.json](sharing-2026-11-10/integration-files.json); the old
  package manifest and expected hashes are not rewritten to bypass checks.

## Task completion checklist

Every row below was checked on 10 November. These ten scopes are covered by
this integration and its recorded checks; they do not require ten historical
or empty commits.

| Planned task ID | Actual work and evidence |
| --- | --- |
| `2026-10-31-liu` | Reviewed the distinct roles of master password, verifier, salts, nonce and derived key, documented below. Existing core tests check independent salts, password/salt-bound derivation, encrypted persistence and fresh nonces; all passed. |
| `2026-11-01-liu` | Reviewed the fixed package fields, version, suite, recipient key and AAD. README explains trusted-channel public-key verification, substitution risk, and PEM-file hash versus DER-key fingerprint. |
| `2026-11-02-liu` | Ran real RSA-OAEP/AES-GCM round trips in module tests, CLI integration tests, acceptance checks and real CLI subprocesses. |
| `2026-11-03-liu` | Integrated sharing, the three CLI commands, sharing tests and acceptance tool into the current core/GUI tree; the complete suite and acceptance checks passed. |
| `2026-11-04-liu` | Ran wrong-recipient, wrong-passphrase, ciphertext/nonce/wrapped-key tampering, malformed/oversized package, weak-key and no-overwrite tests. Failed CLI decryption prints no entry plaintext. |
| `2026-11-05-liu` | Updated and checked sharing examples, separate private-key passphrase guidance and independent public-key verification. Executed the macOS CLI workflow and PEM-file hash command. Windows launcher syntax was inspected but not executed on this Mac. |
| `2026-11-06-liu` | Reviewed memory, clipboard, disk and lock boundaries below. Existing GUI widget, fake-clipboard and session tests all passed; the new share command also respects the GUI vault lock. |
| `2026-11-07-liu` | Used only invented data and temporary directories to test selected-entry sharing, successful receipt, wrong keys/passphrases and tampering. A separate PTY run exercised actual hidden-input CLI subprocesses. |
| `2026-11-08-liu` | Compared the final README with current core, sharing and GUI behavior. Corrected the distinction between PEM-file hashes and DER fingerprints and stated that sender identity is not authenticated. |
| `2026-11-09-liu` | Reviewed the final explicit submission file list, ignore rules and diff. No vault, PEM/private key, share output, environment, cache or working-package control file is included. The final submission report will provide the actual publication SHA and remote branch verification after the push. |

## Cryptographic review

The master password is an input secret, not an on-disk field. `PH.hash/verify`
uses an Argon2id verifier with its own random 16-byte salt. The separate KDF
uses another random 16-byte salt and derives a 32-byte AES key from the entered
password. The public verifier is not the AES key; neither salt is secret. There
is no persisted vault AES-key file. Verification and derivation are separate
operations, not a claim of twice the offline-guessing protection.

Each vault save requests a fresh public 12-byte nonce. AES-GCM authenticates
the public header as AAD and rejects changes before returning plaintext.
Core tests exercised wrong passwords, changed authenticated metadata and
exactly one changed ciphertext-file byte.

Each share uses an independent random AES-256 entry key and nonce, never the
vault's derived key. RSA-3072/OAEP-SHA256 wraps the entry key. The sharing private
key is encrypted PKCS8; a separate long passphrase is advised. Equality with the
master password is not checked by the implementation. The package has strict
field, version, size and key checks. The package's SHA-256 DER public-key
fingerprint binds decryption to that key, but does not establish the receiver's
identity. The README's `Get-FileHash`/`shasum` hashes PEM-file bytes instead;
these values cannot be compared directly. Public-key identity needs a trusted
channel. There is no sender signature or sender authentication.

Sharing leaves the source vault unchanged and reveals only the selected entry
after successful receipt. The receiver can copy that password. Sharing output
publication uses complete temporary files and hard links without replacing an
existing destination. The two key outputs are not one atomic transaction.

## GUI, memory and disk boundaries

While unlocked, the GUI keeps decrypted entries and the derived key in memory
and holds the vault file lock. It clears the master input and does not keep the master password
in its suspended vault context. Lock, expiration and close release the session,
key/entry references and lock; Python does not guarantee physical zeroization.
The default idle timeout is 120 seconds, checked on events and operations as well
as timer ticks. Reaching the deadline cannot be undone by a new input event.

Password reveal is remasked after 15 seconds. Clipboard cleanup attempts to clear
only its own unchanged copied value after 30 seconds or locking; it preserves
new content and bounds contention retries. Tests use a fake clipboard. They do
not establish that OS clipboard history is erased or that another process cannot
read the clipboard. Killing the app can prevent cleanup.

Vault temporary files contain encrypted entries with public metadata. Sharing
private PEMs are encrypted. POSIX outputs use `0600`; Windows inherits directory
ACLs. The vault lock coordinates cooperating GUI/CLI instances, not malicious
processes. Malware, weak passphrases, screen/memory access, rollback, deletion and
availability are outside these protections.

## Actual checks and results

Fresh project `.venv`: macOS arm64, Python 3.14.3, Tcl/Tk 8.6,
argon2-cffi 25.1.0 and cryptography 50.0.2. Dependency installation succeeded and
`pip check` reported no broken requirements. Exact versions are in
[dependencies.txt](sharing-2026-11-10/dependencies.txt).

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python tools/verify_submission.py
```

- **82 tests passed, zero failures/errors/skips**, in 7.306 seconds, exit code 0.
  This includes 57 existing core/GUI tests, 18 imported sharing tests and seven
  new CLI sharing integration tests. See [unit-tests.txt](sharing-2026-11-10/unit-tests.txt).
- **9/9 acceptance checks passed**, exit code 0, using normal Python (without
  `-O`, which would disable the acceptance tool's assertions). See
  [acceptance.txt](sharing-2026-11-10/acceptance.txt).
- Separate real CLI subprocesses ran under PTYs with no mocked `getpass`:
  `init`, two `add` operations, `list`, `keygen`, `share`, `open-share`, wrong
  key passphrase, altered share, `delete`, `unlock` and `gen`. Every secret prompt
  disabled terminal ECHO and did not echo its input. The receiver got exactly
  the selected entry; source vault bytes stayed unchanged. The macOS public-file
  hash command matched the actual PEM bytes. All files were disposable and no
  passwords were saved in the log. See [interactive-smoke.txt](sharing-2026-11-10/interactive-smoke.txt).

The macOS sandbox aborted Tk initialization before a window could be created;
the complete test suite was therefore run outside that sandbox and all actual
Tk widget tests executed successfully. No system clipboard was used. This run
does not claim a new Windows runtime test, real teammate key verification,
personal oral-defense readiness or submission through the course platform.

## Submission scope

The submission consists of the six feature/documentation/test paths listed in
the integration manifest, this review, the integration manifest and the four
actual evidence logs linked above. The pre-existing local working packages,
their control files, the project `.venv` and generated caches remain outside
the submission. The source package's planned dates remain provenance, not
backdated Git history. Remote publication and merging into `main` are separate
states: pushing `liuyunfei` alone does not mean the main branch has changed.
