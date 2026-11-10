# Core and CLI review - 2 November 2026

Requested scope: Wu Yanlan's core/CLI tasks through 2 November 2026.
Base: `main` at `2f539581ab3d213a938feed46bd1ef8dd4452d98`.

All work below was executed on **2 November 2026**. The 31 October and
1 November dates identify planned task scopes, not earlier execution dates or
claims of independent manual authorship.

## Changes

- Integrated the stage-one core, CLI, dependency list, launchers, tests and
  documentation from the supplied reference package. Preserved the existing license.
- Removed unreachable duplicate command dispatch after `return 0` in `vault.py`,
  including a leftover reference to a later sharing function.
- Corrected fresh-checkout installation instructions and clarified that entries
  are encrypted while the stored header and nonce remain public.
- Added five behavioral tests for master-password boundaries, unavailable hidden
  input, update synchronization failure, initial-creation synchronization failure
  and CLI save-failure reporting.

## Actual environment and commands

Windows; Python 3.13.13; a newly created local `.venv`.
Installed packages: argon2-cffi 25.1.0, argon2-cffi-bindings 26.1.0,
cryptography 50.0.2, cffi 2.1.1 and pycparser 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe vault.py --help
.\vault.cmd --help
.\.venv\Scripts\python.exe -m pip freeze
```

Installation succeeded. Both help commands succeeded and listed only the seven
stage-one commands: `init`, `unlock`, `add`, `list`, `get`, `delete`, and `gen`.
The full test run returned exit code 0:

```text
Ran 27 tests in 10.862s
OK
```

The original 22 reference tests remain present; five additional tests account
for the new total.

## Observed results by planned scope

| Planned scope | Actual checks and observations on 2 November |
| --- | --- |
| 31 October: core and CLI integration | The complete suite passed, including real Argon2id/AES-GCM calls, CLI CRUD, persistence after reopening, password generation, tampering rejection and input bounds. Both CLI help entry points succeeded. |
| 1 November: master password and input | Correct-password operations passed. Wrong passwords returned errors without changing the vault. Reinitialization preserved the existing file. Confirmation mismatch, empty/short/overlong UTF-8 master passwords and unavailable hidden input created no files. CLI unit tests use controlled input fixtures. |
| 2 November: atomic saves and locks | Simulated replacement and update synchronization failures preserved the original vault, cleaned temporary files/locks and allowed reopening. Initial-creation synchronization failure removed the incomplete new file and lock; retry succeeded. An existing lock was preserved and access refused. CLI save failure returned nonzero, no success message and no test secrets. |

A separate real interactive terminal check ran:

```powershell
.\.venv\Scripts\python.exe vault.py --vault ..\wu-yanlan-smoke.vault.json init
```

It used an invented passphrase and a disposable file outside the repository.
Both master-password prompts accepted input without echoing the entered value;
initialization completed with exit code 0. This checks the real hidden-input
path separately from the mocked-input unit tests.

## Limits and remaining scope

Injected `fsync` and `os.replace` errors test ordinary failure handling, not
every physical disk or power-loss scenario. A process crash can leave a stale
lock; first-creation interruption can leave an incomplete file, as described in
`FORMAT.md`. The existing-lock test is not a multi-process stress test.
Python cannot guarantee physical zeroization of secrets.

This branch contains the core and CLI. Public-key sharing, GUI integration and
course-platform submission are later scopes. No real vault, credentials, private
keys, environment directory or member-package control files are included.

## Follow-up checks on 6 November 2026

The dates in the first column are the scheduled review slots. All checks in this
section ran on 6 November in the Europe/Paris time zone, using Windows,
Python 3.13.13, argon2-cffi 25.1.0 and cryptography 50.0.2.

| Planned slot | Result on 6 November |
| --- | --- |
| 3 November, sharing and CLI regression | The local sharing snapshot passed 45 unit tests and all 9 acceptance checks. CLI help listed all seven original commands and `keygen`, `share` and `open-share`. A 15-call smoke test exercised the original commands, a share round trip, wrong master and private-key passwords, and refusal to overwrite existing files. Sharing left the vault unchanged. |
| 4 November, tampering and boundaries | All 27 tests on the branch snapshot passed. Coverage included altered ciphertext, tag, nonce, authenticated verifier and KDF salt, invalid encodings and rejection of excessive KDF parameters before cryptography. Separate checks accepted a 12-character master, a 1024-byte UTF-8 master, 1000 entries and exactly 1 MiB of serialized plaintext. One below the minimum or one above each maximum was rejected. Oversized saves preserved the original file bytes. |
| 5 November, CLI instructions and errors | The documented default and named-vault flows passed with simulated prompts and real temporary vaults. Reinitialization, a wrong master and a missing entry returned exit code 1 without changing the vault. The Windows launcher passed `--help` and generated 24 characters with `gen --length 24`. It returned 1 for length 11 and 2 when `--vault` was placed after the command. README now explains setup, vault paths, output and error recovery. |
| 6 November, GUI and CLI compatibility | The local combined snapshot passed 74 unit tests with no skips and all 9 acceptance checks. Using Tk 8.6 widgets in a hidden window, the GUI read and edited an entry created by the CLI. While the GUI held the lock, the CLI refused access and the file was unchanged. After the GUI released the lock, the CLI read the edited entry. The header was preserved and the nonce changed. Neither fixture password appeared in the stored file, and no lock file remained. |

The branch snapshot was Git commit `f01077d405d636339cc4aa546e6150bb428528bc`.
The sharing snapshot overlaid `vault.py`, `sharing.py`, `tests/test_sharing.py`
and `tools/verify_submission.py` from Liu Yunfei's package. The combined snapshot
also overlaid `vault_gui.py`, `gui_session.py`, `tests/test_gui.py` and
`tests/test_gui_session.py` from Chen Ziming's package. These files were checked
against their package manifests. The source ZIP was
`Project2-Full-and-Three-Members-2026-10-31.zip` with SHA-256
`5d71f78bfb3e904a39e4a4767b5ea40a1fbfe51242f84a359f5900b2b2c31354`.

To rerun the suites from the corresponding snapshot, use its project Python.

```text
python -m unittest discover -s tests -v
python vault.py --help
python tools/verify_submission.py
```

The acceptance script is present in the sharing and combined snapshots. The
additional CLI smoke tests supplied invented passwords through simulated prompts.
The GUI smoke test exercised the widget handlers with disposable files.
The sharing and GUI results cover the local combinations. Both modules were
still pending integration in the remote repository when reviewed.

## Clean environment and CLI checks on 7 November 2026

The tested revision was `db02ad312a1c916827c8a20c53955dde35f027af`.
A new checkout on the Windows computer started without a `.venv` directory.
`.\Setup.cmd` created a new virtual environment with
`include-system-site-packages = false`. Both cryptography and argon2 imported
from that environment's own site-packages directory.

Python was 3.13.13 and pip was 26.0.1. Installed packages were as follows.

| Package | Version |
| --- | --- |
| argon2-cffi | 25.1.0 |
| argon2-cffi-bindings | 26.1.0 |
| cryptography | 50.0.2 |
| cffi | 2.1.1 |
| pycparser | 3.12 |

The setup, dependency checks and test commands ran from the new checkout.

```powershell
.\Setup.cmd
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip --version
.\.venv\Scripts\python.exe -m pip freeze
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\vault.cmd --help
```

Setup returned exit code 0 and pip reported `No broken requirements found.`
The complete suite passed with zero skips.

```text
Ran 27 tests in 6.677s
OK
```

A separate interactive terminal workflow used `.\vault.cmd` and a disposable
vault outside the checkout. It created the vault, added `demo.example` with a
generated 24-character password, listed and retrieved the entry, unlocked the
vault, deleted the entry and confirmed the empty list. Standalone
`gen --length 24` also returned 24 characters. Every command returned exit
code 0 and the workflow left no lock file.

The master passphrase was entered through the actual hidden prompts for these
launcher checks. The separate unit tests covered wrong passwords, confirmation
mismatch, invalid lengths and simulated save failures. The workflow used only
invented credentials and a temporary encrypted vault.

## Required-feature checklist on 8 November 2026

The review started from `b9502ffd6e8f87229d673a7af8d4e1c97250e8d7`.
Each required block was checked against its implementation, tests and the
corresponding explanation in README.

| Required block | Implementation in `vault_core.py` | Test evidence in `tests/test_vault.py` |
| --- | --- | --- |
| Master-password verification | `initialize` stores a salted Argon2id verifier using `PH.hash`. `open_vault` verifies it with `PH.verify`. | `test_wrong_master_rejected_without_changing_file`, `test_verifier_and_ciphertext_present_but_no_plaintext_or_key_file` and the CLI wrong-master test passed. |
| Derive the vault key from the master password | `derive_key` uses Argon2id to produce 32 bytes. Initialization generates a separate 16-byte KDF salt, and reopening derives the key again. | The independent-salt and reopening checks passed. The new `test_key_derivation_is_deterministic_and_bound_to_password_and_salt` passed using real Argon2id calls. |
| Encrypt and authenticate stored entries | `Vault.save` uses AES-256-GCM with a fresh 12-byte nonce and the canonical header as AAD. `open_vault` authenticates before returning entries. | Ciphertext, tag, nonce and KDF-salt tampering tests passed, together with authenticated-verifier, single-file-byte, fresh-nonce and persistence checks. |
| Generate strong passwords | `generate_password` uses `secrets.choice`, accepts lengths 12 through 128 and requires all four character classes. | Length-boundary, invalid-length, generated-entry persistence and standalone CLI generation tests passed. |

The review found a missing direct regression check for key derivation. The new
test confirms that the same password and salt produce the same 32-byte key,
while changing either input changes the result. It also checks the output type
and length for all four derivations.

The tracked delivery files include `vault_core.py`, `vault.py`,
`tests/test_vault.py`, `requirements.txt`, `Setup.cmd`, `vault.cmd`,
`README.md` and `FORMAT.md`. README explains the four choices, and FORMAT
describes the public header, encrypted entries, size limits and file handling.
All four required implementations were present in the reviewed revision.

Validation used Windows and Python 3.13.13 with argon2-cffi 25.1.0 and
cryptography 50.0.2. The existing isolated environment installed on 7 November
was reused. Imports were checked to point to the new 8 November checkout.
From that checkout the commands were as follows.

```powershell
& '..\wu-yanlan-nov07\.venv\Scripts\python.exe' -m unittest discover -s tests -v
& '..\wu-yanlan-nov07\.venv\Scripts\python.exe' vault.py --help
```

CLI help succeeded. After adding the key-derivation test, the complete suite
returned exit code 0 with zero skips.

```text
Ran 28 tests in 7.108s
OK
```

## Final core and CLI review on 9 November 2026

The tested `wu-yanlan` revision was
`7c0df7865eadaac15cd3ab8241cbd034323d995f`. The review used a new checkout on
Windows with the isolated Python 3.13.13 environment installed on 7 November.
`pip freeze` reported `argon2-cffi==25.1.0`, `argon2-cffi-bindings==26.1.0`,
`cryptography==50.0.2`, `cffi==2.1.1` and `pycparser==3.12`.

The following commands ran from the new checkout.

```powershell
$python = '..\wu-yanlan-nov07\.venv\Scripts\python.exe'
& $python --version
& $python -m pip freeze
& $python -m pip check
& $python -m unittest discover -s tests -v
& $python vault.py --help
& $python vault.py gen --length 24
git ls-files
```

`pip check` reported no broken requirements. CLI help listed the seven core
commands, and standalone generation returned 24 characters. The complete
core suite finished with exit code 0 and no skips.

```text
Ran 28 tests in 6.116s
OK
```

The tests exercised master-password rejection, key derivation, tamper
detection, encrypted persistence across reopening, save-failure recovery and
the CLI lifecycle from creation to deletion. The CLI tests supply invented
passwords through simulated prompts. The interactive hidden-input check for
the Windows launcher is recorded in the 7 November section.

The delivery contains the core and CLI sources, Windows launchers, pinned
requirements, tests, README and file format notes. The tracked-file check
found no vault files, keys, lock files, caches or virtual environment. The
file format and security limits in README and FORMAT still apply, including
loss of access if the master password is lost and the limits of protecting
secrets in process memory or terminal output.

### Integration handoff

The published `2023905333` branch at
`bc9db56b2f08f94d5f0ccda4e97d5cc141e63bf0` adds the desktop interface,
launcher and GUI tests to the same core revision. A separate checkout of
that commit passed all 57 tests with zero skips in 11.022 seconds using
`python -B -m unittest discover -s tests -v`.

The CLI-to-GUI round trip also passed on that checkout. The CLI created
an encrypted vault, Tk 8.6 widgets opened and edited it in a hidden window,
and the CLI read the updated entry after the GUI released its lock. The CLI
refused access while the GUI held the lock. Saving preserved the header and
changed the nonce. This check used simulated CLI prompts and disposable data.

At review time `main` was at `2f539581ab3d213a938feed46bd1ef8dd4452d98`
and the repository had no pull requests. The inspected remote branches did
not contain the public-key sharing module, its tests or the acceptance script.
The final team handoff still needs a combined revision and a fresh run of
its full tests and acceptance checks.

## Submission readiness on 10 November 2026

The schedule reserves 10–12 November for feedback, environment issues and
submission. This follow-up checked the published core and rehearsed the GUI
integration.

GitHub's default branch `main` and `wu-yanlan` both pointed to
`fa849eaa4b488eed26ff3ad9d0135192897f9930` at the start of the check.
On that core revision, Python 3.13.13 passed `pip check`, CLI help listed the
seven core commands, and `vault.py gen --length 24` returned 24 characters.
Representative vault, key, lock, share output, cache and virtual environment
paths matched the repository ignore rules.

The GUI commit on `2023905333` was
`bc9db56b2f08f94d5f0ccda4e97d5cc141e63bf0`. A temporary checkout of `main`
staged that commit without conflicts using
`git merge --no-commit --no-ff bc9db56b2f08f94d5f0ccda4e97d5cc141e63bf0`.
The staged tree was `72a18a724d3a71104934c199e47daac1ec927ce0`. It added the
five GUI files and retained the 9 November review from `main`.

`python -B -m unittest discover -s tests -v` on that tree completed with exit
code 0, 57 passing tests and zero skips in 11.189 seconds. The same tree also
passed the CLI-to-GUI round trip. Hidden Tk 8.6 widgets opened and edited an
encrypted vault created by the CLI. The CLI refused access while the GUI
held its lock and read back the changed entry after the lock was released.
The test used disposable data and simulated password prompts.

This was a local integration rehearsal. On GitHub, the GUI was still on
`2023905333`, with no pull request, and the public-key sharing submission
was pending. The final combined revision still needs the team's acceptance
checks after integration.
