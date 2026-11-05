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
