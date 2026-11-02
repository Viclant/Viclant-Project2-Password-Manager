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
