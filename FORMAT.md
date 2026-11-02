# Vault format and file handling


The outer JSON contains exactly `header`, `nonce` and `ciphertext`. The header
contains the version, algorithm settings, public salt and Argon2 verifier. The
encrypted inner JSON contains `entries`. Base64 is only an encoding for binary
values; **it does not provide encryption**.

The reader checks file size, fields and both sets of Argon2 parameters before
expensive work. It rejects duplicate JSON keys and invalid encodings. This stops
an edited header from requesting an enormous Argon2 allocation. Version 1 accepts
only our fixed parameters; changing them requires a deliberate format change.

Limits: 1000 entries, 1 MiB of serialized plaintext and a 2 MiB vault file.

Entry contents are written only as ciphertext, including in temporary files;
the serialized document also includes the public header and nonce. Updates use a flushed
same-directory temporary file and `os.replace`; an ordinary write failure keeps
the previous vault. Initial creation uses exclusive creation, so it cannot replace
an existing file. A crash during first creation can leave an incomplete file,
which is rejected on unlock. This is not a transactional database or a guarantee
against every power-loss/filesystem failure.

A `.lock` file contains only a process ID and prevents two instances overwriting
one another's changes. If the process crashes, the lock may remain. Close all
vault processes first, confirm the stored process is no longer using it, then
remove **only** that stale `.lock` file. The program never silently breaks a lock.
Keep encrypted backups. Deletion removes an entry from the new encrypted vault;
it cannot erase old backups, filesystem snapshots or disk history securely.
