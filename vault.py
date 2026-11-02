"""Command-line interface. Passwords are prompted, never supplied in arguments."""

import argparse
import getpass
import json
from pathlib import Path
import sys
import warnings

from vault_core import VaultError, generate_password, initialize, open_vault


def ask_secret(prompt):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning as error:
        raise VaultError("Use an interactive terminal: hidden password input is unavailable here.") from error


def new_secret(prompt):
    value = ask_secret(prompt)
    if value != ask_secret("Confirm: "):
        raise VaultError("The two passwords do not match.")
    return value


def parser():
    root = argparse.ArgumentParser(description="Local encrypted password vault (Project 2).")
    root.add_argument("--vault", type=Path, default=Path("vault.json"), help="Vault path (before the command).")
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create a vault; prompt for a new master passphrase.")
    sub.add_parser("unlock", help="Verify and decrypt once; no persistent unlocked session.")
    add = sub.add_parser("add", help="Add a site and prompt for its password.")
    add.add_argument("site")
    add.add_argument("--user", required=True)
    add.add_argument("--generate", action="store_true", help="Generate the entry password instead of typing it.")
    add.add_argument("--length", type=int, default=20)
    sub.add_parser("list", help="List sites and usernames; passwords are not printed.")
    for name in ("get", "delete"):
        command = sub.add_parser(name)
        command.add_argument("site")
    gen = sub.add_parser("gen", help="Print a generated password without opening the vault.")
    gen.add_argument("--length", type=int, default=20)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "gen":
            print(generate_password(args.length))
            return 0
        if args.command == "init":
            initialize(args.vault, new_secret("New master passphrase (at least 12 characters): "))
            print("Vault created. Keep your master passphrase safe; there is no recovery key.")
        else:
            with open_vault(args.vault, ask_secret("Master passphrase: ")) as vault:
                if args.command == "unlock":
                    print(f"Unlocked successfully: {len(vault.entries)} entries. Session ends after this command.")
                elif args.command == "add":
                    password = generate_password(args.length) if args.generate else new_secret("Entry password: ")
                    vault.add(args.site, args.user, password)
                    vault.save()
                    print("Entry saved.")
                elif args.command == "list":
                    for site, item in sorted(vault.entries.items()):
                        # JSON escaping prevents names from injecting terminal control characters.
                        print(json.dumps({"site": site, "username": item["username"]}, ensure_ascii=True))
                    if not vault.entries:
                        print("Vault is empty.")
                elif args.command == "get":
                    print(json.dumps(vault.get(args.site), indent=2, ensure_ascii=True))
                elif args.command == "delete":
                    vault.delete(args.site)
                    vault.save()
                    print("Entry deleted.")
        return 0
    except (VaultError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
