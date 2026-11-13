"""Tamper demo: pretend to be an attacker so we can show detection.

Usage (run in the project folder):
    python tamper_demo.py flip <name>     flip one byte inside vault/<name>.enc
    python tamper_demo.py replace <name>  swap the file for different bytes
    python tamper_demo.py delete <name>   delete vault/<name>.enc
    python tamper_demo.py editlog         edit one entry in logs/audit_log.json
    python tamper_demo.py restore         undo everything this script did
"""
import json
import os
import shutil
import sys

VAULT_DIR = "vault"
LOG_PATH = os.path.join("logs", "audit_log.json")
BACKUP_DIR = "demo_backup"     # copies of originals, so restore works


def enc_path(name: str) -> str:
    """vault/<name>.enc (accepts the name with or without .enc)."""
    if name.endswith(".enc"):
        name = name[:-4]
    return os.path.join(VAULT_DIR, name + ".enc")


def backup(path: str) -> None:
    """Save a copy of the original once, before we damage it."""
    dest = os.path.join(BACKUP_DIR, path)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if not os.path.exists(dest):
        shutil.copy2(path, dest)


def need(path: str) -> None:
    if not os.path.exists(path):
        sys.exit(f"Cannot find {path}. Upload the file first and check the name.")


def flip(name: str) -> None:
    """Attack 1: change a single byte inside the encrypted file."""
    path = enc_path(name)
    need(path)
    backup(path)
    with open(path, "r+b") as f:
        data = f.read()
        if len(data) <= 28:
            sys.exit("File is too small to be a valid vault file.")
        pos = 28 + (len(data) - 28) // 2      # a byte inside the ciphertext
        f.seek(pos)
        f.write(bytes([data[pos] ^ 0xFF]))    # flip all 8 bits of that byte
    print(f"Flipped one byte at position {pos} of {path}")


def replace(name: str) -> None:
    """Attack 2: swap the file for completely different data."""
    path = enc_path(name)
    need(path)
    backup(path)
    with open(path, "wb") as f:
        f.write(os.urandom(64))
    print(f"Replaced {path} with random bytes")


def delete(name: str) -> None:
    """Attack 3: remove the encrypted file."""
    path = enc_path(name)
    need(path)
    backup(path)
    os.remove(path)
    print(f"Deleted {path}")


def editlog() -> None:
    """Attack 4: change one entry of the audit log."""
    need(LOG_PATH)
    backup(LOG_PATH)
    with open(LOG_PATH, "r") as f:
        log = json.load(f)
    log[0]["file"] = "forged_" + log[0]["file"]    # edit the first entry
    with open(LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)
    print(f"Edited entry 1 of {LOG_PATH}")


def restore() -> None:
    """Put every original file back and remove the backups."""
    if not os.path.exists(BACKUP_DIR):
        sys.exit("Nothing to restore.")
    for folder, _, files in os.walk(BACKUP_DIR):
        for name in files:
            saved = os.path.join(folder, name)
            original = os.path.relpath(saved, BACKUP_DIR)
            os.makedirs(os.path.dirname(original), exist_ok=True)
            shutil.copy2(saved, original)
            print(f"Restored {original}")
    shutil.rmtree(BACKUP_DIR)


if __name__ == "__main__":
    args = sys.argv[1:]
    commands = {"flip": flip, "replace": replace, "delete": delete}
    if args and args[0] in commands and len(args) == 2:
        commands[args[0]](args[1])
    elif args == ["editlog"]:
        editlog()
    elif args == ["restore"]:
        restore()
    else:
        print(__doc__)