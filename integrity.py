import hashlib
import json
import os
from datetime import datetime

LOG_PATH = os.path.join("logs", "audit_log.json")
VAULT_DIR = "vault"
ZERO_HASH = "0" * 64     # prev_hash of the very first entry


def sha256_file(path: str) -> str:
    """SHA-256 fingerprint of a file, as a hex string."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):    # read in pieces, works for big files
            h.update(chunk)
    return h.hexdigest()


def _entry_hash(entry: dict) -> str:
    """Hash of an entry, NOT counting its own entry_hash field."""
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    text = json.dumps(body, sort_keys=True)
    return hashlib.sha256(text.encode()).hexdigest()


def _read_log() -> list:
    """Read the log. Returns [] if there is no log yet."""
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as f:
        return json.load(f)


def log_event(action: str, filename: str, file_hash: str) -> None:
    """Add a new entry to the hash chain."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    log = _read_log()
    prev_hash = log[-1]["entry_hash"] if log else ZERO_HASH

    entry = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "action": action,
        "file": filename,
        "file_hash": file_hash,
        "prev_hash": prev_hash,
    }
    entry["entry_hash"] = _entry_hash(entry)

    log.append(entry)
    with open(LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)


def verify_log():
    """Walk the chain. Returns (True, None) if intact,
    or (False, filename) at the first broken entry."""
    try:
        log = _read_log()
    except ValueError:                       # log is not valid JSON anymore
        return False, "unreadable log file"

    expected_prev = ZERO_HASH
    for entry in log:
        try:
            link_ok = entry["prev_hash"] == expected_prev
            hash_ok = entry["entry_hash"] == _entry_hash(entry)
            name = entry["file"]
        except (KeyError, TypeError):        # an entry was damaged
            return False, "damaged entry"
        if not (link_ok and hash_ok):
            return False, name
        expected_prev = entry["entry_hash"]
    return True, None


def verify_file(filename: str):
    """Compare vault/<filename>.enc with the hash logged at upload.
    Returns (True, "OK") or (False, reason)."""
    path = os.path.join(VAULT_DIR, filename + ".enc")

    # Find the latest UPLOAD entry for this file
    logged_hash = None
    try:
        for entry in _read_log():
            if entry.get("action") == "UPLOAD" and entry.get("file") == filename:
                logged_hash = entry.get("file_hash")
    except ValueError:
        return False, "log unreadable"

    if logged_hash is None:
        return False, "not found in the audit log"
    if not os.path.exists(path):
        return False, "file missing"
    if sha256_file(path) != logged_hash:
        return False, "hash mismatch"
    return True, "OK"