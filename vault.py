import os
from cryptography.exceptions import InvalidTag

import crypto_utils
import integrity   # teammate's module: log_event, verify_log, verify_file, sha256_file

VAULT_DIR = "vault"


class VaultError(Exception):
    """Base class for vault errors."""


class TamperedError(VaultError):
    """The log or a file was modified, so we refuse to decrypt."""


class WrongPasswordError(VaultError):
    """Wrong password (or the data changed)."""


def _path(name: str) -> str:
    """Safe path for vault/<name>.enc (strips folders from the name)."""
    name = os.path.basename(name)
    return os.path.join(VAULT_DIR, name + ".enc")


def list_files() -> list:
    """Names of all files in the vault (without the .enc ending)."""
    os.makedirs(VAULT_DIR, exist_ok=True)
    return sorted(f[:-4] for f in os.listdir(VAULT_DIR) if f.endswith(".enc"))


def add_file(name: str, data: bytes, password: str) -> str:
    """Encrypt data, save it as vault/<name>.enc, log the UPLOAD.
    Returns the SHA-256 hash of the saved .enc file."""
    name = os.path.basename(name)
    os.makedirs(VAULT_DIR, exist_ok=True)
    path = _path(name)
    if os.path.exists(path):
        raise VaultError(f"{name} already exists in the vault.")

    blob = crypto_utils.encrypt(data, password)   # salt + nonce + ciphertext
    with open(path, "wb") as f:
        f.write(blob)

    file_hash = integrity.sha256_file(path)
    integrity.log_event("UPLOAD", name, file_hash)
    return file_hash


def get_file(name: str, password: str) -> bytes:
    """Verify the log and the file FIRST, then decrypt and log the DOWNLOAD."""
    name = os.path.basename(name)
    path = _path(name)

    # 1. Is the audit log chain intact?
    log_ok, bad_entry = integrity.verify_log()
    if not log_ok:
        raise TamperedError(f"LOG TAMPERED: the audit chain is broken at {bad_entry}.")

    # 2. Does the file match the hash recorded at upload?
    file_ok, reason = integrity.verify_file(name)
    if not file_ok:
        raise TamperedError(f"TAMPERED: {name} - {reason}. Download blocked.")

    # 3. Decrypt (GCM tag is checked here)
    with open(path, "rb") as f:
        blob = f.read()
    try:
        data = crypto_utils.decrypt(blob, password)
    except InvalidTag:
        raise WrongPasswordError("Wrong password, or the file was modified. No file returned.")

    integrity.log_event("DOWNLOAD", name, integrity.sha256_file(path))
    return data