"""Demo helpers: sample files and attack simulations (used by the Demo Tools page)."""
import json
import os
import shutil

import vault

VAULT_DIR = vault.VAULT_DIR
LOG_PATH = os.path.join("logs", "audit_log.json")
BACKUP_DIR = "demo_backup"
DEMO_PASSWORD = "demo123"

# Fake documents, only for the demo
SAMPLES = {
    "student_certificate.txt": "CERTIFICATE OF COMPLETION\nThis certifies that Sample Student completed the course with distinction.\nIssued: 01-06-2026\n",
    "marksheet_sem4.txt": "SEMESTER 4 MARKSHEET\nCryptography: 88\nNetworks: 91\nDatabases: 85\nSGPA: 8.9\n",
    "internship_offer_letter.txt": "OFFER LETTER\nWe are pleased to offer you a 3-month internship.\nStipend: as per company policy.\nStart date: 15-12-2026\n",
    "rent_agreement.txt": "RENT AGREEMENT (SAMPLE)\nTenant and landlord agree to an 11-month lease.\nMonthly rent as agreed. Deposit refundable.\n",
    "project_notes.txt": "PROJECT NOTES\nAES-GCM gives confidentiality and integrity.\nscrypt slows down password guessing.\nHash chain makes the log tamper-evident.\n",
    "fee_receipt.txt": "FEE RECEIPT\nReceived: tuition fee for the academic year 2026-2027.\nReceipt no: 000123 (sample)\n",
}


def enc_path(name: str) -> str:
    return os.path.join(VAULT_DIR, name + ".enc")


def load_samples() -> list:
    """Encrypt every sample file into the vault. Returns the names added."""
    added = []
    for name, text in SAMPLES.items():
        if not os.path.exists(enc_path(name)):
            vault.add_file(name, text.encode(), DEMO_PASSWORD)
            added.append(name)
    return added


def _backup(path: str) -> None:
    """Keep a copy of the original once, so restore() can undo the attack."""
    dest = os.path.join(BACKUP_DIR, path)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if not os.path.exists(dest):
        shutil.copy2(path, dest)


def _need(path: str) -> None:
    if not os.path.exists(path):
        raise ValueError(f"Cannot find {path}.")


def flip(name: str) -> str:
    """Attack: change one byte inside the encrypted file."""
    path = enc_path(name)
    _need(path)
    _backup(path)
    with open(path, "r+b") as f:
        data = f.read()
        pos = 28 + (len(data) - 28) // 2          # a byte inside the ciphertext
        f.seek(pos)
        f.write(bytes([data[pos] ^ 0xFF]))
    return f"Attack done: one byte of {name} was changed."


def replace(name: str) -> str:
    """Attack: swap the file for random bytes."""
    path = enc_path(name)
    _need(path)
    _backup(path)
    with open(path, "wb") as f:
        f.write(os.urandom(64))
    return f"Attack done: {name} was replaced with different data."


def delete(name: str) -> str:
    """Attack: remove the encrypted file."""
    path = enc_path(name)
    _need(path)
    _backup(path)
    os.remove(path)
    return f"Attack done: {name} was deleted."


def editlog() -> str:
    """Attack: edit one entry of the audit log."""
    _need(LOG_PATH)
    _backup(LOG_PATH)
    with open(LOG_PATH) as f:
        log = json.load(f)
    log[0]["file"] = "forged_" + log[0]["file"]
    with open(LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)
    return "Attack done: entry 1 of the audit log was edited."


def restore() -> str:
    """Undo every attack."""
    if not os.path.exists(BACKUP_DIR):
        return "Nothing to restore."
    for folder, _, files in os.walk(BACKUP_DIR):
        for fname in files:
            saved = os.path.join(folder, fname)
            original = os.path.relpath(saved, BACKUP_DIR)
            os.makedirs(os.path.dirname(original), exist_ok=True)
            shutil.copy2(saved, original)
    shutil.rmtree(BACKUP_DIR)
    return "Everything was restored to the original state."


def reset_all() -> str:
    """Empty the vault and the log."""
    for f in os.listdir(VAULT_DIR):
        if f.endswith(".enc"):
            os.remove(os.path.join(VAULT_DIR, f))
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    return "The vault and the audit log were emptied."