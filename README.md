# Smart Document Vault with Tamper Detection

A password-protected document vault built for the Cryptography and Network Security (CNS) course.
Files are encrypted with **AES-256-GCM**, and every action is written to a **hash-chained audit log**.
If a file or the log is modified, replaced or deleted, the app shows a clear **TAMPERED** or **DELETED** alert.

## Features
- Encrypts uploaded files with a key derived from the user's password (scrypt + random salt)
- Authenticated encryption: a wrong password or one changed bit is rejected (GCM tag check)
- SHA-256 fingerprint of every stored file, recorded at upload
- Tamper-evident audit log: each entry stores the hash of the previous entry
- Download is blocked if the log or the file fails verification
- Streamlit web interface with three pages: Upload, My Files, Verify Vault
- `tamper_demo.py` simulates attacks so the detection can be shown live

## Technology
| Item | Choice |
|---|---|
| Language | Python 3.10+ |
| Encryption | AES-256-GCM (`cryptography` library) |
| Key derivation | scrypt with a random 16-byte salt |
| Integrity | SHA-256 (`hashlib`) and a hash-chained log |
| Interface | Streamlit |

## How it works
**Upload:** file + password -> scrypt derives a 256-bit key -> AES-GCM encrypts with a random 12-byte nonce -> saved as `vault/<name>.enc` -> SHA-256 of the `.enc` file is logged.

**Download:** verify the audit log chain -> verify the file hash against the log -> derive the key -> AES-GCM decrypts and checks the tag -> return the file and log the download.

**Stored file layout:** `salt (16 bytes) + nonce (12 bytes) + ciphertext + GCM tag (16 bytes)`.
The salt and nonce are not secret. The password is never stored.

## Project structure
```
smart-document-vault/
  app.py            Streamlit user interface
  vault.py          controller: add_file, get_file, list_files
  crypto_utils.py   key derivation, encrypt, decrypt
  integrity.py      SHA-256, hash-chained log, verify_log, verify_file
  tamper_demo.py    attack simulation for the demo
  test_crypto.py, test_vault.py, test_integrity.py   test scripts
  vault/            encrypted .enc files (created at runtime)
  logs/             audit_log.json (created at runtime)
  .streamlit/config.toml   app colours
```

## Installation (Windows)
```
git clone https://github.com/sohanibnaik-ctrl/smart-document-vault.git
cd smart-document-vault
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run the app
```
streamlit run app.py
```
Open http://localhost:8501 if the browser does not open by itself.

## Tamper demo
Upload a file in the app first (for example `notes.txt`), then in a second terminal:
```
python tamper_demo.py flip notes.txt       # flips one byte of the encrypted file
python tamper_demo.py replace notes.txt    # swaps the file for random bytes
python tamper_demo.py delete notes.txt     # deletes the encrypted file
python tamper_demo.py editlog              # edits an entry of the audit log
python tamper_demo.py restore              # undoes all attacks
```
After each attack, open **Verify Vault** and click **Run full verification**.

## Tests
| No. | Test | Expected result |
|---|---|---|
| 1 | Upload, then download with the correct password | Original file returned |
| 2 | Download with a wrong password | Warning, no file returned |
| 3 | Flip one byte of a `.enc` file | TAMPERED (hash mismatch), download blocked |
| 4 | Edit one entry of `audit_log.json` | LOG TAMPERED, chain broken |
| 5 | Delete a `.enc` file | DELETED |
| 6 | Upload several files, then verify | All OK, chain intact |

Script tests: `python test_crypto.py`, `python test_vault.py` (uses stand-in functions) and `python test_integrity.py`.

## Security choices
- **AES-256-GCM:** confidentiality and integrity in one step
- **Random nonce per file:** reusing a nonce with the same key breaks GCM security
- **scrypt with salt:** memory-hard, slows password guessing, defeats precomputed tables
- **Hash chain:** editing or deleting any log entry breaks every later link

## Known limitation
An attacker who can rewrite the whole log and recompute every hash could forge a consistent chain.
Future improvement: sign the latest log hash with an HMAC key, or store it somewhere separate.

## Team
- Sohani (NNM24CC060)
- Shakal (NNM24CC049)

Course: Cryptography and Network Security, Dept. of Computer and Communication Engineering,
NMAM Institute of Technology, Nitte (Deemed to be University).