import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_key(password: str, salt: bytes) -> bytes:
    """Turn the user's password into a 32-byte (256-bit) AES key."""
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode())


def encrypt(data: bytes, password: str) -> bytes:
    """Encrypt file bytes. Returns salt + nonce + ciphertext (tag included)."""
    salt = os.urandom(16)    # random, so every file gets a different key
    nonce = os.urandom(12)   # random, must never repeat with the same key
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt(blob: bytes, password: str) -> bytes:
    """Decrypt a blob made by encrypt().
    Raises InvalidTag if the password is wrong or the data was changed."""
    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)