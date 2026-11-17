"""AES-GCM encryption/decryption used as the universal encryption layer.

Key derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023).
Wire format: salt(16) | nonce(12) | ciphertext+tag
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
_MIN_PASSWORD_LEN = 1
_ENVELOPE_OVERHEAD = 28  # salt(16) + nonce(12)


def _validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LEN:
        raise ValueError("Password must be a non-empty string")


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(data: bytes, password: str) -> bytes:
    """Encrypt *data* with AES-256-GCM.  Output: salt(16) + nonce(12) + ciphertext+tag."""
    _validate_password(password)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt(data: bytes, password: str) -> bytes:
    """Decrypt output produced by :func:`encrypt`.  Raises ValueError on bad password/corrupt data."""
    _validate_password(password)
    if len(data) < _ENVELOPE_OVERHEAD + 16:  # +16 for GCM auth tag minimum
        raise ValueError("Ciphertext is too short — data may be corrupt")
    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong password or corrupt data")
