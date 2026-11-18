"""
Cryptographic Key Management & Derivation Utilities
Implements PBKDF2-HMAC-SHA256, cryptographically secure salt/IV generation,
and key split functions.
"""

import os
import secrets
import base64
import hashlib
from typing import Tuple
import config


def generate_salt(size: int = config.SALT_SIZE) -> bytes:
    """Generate cryptographically secure random bytes for salt."""
    return os.urandom(size)


def generate_nonce(size: int = config.AES_NONCE_SIZE_GCM) -> bytes:
    """Generate cryptographically secure random nonce for AES-GCM."""
    return os.urandom(size)


def generate_iv(size: int = config.AES_IV_SIZE_CBC) -> bytes:
    """Generate cryptographically secure random IV for AES-CBC."""
    return os.urandom(size)


def generate_random_key(bytes_len: int = config.AES_KEY_SIZE) -> str:
    """
    Generate a high-entropy 256-bit symmetric key represented as a URL-safe Base64 string.
    """
    raw_key = os.urandom(bytes_len)
    return base64.urlsafe_b64encode(raw_key).decode("utf-8")


def derive_key(passphrase: str, salt: bytes, length: int = config.AES_KEY_SIZE,
               iterations: int = config.PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit symmetric key from a user passphrase and salt
    using PBKDF2 with HMAC-SHA256.
    """
    if not isinstance(passphrase, bytes):
        passphrase_bytes = passphrase.encode("utf-8")
    else:
        passphrase_bytes = passphrase

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=passphrase_bytes,
        salt=salt,
        iterations=iterations,
        dklen=length
    )


def derive_encryption_and_mac_keys(master_key: bytes) -> Tuple[bytes, bytes]:
    """
    Derive sub-keys for Encrypt-then-MAC (used in AES-CBC mode):
    - Enc Key (32 bytes)
    - MAC Key (32 bytes)
    Uses HKDF-like construction with SHA-256.
    """
    enc_key = hashlib.sha256(master_key + b"|encryption_key").digest()
    mac_key = hashlib.sha256(master_key + b"|authentication_key").digest()
    return enc_key, mac_key
