"""
Crypto package for Secure LAN File Transfer System
"""
from crypto.aes_cipher import AESCipher, CryptoError, AuthenticationFailedError
from crypto.integrity import compute_sha256, verify_sha256, compute_hmac_sha256, verify_hmac_sha256
from crypto.key_manager import (
    generate_salt,
    generate_nonce,
    generate_iv,
    generate_random_key,
    derive_key,
    derive_encryption_and_mac_keys
)

__all__ = [
    "AESCipher",
    "CryptoError",
    "AuthenticationFailedError",
    "compute_sha256",
    "verify_sha256",
    "compute_hmac_sha256",
    "verify_hmac_sha256",
    "generate_salt",
    "generate_nonce",
    "generate_iv",
    "generate_random_key",
    "derive_key",
    "derive_encryption_and_mac_keys",
]
