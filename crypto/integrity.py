"""
Integrity Verification Utilities
Provides SHA-256 file hashing, HMAC generation, and constant-time validation.
"""

import hashlib
import hmac
from pathlib import Path
from typing import Union


def compute_sha256(data: Union[bytes, str, Path]) -> str:
    """
    Compute hex SHA-256 digest of raw bytes or a file path.
    Streams large files in 64KB blocks to prevent memory exhaustion.
    """
    hasher = hashlib.sha256()

    if isinstance(data, bytes):
        hasher.update(data)
        return hasher.hexdigest()

    file_path = Path(data)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        while chunk := f.read(64 * 1024):
            hasher.update(chunk)

    return hasher.hexdigest()


def verify_sha256(data: Union[bytes, str, Path], expected_hex: str) -> bool:
    """
    Verify if computed SHA-256 matches expected hex digest using constant-time comparison.
    """
    actual_hex = compute_sha256(data)
    return hmac.compare_digest(actual_hex.lower(), expected_hex.lower())


def compute_hmac_sha256(key: bytes, data: bytes) -> bytes:
    """
    Compute raw HMAC-SHA256 of data using symmetric key.
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac_sha256(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """
    Constant-time comparison for HMAC integrity tags.
    """
    actual_mac = compute_hmac_sha256(key, data)
    return hmac.compare_digest(actual_mac, expected_mac)
