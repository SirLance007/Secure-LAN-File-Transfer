"""
AES Encryption and Decryption Engine
Supports AES-256-GCM (Authenticated Encryption) and AES-256-CBC (with PKCS#7 and HMAC).
Provides both in-memory byte encryption and streaming file encryption.
"""

import os
from pathlib import Path
from typing import Tuple, Dict, Any, Union

# Try importing cryptography or pycryptodome
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

try:
    from Crypto.Cipher import AES as PyCryptoAES
    from Crypto.Util.Padding import pad as pycrypto_pad, unpad as pycrypto_unpad
    _HAS_PYCRYPTODOME = True
except ImportError:
    _HAS_PYCRYPTODOME = False

from crypto.integrity import compute_sha256, compute_hmac_sha256, verify_hmac_sha256
from crypto.key_manager import generate_nonce, generate_iv, derive_encryption_and_mac_keys
import config


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class AuthenticationFailedError(CryptoError):
    """Raised when data integrity or authentication tag validation fails."""
    pass


class AESCipher:
    """
    Unified AES-256 Cryptographic Engine supporting:
    - AES-256-GCM: AEAD (Confidentiality + Authenticity)
    - AES-256-CBC: Encrypt-then-MAC with PKCS#7
    """

    @staticmethod
    def encrypt_bytes(
        plaintext: bytes,
        key: bytes,
        mode: str = config.DEFAULT_AES_MODE,
        associated_data: bytes = b""
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt raw bytes using AES-256.
        Returns:
            (ciphertext, iv_or_nonce, auth_tag_or_hmac)
        """
        if len(key) != config.AES_KEY_SIZE:
            raise ValueError(f"AES key must be {config.AES_KEY_SIZE} bytes (256-bit). Got {len(key)} bytes.")

        mode = mode.upper()
        if mode == "AES-GCM":
            nonce = generate_nonce(config.AES_NONCE_SIZE_GCM)
            if _HAS_CRYPTOGRAPHY:
                aesgcm = AESGCM(key)
                # AESGCM.encrypt appends 16-byte tag to the ciphertext
                ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
                ciphertext = ct_with_tag[:-config.GCM_TAG_SIZE]
                tag = ct_with_tag[-config.GCM_TAG_SIZE:]
                return ciphertext, nonce, tag
            elif _HAS_PYCRYPTODOME:
                cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=nonce)
                if associated_data:
                    cipher.update(associated_data)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                return ciphertext, nonce, tag
            else:
                raise CryptoError("No supported AES cryptography backend installed.")

        elif mode == "AES-CBC":
            iv = generate_iv(config.AES_IV_SIZE_CBC)
            enc_key, mac_key = derive_encryption_and_mac_keys(key)

            if _HAS_CRYPTOGRAPHY:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(plaintext) + padder.finalize()
                cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            elif _HAS_PYCRYPTODOME:
                padded_data = pycrypto_pad(plaintext, 16)
                cipher = PyCryptoAES.new(enc_key, PyCryptoAES.MODE_CBC, iv=iv)
                ciphertext = cipher.encrypt(padded_data)
            else:
                raise CryptoError("No supported AES cryptography backend installed.")

            # Encrypt-then-MAC: HMAC over IV + ciphertext + associated_data
            mac = compute_hmac_sha256(mac_key, iv + ciphertext + associated_data)
            return ciphertext, iv, mac

        else:
            raise ValueError(f"Unsupported AES mode: {mode}. Must be AES-GCM or AES-CBC.")

    @staticmethod
    def decrypt_bytes(
        ciphertext: bytes,
        key: bytes,
        iv_or_nonce: bytes,
        tag_or_hmac: bytes,
        mode: str = config.DEFAULT_AES_MODE,
        associated_data: bytes = b""
    ) -> bytes:
        """
        Decrypt raw bytes using AES-256 and verify authenticity.
        """
        if len(key) != config.AES_KEY_SIZE:
            raise ValueError(f"AES key must be {config.AES_KEY_SIZE} bytes. Got {len(key)} bytes.")

        mode = mode.upper()
        if mode == "AES-GCM":
            if _HAS_CRYPTOGRAPHY:
                aesgcm = AESGCM(key)
                ct_with_tag = ciphertext + tag_or_hmac
                try:
                    plaintext = aesgcm.decrypt(iv_or_nonce, ct_with_tag, associated_data)
                    return plaintext
                except Exception as e:
                    raise AuthenticationFailedError("GCM authentication tag verification failed. Ciphertext has been tampered with.") from e
            elif _HAS_PYCRYPTODOME:
                cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_GCM, nonce=iv_or_nonce)
                if associated_data:
                    cipher.update(associated_data)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag_or_hmac)
                    return plaintext
                except ValueError as e:
                    raise AuthenticationFailedError("GCM authentication tag verification failed. Ciphertext has been tampered with.") from e
            else:
                raise CryptoError("No supported AES cryptography backend installed.")

        elif mode == "AES-CBC":
            enc_key, mac_key = derive_encryption_and_mac_keys(key)

            # 1. Verify MAC first (Encrypt-then-MAC)
            expected_mac_input = iv_or_nonce + ciphertext + associated_data
            if not verify_hmac_sha256(mac_key, expected_mac_input, tag_or_hmac):
                raise AuthenticationFailedError("HMAC integrity check failed. Ciphertext has been modified or corrupted.")

            # 2. Decrypt & unpad
            if _HAS_CRYPTOGRAPHY:
                cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv_or_nonce), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                try:
                    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                    return plaintext
                except Exception as e:
                    raise CryptoError("PKCS#7 padding validation failed.") from e
            elif _HAS_PYCRYPTODOME:
                cipher = PyCryptoAES.new(enc_key, PyCryptoAES.MODE_CBC, iv=iv_or_nonce)
                padded_plaintext = cipher.decrypt(ciphertext)
                try:
                    plaintext = pycrypto_unpad(padded_plaintext, 16)
                    return plaintext
                except Exception as e:
                    raise CryptoError("PKCS#7 padding validation failed.") from e
            else:
                raise CryptoError("No supported AES cryptography backend installed.")

        else:
            raise ValueError(f"Unsupported AES mode: {mode}")

    @classmethod
    def encrypt_file(
        cls,
        source_path: Union[str, Path],
        dest_path: Union[str, Path],
        key: bytes,
        mode: str = config.DEFAULT_AES_MODE,
        associated_data: bytes = b""
    ) -> Dict[str, Any]:
        """
        Encrypt an entire file from source_path to dest_path.
        Returns encryption metadata dict containing IV/nonce, tag, sha256, etc.
        """
        src = Path(source_path)
        dst = Path(dest_path)
        if not src.is_file():
            raise FileNotFoundError(f"Source file not found: {src}")

        original_sha256 = compute_sha256(src)
        original_size = src.stat().st_size

        with open(src, "rb") as f:
            plaintext = f.read()

        ciphertext, iv_nonce, tag_hmac = cls.encrypt_bytes(
            plaintext=plaintext,
            key=key,
            mode=mode,
            associated_data=associated_data
        )

        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(ciphertext)

        encrypted_sha256 = compute_sha256(dst)

        return {
            "mode": mode,
            "original_filename": src.name,
            "original_size": original_size,
            "original_sha256": original_sha256,
            "encrypted_size": len(ciphertext),
            "encrypted_sha256": encrypted_sha256,
            "iv_nonce": iv_nonce,
            "tag_hmac": tag_hmac,
        }

    @classmethod
    def decrypt_file(
        cls,
        encrypted_path: Union[str, Path],
        dest_path: Union[str, Path],
        key: bytes,
        iv_nonce: bytes,
        tag_hmac: bytes,
        mode: str = config.DEFAULT_AES_MODE,
        associated_data: bytes = b"",
        expected_sha256: str = None
    ) -> Dict[str, Any]:
        """
        Decrypt a file from encrypted_path to dest_path and verify integrity.
        """
        enc_file = Path(encrypted_path)
        dst = Path(dest_path)
        if not enc_file.is_file():
            raise FileNotFoundError(f"Encrypted file not found: {enc_file}")

        with open(enc_file, "rb") as f:
            ciphertext = f.read()

        plaintext = cls.decrypt_bytes(
            ciphertext=ciphertext,
            key=key,
            iv_or_nonce=iv_nonce,
            tag_or_hmac=tag_hmac,
            mode=mode,
            associated_data=associated_data
        )

        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, "wb") as f:
            f.write(plaintext)

        decrypted_sha256 = compute_sha256(dst)
        hash_verified = True
        if expected_sha256:
            if decrypted_sha256.lower() != expected_sha256.lower():
                hash_verified = False
                raise AuthenticationFailedError(
                    f"Integrity check failed: Expected {expected_sha256}, got {decrypted_sha256}"
                )

        return {
            "decrypted_size": len(plaintext),
            "decrypted_sha256": decrypted_sha256,
            "hash_verified": hash_verified,
            "dest_path": str(dst.resolve())
        }
