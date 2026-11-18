"""
Unit tests for cryptographic components: AES-GCM, AES-CBC, Key Derivation, Integrity
"""

import unittest
import os
import tempfile
from pathlib import Path

from crypto.aes_cipher import AESCipher, AuthenticationFailedError
from crypto.key_manager import derive_key, generate_salt, generate_random_key
from crypto.integrity import compute_sha256, verify_sha256


class TestCryptography(unittest.TestCase):

    def setUp(self):
        self.salt = generate_salt()
        self.passphrase = "SyllabusSecretP@ssw0rd2026!"
        self.key = derive_key(self.passphrase, self.salt)
        self.test_data = b"Hello, Secure LAN File Transfer! This is confidential academic research data."

    def test_key_derivation_deterministic(self):
        """Verify PBKDF2 derives the exact same 256-bit key given same pass and salt."""
        key1 = derive_key(self.passphrase, self.salt)
        key2 = derive_key(self.passphrase, self.salt)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_key_derivation_different_salt(self):
        """Different salt should yield completely different key."""
        salt2 = generate_salt()
        key2 = derive_key(self.passphrase, salt2)
        self.assertNotEqual(self.key, key2)

    def test_aes_gcm_encrypt_decrypt(self):
        """Verify AES-256-GCM round-trip encryption and decryption."""
        ct, nonce, tag = AESCipher.encrypt_bytes(
            plaintext=self.test_data,
            key=self.key,
            mode="AES-GCM",
            associated_data=b"user:alice"
        )
        self.assertNotEqual(ct, self.test_data)

        pt = AESCipher.decrypt_bytes(
            ciphertext=ct,
            key=self.key,
            iv_or_nonce=nonce,
            tag_or_hmac=tag,
            mode="AES-GCM",
            associated_data=b"user:alice"
        )
        self.assertEqual(pt, self.test_data)

    def test_aes_gcm_tamper_detection(self):
        """GCM must detect ciphertext tampering and reject decryption."""
        ct, nonce, tag = AESCipher.encrypt_bytes(self.test_data, self.key, mode="AES-GCM")
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0xFF  # Flip bits in first byte

        with self.assertRaises(AuthenticationFailedError):
            AESCipher.decrypt_bytes(bytes(tampered_ct), self.key, nonce, tag, mode="AES-GCM")

    def test_aes_cbc_encrypt_decrypt(self):
        """Verify AES-256-CBC Encrypt-then-MAC round-trip."""
        ct, iv, mac = AESCipher.encrypt_bytes(
            plaintext=self.test_data,
            key=self.key,
            mode="AES-CBC",
            associated_data=b"user:bob"
        )
        self.assertNotEqual(ct, self.test_data)

        pt = AESCipher.decrypt_bytes(
            ciphertext=ct,
            key=self.key,
            iv_or_nonce=iv,
            tag_or_hmac=mac,
            mode="AES-CBC",
            associated_data=b"user:bob"
        )
        self.assertEqual(pt, self.test_data)

    def test_aes_cbc_tamper_detection(self):
        """CBC Encrypt-then-MAC must reject tampered ciphertext."""
        ct, iv, mac = AESCipher.encrypt_bytes(self.test_data, self.key, mode="AES-CBC")
        tampered_ct = bytearray(ct)
        tampered_ct[-1] ^= 0x01

        with self.assertRaises(AuthenticationFailedError):
            AESCipher.decrypt_bytes(bytes(tampered_ct), self.key, iv, mac, mode="AES-CBC")

    def test_file_encrypt_decrypt(self):
        """Test streaming file encryption and decryption with SHA-256 verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src_file = Path(tmpdir) / "source.txt"
            enc_file = Path(tmpdir) / "source.txt.enc"
            dec_file = Path(tmpdir) / "restored.txt"

            sample_content = b"Binary and text content line 1\nLine 2\nSpecial: \x00\xff\xfe\x42" * 500
            src_file.write_bytes(sample_content)

            meta = AESCipher.encrypt_file(src_file, enc_file, self.key, mode="AES-GCM")
            self.assertTrue(enc_file.exists())
            self.assertNotEqual(enc_file.read_bytes(), sample_content)

            res = AESCipher.decrypt_file(
                encrypted_path=enc_file,
                dest_path=dec_file,
                key=self.key,
                iv_nonce=meta["iv_nonce"],
                tag_hmac=meta["tag_hmac"],
                mode="AES-GCM",
                expected_sha256=meta["original_sha256"]
            )

            self.assertTrue(res["hash_verified"])
            self.assertEqual(dec_file.read_bytes(), sample_content)


if __name__ == "__main__":
    unittest.main()
