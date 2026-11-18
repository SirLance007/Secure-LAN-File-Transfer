"""
End-to-End Integration Tests for Secure LAN File Transfer System
Tests full socket lifecycle: connection, registration, login, AES file transfer,
SHA-256 verification, and error handling.
"""

import unittest
import tempfile
import time
from pathlib import Path

from server.server_core import FileTransferServer
from client.client_core import TransferClient
from crypto.integrity import compute_sha256


class TestEndToEndTransfer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.base_path = Path(cls.temp_dir.name)
        cls.db_path = cls.base_path / "test_server.db"
        cls.storage_dir = cls.base_path / "server_storage"
        cls.port = 5098

        cls.server = FileTransferServer(
            host="127.0.0.1",
            port=cls.port,
            shared_secret="IntegrationTestKey2026!",
            db_path=cls.db_path,
            storage_dir=cls.storage_dir
        )
        started = cls.server.start()
        if not started:
            raise RuntimeError("Failed to start test server")
        time.sleep(0.1)  # Allow socket bind

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = TransferClient(server_host="127.0.0.1", server_port=self.port)

    def tearDown(self):
        self.client.disconnect()

    def test_01_heartbeat_ping(self):
        """Test TCP connection and ping response."""
        ok, msg = self.client.connect()
        self.assertTrue(ok)
        ping_ok, rtt = self.client.ping()
        self.assertTrue(ping_ok)
        self.assertGreaterEqual(rtt, 0.0)

    def test_02_registration_and_authentication(self):
        """Test registering a student account and authenticating."""
        self.client.connect()
        ok_reg, _ = self.client.register("lab_user", "LabSecurePass123!")
        self.assertTrue(ok_reg)

        ok_login, msg = self.client.login("lab_user", "LabSecurePass123!")
        self.assertTrue(ok_login)
        self.assertIsNotNone(self.client.session_token)

    def test_03_file_transfer_aes_gcm(self):
        """Test sending a file encrypted with AES-256-GCM and verifying receiver decryption."""
        self.client.connect()
        self.client.login("lab_user", "LabSecurePass123!")

        # Create a test file
        test_file = self.base_path / "academic_report.txt"
        content = b"Confidential Research Data: Secure LAN File Transfer System Using AES-256-GCM\n" * 1000
        test_file.write_bytes(content)
        original_hash = compute_sha256(test_file)

        result = self.client.send_file(
            file_path=test_file,
            passphrase="IntegrationTestKey2026!",
            mode="AES-GCM"
        )

        self.assertTrue(result["success"], f"Transfer failed: {result.get('message')}")
        self.assertTrue(result["verified"])
        self.assertEqual(result["original_sha256"], original_hash)

        # Check server storage
        received_files = list((self.storage_dir / "lab_user").glob("*academic_report.txt*"))
        self.assertTrue(len(received_files) > 0)
        self.assertEqual(received_files[0].read_bytes(), content)

    def test_04_file_transfer_aes_cbc(self):
        """Test sending a file encrypted with AES-256-CBC with HMAC-SHA256."""
        self.client.connect()
        self.client.login("student", "Student@123")

        test_file = self.base_path / "network_packet_capture.bin"
        content = bytes(range(256)) * 40  # 10 KB binary file
        test_file.write_bytes(content)
        original_hash = compute_sha256(test_file)

        result = self.client.send_file(
            file_path=test_file,
            passphrase="IntegrationTestKey2026!",
            mode="AES-CBC"
        )

        self.assertTrue(result["success"], f"Transfer failed: {result.get('message')}")
        self.assertTrue(result["verified"])
        self.assertEqual(result["original_sha256"], original_hash)

        received_files = list((self.storage_dir / "student").glob("*network_packet_capture.bin*"))
        self.assertTrue(len(received_files) > 0)
        self.assertEqual(received_files[0].read_bytes(), content)

    def test_05_unauthorized_transfer_rejected(self):
        """Transfer without logging in must be rejected."""
        self.client.connect()
        # Do not log in
        test_file = self.base_path / "secret.txt"
        test_file.write_bytes(b"secret")

        res = self.client.send_file(test_file)
        self.assertFalse(res["success"])
        self.assertIn("Not authenticated", res["message"])


if __name__ == "__main__":
    unittest.main()
