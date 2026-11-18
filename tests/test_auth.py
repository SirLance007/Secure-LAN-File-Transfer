"""
Unit tests for Server Authentication and SQLite Database
"""

import unittest
import tempfile
from pathlib import Path
from server.auth import AuthManager


class TestAuthManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_users.db"
        self.auth = AuthManager(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_seeded_users(self):
        """Check that default users exist and authenticate."""
        ok, msg, token = self.auth.authenticate("student", "Student@123")
        self.assertTrue(ok)
        self.assertIsNotNone(token)
        self.assertEqual(self.auth.validate_token(token), "student")

    def test_user_registration_and_login(self):
        """Register a new user and test login with correct & incorrect credentials."""
        ok, msg = self.auth.register("alice", "AliceSecurePass2026!")
        self.assertTrue(ok)

        # Login with correct password
        ok_login, _, token = self.auth.authenticate("alice", "AliceSecurePass2026!")
        self.assertTrue(ok_login)
        self.assertIsNotNone(token)

        # Login with wrong password
        ok_fail, _, token_fail = self.auth.authenticate("alice", "WrongPass")
        self.assertFalse(ok_fail)
        self.assertIsNone(token_fail)

    def test_duplicate_registration_rejected(self):
        """Duplicate username registration should be rejected."""
        ok1, _ = self.auth.register("bob", "Password123")
        self.assertTrue(ok1)
        ok2, msg = self.auth.register("bob", "DifferentPass456")
        self.assertFalse(ok2)
        self.assertIn("already taken", msg)

    def test_case_insensitive_username(self):
        """Usernames should match case-insensitively."""
        ok, _, token = self.auth.authenticate("STUDENT", "Student@123")
        self.assertTrue(ok)
        self.assertEqual(self.auth.validate_token(token), "student")

    def test_token_invalidation(self):
        """Logging out should invalidate the session token."""
        _, _, token = self.auth.authenticate("student", "Student@123")
        self.assertIsNotNone(self.auth.validate_token(token))
        self.auth.invalidate_token(token)
        self.assertIsNone(self.auth.validate_token(token))


if __name__ == "__main__":
    unittest.main()
