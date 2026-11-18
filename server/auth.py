"""
User Authentication and Credential Store
Implements SQLite storage, PBKDF2 password hashing with salt, and session token issuance.
"""

import sqlite3
import secrets
import hashlib
import time
import contextlib
from pathlib import Path
from typing import Tuple, Optional, Dict, List
import config


class AuthManager:
    """
    Manages user registration, credential hashing, authentication, and session tokens.
    """

    def __init__(self, db_path: Path = config.SERVER_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._active_sessions: Dict[str, Dict] = {}  # token -> {username, created_at}
        self._init_db()
        self._seed_default_users()

    @contextlib.contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema with WAL mode for concurrency."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_login REAL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp REAL NOT NULL,
                    details TEXT
                );
            """)
            conn.commit()

    def _seed_default_users(self) -> None:
        """Seed sample users for quick evaluation if not already present."""
        default_users = [
            ("student", "Student@123"),
            ("faculty", "Faculty@2026"),
            ("admin", "AdminSecure123!")
        ]
        for uname, pwd in default_users:
            if not self.user_exists(uname):
                self.register(uname, pwd)

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        """Hash password using PBKDF2-HMAC-SHA256."""
        dk = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt,
            iterations=config.PBKDF2_ITERATIONS,
            dklen=32
        )
        return dk.hex()

    def user_exists(self, username: str) -> bool:
        """Check if username exists in database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username.strip(),))
            return cursor.fetchone() is not None

    def register(self, username: str, password: str, client_ip: str = "local") -> Tuple[bool, str]:
        """
        Register a new user with salt and PBKDF2 hash.
        """
        username = username.strip()
        if len(username) < 3:
            return False, "Username must be at least 3 characters long."
        if len(password) < 6:
            return False, "Password must be at least 6 characters long."

        salt_bytes = secrets.token_bytes(config.SALT_SIZE)
        salt_hex = salt_bytes.hex()
        pwd_hash = self._hash_password(password, salt_bytes)
        now = time.time()

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, salt_hex, pwd_hash, now)
                )
                cursor.execute(
                    "INSERT INTO audit_logs (username, action, ip_address, timestamp, details) VALUES (?, ?, ?, ?, ?)",
                    (username, "REGISTER", client_ip, now, "User account created successfully")
                )
                conn.commit()
            return True, f"User '{username}' registered successfully."
        except sqlite3.IntegrityError:
            return False, f"Username '{username}' is already taken."
        except Exception as e:
            return False, f"Registration failed: {str(e)}"

    def authenticate(self, username: str, password: str, client_ip: str = "local") -> Tuple[bool, str, Optional[str]]:
        """
        Verify credentials.
        Returns:
            (success: bool, message: str, session_token: Optional[str])
        """
        username = username.strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, salt, password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()

            if not row:
                self.log_event(username, "AUTH_FAIL", client_ip, "Invalid username")
                return False, "Invalid username or password.", None

            canonical_username = row["username"]
            salt_bytes = bytes.fromhex(row["salt"])
            expected_hash = row["password_hash"]
            computed_hash = self._hash_password(password, salt_bytes)

            # Constant-time comparison
            if secrets.compare_digest(computed_hash, expected_hash):
                now = time.time()
                cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (now, canonical_username))
                conn.commit()

                # Generate secure session token
                token = secrets.token_hex(config.SESSION_TOKEN_LENGTH)
                self._active_sessions[token] = {
                    "username": canonical_username,
                    "created_at": now,
                    "ip": client_ip
                }
                self.log_event(canonical_username, "LOGIN_SUCCESS", client_ip, "Authenticated successfully")
                return True, "Authentication successful.", token
            else:
                self.log_event(username, "AUTH_FAIL", client_ip, "Incorrect password")
                return False, "Invalid username or password.", None

    def validate_token(self, token: str) -> Optional[str]:
        """
        Validate active session token. Returns username if valid, else None.
        """
        if not token or token not in self._active_sessions:
            return None
        session = self._active_sessions[token]
        # Invalidate after 24 hours
        if time.time() - session["created_at"] > 86400:
            del self._active_sessions[token]
            return None
        return session["username"]

    def invalidate_token(self, token: str) -> None:
        """Revoke a session token upon logout."""
        self._active_sessions.pop(token, None)

    def log_event(self, username: str, action: str, ip_address: str, details: str = "") -> None:
        """Record an audit log entry."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO audit_logs (username, action, ip_address, timestamp, details) VALUES (?, ?, ?, ?, ?)",
                    (username, action, ip_address, time.time(), details)
                )
                conn.commit()
        except Exception:
            pass

    def list_users(self) -> List[Dict]:
        """List all registered users (for server dashboard)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, created_at, last_login FROM users ORDER BY id ASC")
            return [dict(row) for row in cursor.fetchall()]

    def get_audit_logs(self, limit: int = 50) -> List[Dict]:
        """Retrieve recent audit logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
