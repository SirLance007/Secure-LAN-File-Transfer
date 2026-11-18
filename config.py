"""
Configuration Constants for Secure LAN File Transfer System
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
SERVER_STORAGE_DIR = BASE_DIR / "server_storage"
CLIENT_DOWNLOADS_DIR = BASE_DIR / "client_downloads"
SERVER_DB_PATH = BASE_DIR / "server" / "users.db"

# Ensure directories exist
SERVER_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
CLIENT_DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

# Networking Defaults
DEFAULT_HOST = "0.0.0.0"          # Listen on all interfaces
DEFAULT_CLIENT_HOST = "127.0.0.1"  # Default connect host
DEFAULT_PORT = 5055               # Default listening port
SOCKET_TIMEOUT = 30.0             # Seconds for socket operations
CHUNK_SIZE = 64 * 1024            # 64 KB chunk size for buffered transfer

# Protocol Definitions
MAGIC_BYTES = b"SFTP"             # Secure File Transfer Protocol identifier
PROTOCOL_VERSION = 1

# Cryptography Settings
AES_KEY_SIZE = 32                 # 256 bits
AES_IV_SIZE_CBC = 16              # 128 bits
AES_NONCE_SIZE_GCM = 12           # 96 bits
GCM_TAG_SIZE = 16                 # 128 bits authentication tag
PBKDF2_ITERATIONS = 100_000       # Key derivation iterations
SALT_SIZE = 16                    # Salt size for password and key derivation
DEFAULT_AES_MODE = "AES-GCM"       # "AES-GCM" or "AES-CBC"
SUPPORTED_CIPHERS = ["AES-GCM", "AES-CBC"]

# Security & Limits
MAX_PACKET_SIZE = 100 * 1024 * 1024  # 100 MB max single packet guard
SESSION_TOKEN_LENGTH = 32         # 256 bits session token
