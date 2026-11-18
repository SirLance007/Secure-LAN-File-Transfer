"""
Client Core Engine for Secure LAN File Transfer
Handles TCP connection, user registration/login, local AES file encryption,
chunked streaming over sockets, and verification response parsing.
"""

import socket
import time
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List, Tuple, Union

import config
from protocol.constants import (
    OP_REQ_REGISTER,
    OP_RESP_REGISTER,
    OP_REQ_LOGIN,
    OP_RESP_LOGIN,
    OP_REQ_UPLOAD_INIT,
    OP_RESP_UPLOAD_INIT,
    OP_FILE_CHUNK,
    OP_REQ_UPLOAD_FINISH,
    OP_RESP_UPLOAD_FINISH,
    OP_REQ_LIST_FILES,
    OP_RESP_LIST_FILES,
    OP_HEARTBEAT_PING,
    OP_HEARTBEAT_PONG,
    OP_ERR_GENERIC,
    STATUS_OK,
    STATUS_ERROR,
    STATUS_UNAUTHORIZED,
)
from protocol.packet import send_packet, recv_packet, ConnectionClosedError, ProtocolError
from crypto.aes_cipher import AESCipher, CryptoError
from crypto.key_manager import derive_key, generate_salt
from crypto.integrity import compute_sha256


class TransferClient:
    """
    Client for interacting with the Secure LAN File Transfer Server.
    """

    def __init__(
        self,
        server_host: str = config.DEFAULT_CLIENT_HOST,
        server_port: int = config.DEFAULT_PORT,
        log_callback: Optional[Callable[[str, str], None]] = None
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.log_callback = log_callback
        self.sock: Optional[socket.socket] = None
        self.session_token: Optional[str] = None
        self.logged_in_user: Optional[str] = None
        self.is_connected = False

    def log(self, level: str, message: str) -> None:
        """Internal logging."""
        formatted = f"[{time.strftime('%H:%M:%S')}] [{level.upper()}] {message}"
        print(formatted)
        if self.log_callback:
            try:
                self.log_callback(level, message)
            except Exception:
                pass

    def connect(self) -> Tuple[bool, str]:
        """Establish TCP connection to server."""
        if self.is_connected and self.sock:
            return True, "Already connected."

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(config.SOCKET_TIMEOUT)
            self.sock.connect((self.server_host, self.server_port))
            self.is_connected = True
            self.log("INFO", f"Connected to server at {self.server_host}:{self.server_port}")
            return True, f"Connected to {self.server_host}:{self.server_port}"
        except Exception as e:
            self.is_connected = False
            self.sock = None
            self.log("ERROR", f"Connection failed to {self.server_host}:{self.server_port}: {e}")
            return False, f"Failed to connect: {e}"

    def disconnect(self) -> None:
        """Close socket connection gracefully."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.is_connected = False
        self.session_token = None
        self.logged_in_user = None
        self.log("INFO", "Disconnected from server.")

    def ping(self) -> Tuple[bool, float]:
        """Send heartbeat ping to measure latency."""
        if not self.is_connected:
            return False, 0.0

        t0 = time.time()
        try:
            send_packet(self.sock, OP_HEARTBEAT_PING, {})
            opcode, resp = recv_packet(self.sock)
            if opcode == OP_HEARTBEAT_PONG:
                rtt_ms = (time.time() - t0) * 1000.0
                return True, rtt_ms
        except Exception as e:
            self.log("ERROR", f"Ping error: {e}")
        return False, 0.0

    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user account on the server."""
        if not self.is_connected:
            ok, msg = self.connect()
            if not ok:
                return False, msg

        try:
            send_packet(self.sock, OP_REQ_REGISTER, {
                "username": username,
                "password": password
            })
            opcode, resp = recv_packet(self.sock)
            if opcode == OP_RESP_REGISTER:
                success = (resp.get("status") == STATUS_OK)
                return success, resp.get("message", "")
            return False, f"Unexpected response opcode: {opcode}"
        except Exception as e:
            return False, f"Registration network error: {e}"

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user and obtain session token."""
        if not self.is_connected:
            ok, msg = self.connect()
            if not ok:
                return False, msg

        try:
            send_packet(self.sock, OP_REQ_LOGIN, {
                "username": username,
                "password": password
            })
            opcode, resp = recv_packet(self.sock)
            if opcode == OP_RESP_LOGIN:
                if resp.get("status") == STATUS_OK:
                    self.session_token = resp.get("token")
                    self.logged_in_user = resp.get("username", username)
                    self.log("AUTH", f"User '{self.logged_in_user}' authenticated successfully.")
                    return True, "Login successful."
                else:
                    return False, resp.get("message", "Login failed.")
            return False, f"Unexpected response opcode: {opcode}"
        except Exception as e:
            return False, f"Login network error: {e}"

    def send_file(
        self,
        file_path: Union[str, Path],
        passphrase: str = "SecureLANFileTransferKey2026",
        mode: str = config.DEFAULT_AES_MODE,
        progress_callback: Optional[Callable[[int, int, float, float], None]] = None
    ) -> Dict[str, Any]:
        """
        Encrypt file locally using AES-256 and stream ciphertext to server.
        Progress callback signature: (bytes_sent, total_bytes, percent, kbps)
        """
        if not self.is_connected or not self.session_token:
            return {
                "success": False,
                "message": "Not authenticated. Please connect and log in before transferring files."
            }

        src_path = Path(file_path).resolve()
        if not src_path.is_file():
            return {"success": False, "message": f"File does not exist: {src_path}"}

        self.log("INFO", f"Preparing file for transfer: {src_path.name} ({src_path.stat().st_size} bytes)")
        t_start = time.time()

        # Step 1: Generate cryptographic salt & derive 256-bit AES key
        salt = generate_salt()
        aes_key = derive_key(passphrase, salt)

        # Step 2: Encrypt file locally before network transmission
        temp_enc_file = src_path.parent / f".tmp_{src_path.name}.enc"
        try:
            self.log("CRYPTO", f"Encrypting file with AES-256 ({mode})...")
            enc_meta = AESCipher.encrypt_file(
                source_path=src_path,
                dest_path=temp_enc_file,
                key=aes_key,
                mode=mode,
                associated_data=src_path.name.encode("utf-8")
            )
            self.log("CRYPTO", f"Encryption complete! Original SHA-256: {enc_meta['original_sha256']}")
        except Exception as e:
            if temp_enc_file.exists():
                temp_enc_file.unlink()
            return {"success": False, "message": f"Local encryption error: {e}"}

        # Step 3: Send upload initialization metadata
        try:
            init_payload = {
                "token": self.session_token,
                "filename": src_path.name,
                "original_size": enc_meta["original_size"],
                "original_sha256": enc_meta["original_sha256"],
                "encrypted_size": enc_meta["encrypted_size"],
                "mode": mode,
                "salt_hex": salt.hex(),
                "iv_nonce_hex": enc_meta["iv_nonce"].hex(),
                "tag_hmac_hex": enc_meta["tag_hmac"].hex(),
                "secret_passphrase": passphrase
            }
            send_packet(self.sock, OP_REQ_UPLOAD_INIT, init_payload)

            opcode, resp = recv_packet(self.sock)
            if opcode != OP_RESP_UPLOAD_INIT or resp.get("status") != STATUS_OK:
                return {
                    "success": False,
                    "message": f"Server rejected upload: {resp.get('message', 'Unknown error')}"
                }

            # Step 4: Stream encrypted file chunks
            total_bytes = enc_meta["encrypted_size"]
            bytes_sent = 0
            transfer_start_time = time.time()

            self.log("TRANSFER", f"Streaming {total_bytes} encrypted bytes across LAN in {config.CHUNK_SIZE}B chunks...")

            with open(temp_enc_file, "rb") as f:
                while chunk := f.read(config.CHUNK_SIZE):
                    send_packet(self.sock, OP_FILE_CHUNK, chunk)
                    bytes_sent += len(chunk)

                    elapsed = time.time() - transfer_start_time
                    speed_kbps = (bytes_sent / 1024.0) / elapsed if elapsed > 0 else 0.0
                    percent = (bytes_sent / total_bytes) * 100.0 if total_bytes > 0 else 100.0

                    if progress_callback:
                        progress_callback(bytes_sent, total_bytes, percent, speed_kbps)

            # Step 5: Send upload finish signal
            send_packet(self.sock, OP_REQ_UPLOAD_FINISH, {"token": self.session_token})

            # Step 6: Await server decryption and integrity verification response
            opcode, finish_resp = recv_packet(self.sock)
            total_duration = time.time() - t_start

            if opcode == OP_RESP_UPLOAD_FINISH and finish_resp.get("status") == STATUS_OK:
                self.log("SUCCESS", f"File '{src_path.name}' delivered & verified! Time: {total_duration:.2f}s")
                return {
                    "success": True,
                    "filename": src_path.name,
                    "original_size": enc_meta["original_size"],
                    "encrypted_size": enc_meta["encrypted_size"],
                    "original_sha256": enc_meta["original_sha256"],
                    "mode": mode,
                    "duration_seconds": round(total_duration, 2),
                    "server_message": finish_resp.get("message", ""),
                    "verified": finish_resp.get("verified", False)
                }
            else:
                err_msg = finish_resp.get("message", "Decryption/Integrity failure on server.")
                self.log("ERROR", f"Transfer failed: {err_msg}")
                return {
                    "success": False,
                    "message": err_msg,
                    "verified": False
                }

        except Exception as e:
            self.log("ERROR", f"Network transfer exception: {e}")
            return {"success": False, "message": f"Transfer exception: {e}"}
        finally:
            if temp_enc_file.exists():
                try:
                    temp_enc_file.unlink()
                except Exception:
                    pass

    def list_server_files(self) -> List[Dict]:
        """Fetch list of user's files stored on the server."""
        if not self.is_connected or not self.session_token:
            return []

        try:
            send_packet(self.sock, OP_REQ_LIST_FILES, {"token": self.session_token})
            opcode, resp = recv_packet(self.sock)
            if opcode == OP_RESP_LIST_FILES and resp.get("status") == STATUS_OK:
                return resp.get("files", [])
        except Exception as e:
            self.log("ERROR", f"Failed to list server files: {e}")
        return []
