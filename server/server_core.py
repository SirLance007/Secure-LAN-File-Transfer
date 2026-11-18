"""
Multi-Threaded TCP Socket Server Engine
Listens on LAN interfaces, manages concurrent client threads, enforces authentication,
receives AES-encrypted files, performs on-the-fly decryption, and validates integrity.
"""

import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional, Dict, Any

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
from crypto.aes_cipher import AESCipher, AuthenticationFailedError, CryptoError
from crypto.key_manager import derive_key
from crypto.integrity import compute_sha256
from server.auth import AuthManager
from server.storage import StorageManager


class FileTransferServer:
    """
    Core Server handling TCP connections, user authentication, and secure file reception.
    """

    def __init__(
        self,
        host: str = config.DEFAULT_HOST,
        port: int = config.DEFAULT_PORT,
        shared_secret: str = "SecureLANFileTransferKey2026",
        event_callback: Optional[Callable[[str, str, str], None]] = None,
        db_path: Path = config.SERVER_DB_PATH,
        storage_dir: Path = config.SERVER_STORAGE_DIR
    ):
        self.host = host
        self.port = port
        self.shared_secret = shared_secret
        self.event_callback = event_callback  # Callback: (level, category, message)
        self.auth_manager = AuthManager(db_path)
        self.storage_manager = StorageManager(storage_dir)

        self._server_socket: Optional[socket.socket] = None
        self._is_running = False
        self._listener_thread: Optional[threading.Thread] = None
        self._client_threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()

    def log(self, level: str, category: str, message: str) -> None:
        """Internal logging with notification to optional callback."""
        timestamp = time.strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level.upper()}] [{category}] {message}"
        # Print to console
        print(formatted)
        if self.event_callback:
            try:
                self.event_callback(level, category, message)
            except Exception:
                pass

    @staticmethod
    def get_lan_ip() -> str:
        """
        Detect the host's actual LAN IP address (e.g. 192.168.x.x)
        by opening a dummy UDP socket to a routable IP without transmitting data.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Does not send packets, just asks OS for routing interface
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
        except Exception:
            lan_ip = "127.0.0.1"
        finally:
            s.close()
        return lan_ip

    def start(self) -> bool:
        """Start the socket listener in a background daemon thread."""
        if self._is_running:
            return True

        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow rapid restart without 'Address already in use' error
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(10)
            self._is_running = True

            self._listener_thread = threading.Thread(
                target=self._listen_loop,
                name="ServerListenerThread",
                daemon=True
            )
            self._listener_thread.start()

            lan_ip = self.get_lan_ip()
            self.log("INFO", "SERVER", f"Server started. Listening on {self.host}:{self.port} (LAN IP: {lan_ip})")
            return True
        except Exception as e:
            self.log("ERROR", "SERVER", f"Failed to start server: {e}")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop server and close all client connections."""
        self._is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        self.log("INFO", "SERVER", "Server stopped.")

    def _listen_loop(self) -> None:
        """Main listening loop accepting incoming client connections."""
        while self._is_running:
            try:
                client_sock, client_addr = self._server_socket.accept()
                client_id = f"{client_addr[0]}:{client_addr[1]}"
                self.log("INFO", "CONNECT", f"Accepted connection from {client_id}")

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    name=f"ClientThread-{client_id}",
                    daemon=True
                )
                with self._lock:
                    self._client_threads[client_id] = t
                t.start()
            except (OSError, socket.error):
                # Socket was closed or shutdown
                break
            except Exception as e:
                if self._is_running:
                    self.log("ERROR", "SERVER", f"Error accepting connection: {e}")

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        """
        Handle all requests from an individual client connection session.
        """
        client_id = f"{client_addr[0]}:{client_addr[1]}"
        client_ip = client_addr[0]
        authenticated_user: Optional[str] = None
        current_upload_state: Optional[Dict[str, Any]] = None

        try:
            client_sock.settimeout(config.SOCKET_TIMEOUT)

            while self._is_running:
                try:
                    opcode, payload = recv_packet(client_sock)
                except ConnectionClosedError:
                    self.log("INFO", "DISCONNECT", f"Client {client_id} disconnected.")
                    break
                except socket.timeout:
                    # Keepalive check or timeout
                    continue

                # 1. PING / HEARTBEAT
                if opcode == OP_HEARTBEAT_PING:
                    send_packet(client_sock, OP_HEARTBEAT_PONG, {"status": STATUS_OK, "time": time.time()})
                    continue

                # 2. USER REGISTRATION
                if opcode == OP_REQ_REGISTER:
                    uname = payload.get("username", "")
                    pwd = payload.get("password", "")
                    success, msg = self.auth_manager.register(uname, pwd, client_ip)
                    self.log("AUTH", "REGISTER", f"Registration for '{uname}' from {client_id}: {msg}")
                    send_packet(client_sock, OP_RESP_REGISTER, {
                        "status": STATUS_OK if success else STATUS_ERROR,
                        "message": msg
                    })
                    continue

                # 3. USER LOGIN
                if opcode == OP_REQ_LOGIN:
                    uname = payload.get("username", "")
                    pwd = payload.get("password", "")
                    success, msg, token = self.auth_manager.authenticate(uname, pwd, client_ip)
                    if success:
                        authenticated_user = uname
                        self.log("AUTH", "LOGIN", f"User '{uname}' logged in successfully from {client_id}")
                        send_packet(client_sock, OP_RESP_LOGIN, {
                            "status": STATUS_OK,
                            "message": msg,
                            "token": token,
                            "username": uname
                        })
                    else:
                        self.log("WARNING", "LOGIN_FAIL", f"Failed login attempt for '{uname}' from {client_id}")
                        send_packet(client_sock, OP_RESP_LOGIN, {
                            "status": STATUS_UNAUTHORIZED,
                            "message": msg,
                            "token": None
                        })
                    continue

                # --- PROTECTED OPERATIONS BELOW REQUIRE AUTHENTICATION ---
                # Check session token
                token = payload.get("token") if isinstance(payload, dict) else None
                validated_user = self.auth_manager.validate_token(token) if token else authenticated_user

                if not validated_user:
                    self.log("WARNING", "AUTH_GUARD", f"Unauthorized request opcode={opcode} from {client_id}")
                    send_packet(client_sock, OP_ERR_GENERIC, {
                        "status": STATUS_UNAUTHORIZED,
                        "message": "Authentication required. Please log in first."
                    })
                    continue

                authenticated_user = validated_user

                # 4. FILE UPLOAD INITIALIZATION
                if opcode == OP_REQ_UPLOAD_INIT:
                    meta = payload
                    filename = meta.get("filename", "unknown.bin")
                    orig_size = meta.get("original_size", 0)
                    enc_size = meta.get("encrypted_size", 0)
                    mode = meta.get("mode", config.DEFAULT_AES_MODE)

                    self.log("TRANSFER", "UPLOAD_INIT",
                             f"User '{authenticated_user}' initiating transfer of '{filename}' "
                             f"({orig_size} bytes, Mode: {mode})")

                    # Create temporary file path for encrypted payload
                    temp_enc_path = config.SERVER_STORAGE_DIR / f".tmp_{int(time.time()*1000)}_{filename}.enc"

                    current_upload_state = {
                        "filename": filename,
                        "original_size": orig_size,
                        "original_sha256": meta.get("original_sha256"),
                        "encrypted_size": enc_size,
                        "mode": mode,
                        "salt": bytes.fromhex(meta.get("salt_hex", "")),
                        "iv_nonce": bytes.fromhex(meta.get("iv_nonce_hex", "")),
                        "tag_hmac": bytes.fromhex(meta.get("tag_hmac_hex", "")),
                        "temp_enc_path": temp_enc_path,
                        "bytes_received": 0,
                        "secret_passphrase": meta.get("secret_passphrase") or self.shared_secret
                    }

                    # Open temp encrypted file for writing
                    temp_enc_path.parent.mkdir(parents=True, exist_ok=True)
                    current_upload_state["file_handle"] = open(temp_enc_path, "wb")

                    send_packet(client_sock, OP_RESP_UPLOAD_INIT, {
                        "status": STATUS_OK,
                        "message": "Ready to receive encrypted chunks."
                    })
                    continue

                # 5. FILE CHUNK ARRIVAL
                if opcode == OP_FILE_CHUNK:
                    if not current_upload_state or "file_handle" not in current_upload_state:
                        send_packet(client_sock, OP_ERR_GENERIC, {
                            "status": STATUS_ERROR,
                            "message": "No active upload initialization found."
                        })
                        continue

                    # In OP_FILE_CHUNK, payload is raw encrypted bytes
                    chunk_bytes = payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
                    current_upload_state["file_handle"].write(chunk_bytes)
                    current_upload_state["bytes_received"] += len(chunk_bytes)
                    continue

                # 6. FILE UPLOAD COMPLETION & DECRYPTION
                if opcode == OP_REQ_UPLOAD_FINISH:
                    if not current_upload_state:
                        send_packet(client_sock, OP_ERR_GENERIC, {
                            "status": STATUS_ERROR,
                            "message": "Upload state missing."
                        })
                        continue

                    # Close temporary encrypted file handle
                    if "file_handle" in current_upload_state:
                        current_upload_state["file_handle"].close()
                        del current_upload_state["file_handle"]

                    temp_enc_path = current_upload_state["temp_enc_path"]
                    filename = current_upload_state["filename"]
                    mode = current_upload_state["mode"]
                    salt = current_upload_state["salt"]
                    iv_nonce = current_upload_state["iv_nonce"]
                    tag_hmac = current_upload_state["tag_hmac"]
                    passphrase = current_upload_state["secret_passphrase"]
                    orig_sha256 = current_upload_state["original_sha256"]

                    self.log("CRYPTO", "DECRYPT_START",
                             f"Decrypting received ciphertext for '{filename}' with AES-256 ({mode})...")

                    try:
                        # 1. Derive identical 256-bit AES key using PBKDF2 with received salt
                        derived_key = derive_key(passphrase, salt)

                        # 2. Get safe final destination path
                        final_dest = self.storage_manager.get_destination_path(authenticated_user, filename)

                        # 3. Decrypt and verify tag/HMAC + SHA-256
                        decrypt_result = AESCipher.decrypt_file(
                            encrypted_path=temp_enc_path,
                            dest_path=final_dest,
                            key=derived_key,
                            iv_nonce=iv_nonce,
                            tag_hmac=tag_hmac,
                            mode=mode,
                            associated_data=filename.encode("utf-8"),
                            expected_sha256=orig_sha256
                        )

                        # Decryption & verification succeeded!
                        self.log("CRYPTO", "DECRYPT_SUCCESS",
                                 f"Successfully decrypted '{filename}'! SHA-256 verified: {orig_sha256[:16]}...")
                        self.auth_manager.log_event(
                            authenticated_user,
                            "FILE_RECEIVED",
                            client_ip,
                            f"Saved '{filename}' ({decrypt_result['decrypted_size']} bytes, verified SHA-256)"
                        )

                        # Clean up temp ciphertext
                        if temp_enc_path.exists():
                            temp_enc_path.unlink()

                        send_packet(client_sock, OP_RESP_UPLOAD_FINISH, {
                            "status": STATUS_OK,
                            "message": f"File '{filename}' received, decrypted, and verified successfully.",
                            "filename": final_dest.name,
                            "size": decrypt_result["decrypted_size"],
                            "sha256": decrypt_result["decrypted_sha256"],
                            "verified": True
                        })

                    except AuthenticationFailedError as e:
                        self.log("ERROR", "INTEGRITY_FAIL", f"Decryption/Integrity check failed for '{filename}': {e}")
                        if temp_enc_path.exists():
                            temp_enc_path.unlink()
                        send_packet(client_sock, OP_RESP_UPLOAD_FINISH, {
                            "status": STATUS_ERROR,
                            "message": f"Integrity check failed: {str(e)}",
                            "verified": False
                        })
                    except Exception as e:
                        self.log("ERROR", "DECRYPT_ERROR", f"Error during decryption of '{filename}': {e}")
                        if temp_enc_path.exists():
                            temp_enc_path.unlink()
                        send_packet(client_sock, OP_RESP_UPLOAD_FINISH, {
                            "status": STATUS_ERROR,
                            "message": f"Decryption error: {str(e)}",
                            "verified": False
                        })
                    finally:
                        current_upload_state = None
                    continue

                # 7. LIST STORED FILES
                if opcode == OP_REQ_LIST_FILES:
                    files = self.storage_manager.list_files(authenticated_user)
                    send_packet(client_sock, OP_RESP_LIST_FILES, {
                        "status": STATUS_OK,
                        "files": files
                    })
                    continue

                # Unhandled opcode
                send_packet(client_sock, OP_ERR_GENERIC, {
                    "status": STATUS_ERROR,
                    "message": f"Unsupported opcode: {opcode}"
                })

        except Exception as e:
            self.log("ERROR", "CLIENT_ERR", f"Unhandled error with client {client_id}: {e}")
        finally:
            if current_upload_state and "file_handle" in current_upload_state:
                try:
                    current_upload_state["file_handle"].close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self._client_threads.pop(client_id, None)
            self.log("INFO", "DISCONNECT", f"Connection cleaned up for {client_id}")
