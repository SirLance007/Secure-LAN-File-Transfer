"""
Server File Storage and Sandbox Manager
Manages storage directories, prevents path traversal attacks, and tracks file metadata.
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Optional
import config
from crypto.integrity import compute_sha256


class StorageManager:
    """
    Manages safe storage of uploaded files on the server.
    """

    def __init__(self, storage_dir: Path = config.SERVER_STORAGE_DIR):
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent directory traversal attacks (e.g. ../../etc/passwd).
        """
        base = os.path.basename(filename).strip()
        # Remove null bytes or risky characters
        safe_name = "".join(c for c in base if c.isalnum() or c in "._- ")
        if not safe_name or safe_name in (".", ".."):
            safe_name = f"upload_{int(time.time())}.bin"
        return safe_name

    def get_destination_path(self, username: str, filename: str) -> Path:
        """
        Compute sanitized safe destination path inside the server storage folder.
        Files are organized by user folders for multi-user isolation.
        """
        safe_name = self.sanitize_filename(filename)
        safe_user = self.sanitize_filename(username)
        user_dir = self.storage_dir / safe_user
        user_dir.mkdir(parents=True, exist_ok=True)

        target_path = user_dir / safe_name
        # Prevent collisions by appending timestamp if exists
        if target_path.exists():
            stem = target_path.stem
            suffix = target_path.suffix
            timestamp = int(time.time())
            target_path = user_dir / f"{stem}_{timestamp}{suffix}"

        # Path traversal guard
        if not str(target_path.resolve()).startswith(str(self.storage_dir)):
            raise ValueError("Path traversal attempt detected!")

        return target_path

    def list_files(self, username: Optional[str] = None) -> List[Dict]:
        """
        List all received files on the server with sizes, dates, and SHA-256 hashes.
        """
        files_info = []
        target_dir = self.storage_dir
        if username:
            safe_user = self.sanitize_filename(username)
            target_dir = self.storage_dir / safe_user
            if not target_dir.exists():
                return []

        for p in target_dir.rglob("*"):
            if p.is_file() and not p.name.startswith("."):
                try:
                    stat = p.stat()
                    # Owner is the parent directory name if under user subfolder
                    owner = p.parent.name if p.parent != self.storage_dir else "public"
                    files_info.append({
                        "filename": p.name,
                        "rel_path": str(p.relative_to(self.storage_dir)),
                        "size": stat.st_size,
                        "owner": owner,
                        "uploaded_at": stat.st_mtime,
                        "sha256": compute_sha256(p)
                    })
                except Exception:
                    continue

        return files_info
