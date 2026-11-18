"""
Modern Tkinter Graphical Interface for Client
Handles LAN connection, user login/registration, local AES-256 encryption,
live streaming progress reporting, and SHA-256 verification display.
"""

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional

import config
from client.client_core import TransferClient
from crypto.key_manager import generate_random_key
from crypto.integrity import compute_sha256


class ClientGUI:
    """
    Tkinter Graphical Application for TransferClient.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure LAN File Transfer — Client")
        self.root.geometry("900x700")
        self.root.minsize(780, 580)

        self.client = TransferClient(log_callback=self._append_log)
        self.selected_file_path: Optional[Path] = None

        self._setup_styles()
        self._build_header()
        self._build_main_layout()
        self._build_statusbar()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.bg_color = "#f8fafc"
        self.header_bg = "#0f172a"
        self.card_bg = "#ffffff"
        self.accent_color = "#2563eb"

        self.root.configure(bg=self.bg_color)
        style.configure("TFrame", background=self.bg_color)
        style.configure("Card.TFrame", background=self.card_bg, relief="solid", borderwidth=1)
        style.configure("TNotebook", background=self.bg_color)
        style.configure("TNotebook.Tab", padding=[14, 6], font=("Helvetica", 9, "bold"))
        style.configure("Primary.TButton", font=("Helvetica", 10, "bold"), padding=8)

    def _build_header(self):
        header = tk.Frame(self.root, bg=self.header_bg, height=75)
        header.pack(fill=tk.X, side=tk.TOP)

        title = tk.Label(
            header,
            text="🚀 Secure LAN File Sender (AES-256)",
            font=("Helvetica", 16, "bold"),
            bg=self.header_bg,
            fg="#ffffff"
        )
        title.pack(side=tk.LEFT, padx=20, pady=12)

        subtitle = tk.Label(
            header,
            text="Client-Side Encrypted File Transfer & Integrity Verification",
            font=("Helvetica", 9),
            bg=self.header_bg,
            fg="#94a3b8"
        )
        subtitle.place(x=22, y=42)

        # Connection status badge
        self.lbl_conn_badge = tk.Label(
            header,
            text="DISCONNECTED",
            font=("Helvetica", 9, "bold"),
            bg="#ef4444",
            fg="#ffffff",
            padx=10,
            pady=4,
            relief="flat"
        )
        self.lbl_conn_badge.pack(side=tk.RIGHT, padx=20, pady=18)

    def _build_main_layout(self):
        container = tk.Frame(self.root, bg=self.bg_color)
        container.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

        # Top row: Connection Card (Left) and Authentication Card (Right)
        top_grid = tk.Frame(container, bg=self.bg_color)
        top_grid.pack(fill=tk.X, pady=(0, 8))

        # 1. Server Connection Box
        conn_card = tk.LabelFrame(top_grid, text=" 1. Connect to LAN Server ", font=("Helvetica", 10, "bold"), bg=self.card_bg)
        conn_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6), ipady=4)

        tk.Label(conn_card, text="Server IP / Host:", bg=self.card_bg).grid(row=0, column=0, padx=8, pady=4, sticky="w")
        self.ent_host = tk.Entry(conn_card, width=16)
        self.ent_host.insert(0, config.DEFAULT_CLIENT_HOST)
        self.ent_host.grid(row=0, column=1, padx=6, pady=4, sticky="w")

        tk.Label(conn_card, text="Port:", bg=self.card_bg).grid(row=1, column=0, padx=8, pady=4, sticky="w")
        self.ent_port = tk.Entry(conn_card, width=8)
        self.ent_port.insert(0, str(config.DEFAULT_PORT))
        self.ent_port.grid(row=1, column=1, padx=6, pady=4, sticky="w")

        btn_box = tk.Frame(conn_card, bg=self.card_bg)
        btn_box.grid(row=2, column=0, columnspan=2, pady=6, padx=8, sticky="w")

        self.btn_connect = tk.Button(btn_box, text="Connect", font=("Helvetica", 9, "bold"), bg="#3b82f6", fg="#ffffff", command=self._toggle_connection)
        self.btn_connect.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_ping = tk.Button(btn_box, text="⚡ Ping", font=("Helvetica", 9), command=self._ping_server)
        self.btn_ping.pack(side=tk.LEFT)

        # 2. Authentication Box
        auth_card = tk.LabelFrame(top_grid, text=" 2. User Authentication ", font=("Helvetica", 10, "bold"), bg=self.card_bg)
        auth_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0), ipady=4)

        self.auth_notebook = ttk.Notebook(auth_card)
        self.auth_notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Login Tab
        tab_login = tk.Frame(self.auth_notebook, bg=self.card_bg)
        self.auth_notebook.add(tab_login, text="  Login  ")

        tk.Label(tab_login, text="Username:", bg=self.card_bg).grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.ent_login_user = tk.Entry(tab_login, width=14)
        self.ent_login_user.insert(0, "student")
        self.ent_login_user.grid(row=0, column=1, padx=4, pady=4, sticky="w")

        tk.Label(tab_login, text="Password:", bg=self.card_bg).grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.ent_login_pwd = tk.Entry(tab_login, width=14, show="*")
        self.ent_login_pwd.insert(0, "Student@123")
        self.ent_login_pwd.grid(row=1, column=1, padx=4, pady=4, sticky="w")

        btn_login = tk.Button(tab_login, text="Log In", font=("Helvetica", 9, "bold"), bg="#10b981", fg="#ffffff", command=self._do_login)
        btn_login.grid(row=0, column=2, rowspan=2, padx=10, pady=4)

        # Register Tab
        tab_reg = tk.Frame(self.auth_notebook, bg=self.card_bg)
        self.auth_notebook.add(tab_reg, text="  Register  ")

        tk.Label(tab_reg, text="Username:", bg=self.card_bg).grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.ent_reg_user = tk.Entry(tab_reg, width=14)
        self.ent_reg_user.grid(row=0, column=1, padx=4, pady=4, sticky="w")

        tk.Label(tab_reg, text="Password:", bg=self.card_bg).grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.ent_reg_pwd = tk.Entry(tab_reg, width=14, show="*")
        self.ent_reg_pwd.grid(row=1, column=1, padx=4, pady=4, sticky="w")

        btn_reg = tk.Button(tab_reg, text="Register", font=("Helvetica", 9, "bold"), bg="#6366f1", fg="#ffffff", command=self._do_register)
        btn_reg.grid(row=0, column=2, rowspan=2, padx=10, pady=4)

        # Session Status
        self.lbl_session = tk.Label(auth_card, text="Status: Not logged in", font=("Helvetica", 8, "italic"), fg="#64748b", bg=self.card_bg)
        self.lbl_session.pack(anchor="w", padx=10, pady=(0, 4))

        # 3. File Selection & Encryption Settings
        transfer_card = tk.LabelFrame(container, text=" 3. File Encryption & Transfer Setup ", font=("Helvetica", 10, "bold"), bg=self.card_bg)
        transfer_card.pack(fill=tk.X, pady=6, ipady=6)

        # File Chooser Row
        file_row = tk.Frame(transfer_card, bg=self.card_bg)
        file_row.pack(fill=tk.X, padx=10, pady=4)

        btn_browse = tk.Button(file_row, text="📁 Choose File...", font=("Helvetica", 9, "bold"), command=self._choose_file)
        btn_browse.pack(side=tk.LEFT, padx=(0, 8))

        self.lbl_file_path = tk.Label(file_row, text="No file selected (click Choose File)", font=("Helvetica", 9), fg="#64748b", bg=self.card_bg, anchor="w")
        self.lbl_file_path.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.lbl_file_size = tk.Label(file_row, text="", font=("Helvetica", 9, "bold"), fg="#1e293b", bg=self.card_bg)
        self.lbl_file_size.pack(side=tk.RIGHT, padx=8)

        # Encryption Options Row
        crypto_row = tk.Frame(transfer_card, bg=self.card_bg)
        crypto_row.pack(fill=tk.X, padx=10, pady=6)

        tk.Label(crypto_row, text="AES Mode:", font=("Helvetica", 9, "bold"), bg=self.card_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.cmb_mode = ttk.Combobox(crypto_row, values=["AES-GCM", "AES-CBC"], state="readonly", width=10)
        self.cmb_mode.set("AES-GCM")
        self.cmb_mode.pack(side=tk.LEFT, padx=(0, 14))

        tk.Label(crypto_row, text="Secret Passphrase:", font=("Helvetica", 9, "bold"), bg=self.card_bg).pack(side=tk.LEFT, padx=(0, 4))
        self.ent_passphrase = tk.Entry(crypto_row, width=28)
        self.ent_passphrase.insert(0, "SecureLANFileTransferKey2026")
        self.ent_passphrase.pack(side=tk.LEFT, padx=(0, 6))

        btn_rand_key = tk.Button(crypto_row, text="🎲 Random Key", font=("Helvetica", 8), command=self._generate_random_key)
        btn_rand_key.pack(side=tk.LEFT, padx=(0, 10))

        # Big Action Button
        self.btn_send = tk.Button(
            transfer_card,
            text="🔒 Encrypt & Send File Across LAN",
            font=("Helvetica", 11, "bold"),
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            padx=16,
            pady=8,
            cursor="hand2",
            command=self._start_transfer_thread
        )
        self.btn_send.pack(padx=10, pady=6)

        # 4. Progress and Verification Card
        prog_card = tk.LabelFrame(container, text=" Transfer Progress & Bit-Level Integrity Verification ", font=("Helvetica", 10, "bold"), bg=self.card_bg)
        prog_card.pack(fill=tk.X, pady=6, ipady=4)

        self.progress_bar = ttk.Progressbar(prog_card, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill=tk.X, padx=12, pady=(6, 2))

        self.lbl_progress = tk.Label(prog_card, text="Idle. Waiting to initiate transfer.", font=("Helvetica", 9), bg=self.card_bg, fg="#475569")
        self.lbl_progress.pack(anchor="w", padx=12, pady=(0, 4))

        # Verification result label
        self.lbl_verify_result = tk.Label(prog_card, text="", font=("Helvetica", 10, "bold"), bg=self.card_bg)
        self.lbl_verify_result.pack(anchor="w", padx=12, pady=(0, 4))

        # 5. Scrolled Log Console
        log_frame = tk.LabelFrame(container, text=" Transmission & Cryptography Log ", font=("Helvetica", 9, "bold"), bg=self.bg_color)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self.txt_log = tk.Text(log_frame, bg="#0f172a", fg="#f8fafc", font=("Courier", 9), height=7)
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)

        scroll = tk.Scrollbar(log_frame, command=self.txt_log.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_log.config(yscrollcommand=scroll.set)

    def _build_statusbar(self):
        self.statusbar = tk.Label(
            self.root,
            text="Ready | Client-side AES-256 GCM/CBC File Transfer",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            font=("Helvetica", 9),
            bg="#e2e8f0",
            fg="#475569",
            padx=10,
            pady=3
        )
        self.statusbar.pack(side=tk.BOTTOM, fill=tk.X)

    def _append_log(self, level: str, message: str):
        def _ins():
            ts = time.strftime("%H:%M:%S")
            line = f"[{ts}] [{level:<7}] {message}\n"
            self.txt_log.insert(tk.END, line)
            self.txt_log.see(tk.END)
        self.root.after(0, _ins)

    def _generate_random_key(self):
        key = generate_random_key()
        self.ent_passphrase.delete(0, tk.END)
        self.ent_passphrase.insert(0, key)
        self._append_log("CRYPTO", f"Generated fresh 256-bit symmetric key: {key[:12]}...")

    def _toggle_connection(self):
        if not self.client.is_connected:
            host = self.ent_host.get().strip()
            try:
                port = int(self.ent_port.get().strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid port number.")
                return

            self.client.server_host = host
            self.client.server_port = port

            ok, msg = self.client.connect()
            if ok:
                self.btn_connect.config(text="Disconnect", bg="#dc2626")
                self.lbl_conn_badge.config(text=f"CONNECTED ({host}:{port})", bg="#16a34a")
                self.statusbar.config(text=f"Connected to {host}:{port}")
            else:
                messagebox.showerror("Connection Failed", msg)
        else:
            self.client.disconnect()
            self.btn_connect.config(text="Connect", bg="#3b82f6")
            self.lbl_conn_badge.config(text="DISCONNECTED", bg="#ef4444")
            self.lbl_session.config(text="Status: Not logged in", fg="#64748b")
            self.statusbar.config(text="Disconnected from server.")

    def _ping_server(self):
        if not self.client.is_connected:
            messagebox.showwarning("Warning", "Please connect to server first.")
            return
        ok, rtt = self.client.ping()
        if ok:
            messagebox.showinfo("Ping", f"Server pong received! Round-Trip Time: {rtt:.2f} ms")
        else:
            messagebox.showerror("Ping Failed", "Server did not respond to ping.")

    def _do_login(self):
        if not self.client.is_connected:
            messagebox.showwarning("Warning", "Please connect to server first.")
            return

        uname = self.ent_login_user.get().strip()
        pwd = self.ent_login_pwd.get().strip()
        if not uname or not pwd:
            messagebox.showwarning("Warning", "Enter username and password.")
            return

        ok, msg = self.client.login(uname, pwd)
        if ok:
            self.lbl_session.config(
                text=f"✅ Logged in as: {uname} (Token: {self.client.session_token[:10]}...)",
                fg="#16a34a",
                font=("Helvetica", 9, "bold")
            )
            messagebox.showinfo("Login Success", f"Welcome, {uname}! Authentication successful.")
        else:
            messagebox.showerror("Login Failed", msg)

    def _do_register(self):
        if not self.client.is_connected:
            messagebox.showwarning("Warning", "Please connect to server first.")
            return

        uname = self.ent_reg_user.get().strip()
        pwd = self.ent_reg_pwd.get().strip()
        if not uname or not pwd:
            messagebox.showwarning("Warning", "Enter username and password.")
            return

        ok, msg = self.client.register(uname, pwd)
        if ok:
            messagebox.showinfo("Registration Success", msg + "\nYou can now switch to the Login tab.")
            self.ent_login_user.delete(0, tk.END)
            self.ent_login_user.insert(0, uname)
            self.ent_login_pwd.delete(0, tk.END)
            self.ent_login_pwd.insert(0, pwd)
            self.auth_notebook.select(0)
        else:
            messagebox.showerror("Registration Failed", msg)

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Select File to Encrypt & Send")
        if path:
            self.selected_file_path = Path(path)
            size = self.selected_file_path.stat().st_size
            self.lbl_file_path.config(text=str(self.selected_file_path.name), fg="#0f172a")
            self.lbl_file_size.config(text=f"Size: {size:,} bytes")
            self.lbl_verify_result.config(text="")
            self._append_log("INFO", f"Selected file: {self.selected_file_path.name} ({size} bytes)")

    def _start_transfer_thread(self):
        if not self.client.is_connected:
            messagebox.showwarning("Warning", "Connect to server first.")
            return
        if not self.client.session_token:
            messagebox.showwarning("Warning", "Log in first before transferring files.")
            return
        if not self.selected_file_path or not self.selected_file_path.is_file():
            messagebox.showwarning("Warning", "Please choose a valid file to send.")
            return

        passphrase = self.ent_passphrase.get().strip()
        if not passphrase:
            messagebox.showwarning("Warning", "Enter a secret passphrase for AES encryption.")
            return

        mode = self.cmb_mode.get()
        self.btn_send.config(state=tk.DISABLED, text="⏳ Transferring...")
        self.lbl_verify_result.config(text="")

        threading.Thread(
            target=self._execute_transfer,
            args=(self.selected_file_path, passphrase, mode),
            daemon=True
        ).start()

    def _execute_transfer(self, file_path: Path, passphrase: str, mode: str):
        def _on_progress(sent, total, pct, speed):
            self.root.after(0, lambda: self._update_progress_ui(sent, total, pct, speed))

        result = self.client.send_file(
            file_path=file_path,
            passphrase=passphrase,
            mode=mode,
            progress_callback=_on_progress
        )

        self.root.after(0, lambda: self._handle_transfer_complete(result))

    def _update_progress_ui(self, sent: int, total: int, pct: float, speed: float):
        self.progress_bar["value"] = pct
        self.lbl_progress.config(
            text=f"Transferring: {sent:,} / {total:,} bytes ({pct:.1f}%) | Speed: {speed:.1f} KB/s"
        )

    def _handle_transfer_complete(self, result: dict):
        self.btn_send.config(state=tk.NORMAL, text="🔒 Encrypt & Send File Across LAN")

        if result.get("success"):
            self.progress_bar["value"] = 100
            msg = (
                f"✅ SUCCESS! File '{result['filename']}' transferred and decrypted.\n"
                f"• Verified Bit-Exact SHA-256: {result['original_sha256']}\n"
                f"• Cipher: AES-256 ({result['mode']}) | Time: {result['duration_seconds']}s"
            )
            self.lbl_verify_result.config(text=msg, fg="#16a34a")
            messagebox.showinfo("Transfer Verified", f"Transfer Complete & Decrypted!\n\nSHA-256 Checksum Verified:\n{result['original_sha256']}")
        else:
            self.lbl_verify_result.config(
                text=f"❌ FAILED: {result.get('message')}",
                fg="#dc2626"
            )
            messagebox.showerror("Transfer Error", result.get("message", "Unknown error"))

    def _on_close(self):
        if self.client.is_connected:
            self.client.disconnect()
        self.root.destroy()


def run_client_gui():
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_client_gui()
