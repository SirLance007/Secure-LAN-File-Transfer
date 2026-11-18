"""
Modern Tkinter Graphical Interface for Server
Provides live connection monitoring, LAN IP discovery, real-time logging,
user management, and received file inspection.
"""

import os
import sys
import time
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Optional

import config
from server.server_core import FileTransferServer


class ServerGUI:
    """
    Tkinter Graphical Dashboard for FileTransferServer.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure LAN File Transfer — Server Dashboard")
        self.root.geometry("880x640")
        self.root.minsize(760, 520)

        # Server instance
        self.server: Optional[FileTransferServer] = None
        self.is_running = False

        # Apply Modern Styling
        self._setup_styles()

        # Build UI Components
        self._build_header()
        self._build_tabs()
        self._build_statusbar()

        # Update LAN IP display
        self._refresh_lan_ip()

        # Auto-start server for immediate convenience
        self.root.after(200, self._toggle_server)

        # Handle clean window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Configure colors
        self.bg_color = "#f4f6f9"
        self.header_bg = "#1e293b"
        self.accent_color = "#2563eb"
        self.success_color = "#16a34a"
        self.danger_color = "#dc2626"

        self.root.configure(bg=self.bg_color)
        style.configure("TNotebook", background=self.bg_color)
        style.configure("TNotebook.Tab", padding=[16, 8], font=("Helvetica", 10, "bold"))
        style.configure("TFrame", background=self.bg_color)
        style.configure("Card.TFrame", background="#ffffff", relief="flat")
        style.configure("Action.TButton", font=("Helvetica", 10, "bold"), padding=6)

    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=self.header_bg, height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)

        title_label = tk.Label(
            header_frame,
            text="🛡️ Secure LAN File Transfer Server",
            font=("Helvetica", 16, "bold"),
            bg=self.header_bg,
            fg="#ffffff"
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=16)

        subtitle_label = tk.Label(
            header_frame,
            text="AES-256 Authenticated Encryption | Socket Programming",
            font=("Helvetica", 9),
            bg=self.header_bg,
            fg="#94a3b8"
        )
        subtitle_label.place(x=22, y=44)

        # Toggle Server Button
        self.btn_toggle = tk.Button(
            header_frame,
            text="▶ Start Server",
            font=("Helvetica", 10, "bold"),
            bg="#22c55e",
            fg="#ffffff",
            activebackground="#16a34a",
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self._toggle_server
        )
        self.btn_toggle.pack(side=tk.RIGHT, padx=20, pady=16)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

        # Tab 1: Live Monitor & Logs
        self.tab_monitor = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_monitor, text="  Live Monitor  ")
        self._build_monitor_tab()

        # Tab 2: Received Decrypted Files
        self.tab_files = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_files, text="  Received Files  ")
        self._build_files_tab()

        # Tab 3: Registered Users
        self.tab_users = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_users, text="  User Accounts  ")
        self._build_users_tab()

        # Tab 4: Server Settings
        self.tab_settings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_settings, text="  Settings  ")
        self._build_settings_tab()

    def _build_monitor_tab(self):
        # Top Info Card
        card = tk.Frame(self.tab_monitor, bg="#ffffff", bd=1, relief="solid")
        card.pack(fill=tk.X, padx=10, pady=10)

        # Grid inside card
        tk.Label(card, text="Server Status:", font=("Helvetica", 10, "bold"), bg="#ffffff").grid(row=0, column=0, padx=14, pady=10, sticky="w")
        self.lbl_status = tk.Label(card, text="STOPPED", font=("Helvetica", 10, "bold"), fg="#dc2626", bg="#ffffff")
        self.lbl_status.grid(row=0, column=1, padx=6, pady=10, sticky="w")

        tk.Label(card, text="LAN Host IP:", font=("Helvetica", 10, "bold"), bg="#ffffff").grid(row=0, column=2, padx=14, pady=10, sticky="w")
        self.lbl_ip = tk.Label(card, text="Detecting...", font=("Courier", 10, "bold"), fg="#1e293b", bg="#ffffff")
        self.lbl_ip.grid(row=0, column=3, padx=6, pady=10, sticky="w")

        btn_copy_ip = tk.Button(card, text="Copy IP", font=("Helvetica", 8), command=self._copy_ip, relief="groove")
        btn_copy_ip.grid(row=0, column=4, padx=6, pady=10)

        tk.Label(card, text="Port:", font=("Helvetica", 10, "bold"), bg="#ffffff").grid(row=0, column=5, padx=14, pady=10, sticky="w")
        self.lbl_port = tk.Label(card, text=str(config.DEFAULT_PORT), font=("Courier", 10, "bold"), fg="#1e293b", bg="#ffffff")
        self.lbl_port.grid(row=0, column=6, padx=6, pady=10, sticky="w")

        # Scrolled Text for Real-time Logs
        log_frame = tk.LabelFrame(self.tab_monitor, text=" Real-Time Server Activity & Crypto Log ", bg=self.bg_color, font=("Helvetica", 10, "bold"))
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        self.txt_log = tk.Text(log_frame, bg="#0f172a", fg="#f8fafc", font=("Courier", 9), insertbackground="#ffffff")
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        scroll = tk.Scrollbar(log_frame, command=self.txt_log.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_log.config(yscrollcommand=scroll.set)

        # Log color tags
        self.txt_log.tag_config("INFO", foreground="#38bdf8")
        self.txt_log.tag_config("SUCCESS", foreground="#4ade80")
        self.txt_log.tag_config("WARNING", foreground="#facc15")
        self.txt_log.tag_config("ERROR", foreground="#f87171")
        self.txt_log.tag_config("CRYPTO", foreground="#c084fc")
        self.txt_log.tag_config("AUTH", foreground="#fb923c")

        # Bottom buttons for log
        btn_bar = tk.Frame(self.tab_monitor, bg=self.bg_color)
        btn_bar.pack(fill=tk.X, padx=10, pady=4)
        tk.Button(btn_bar, text="Clear Log", font=("Helvetica", 9), command=lambda: self.txt_log.delete("1.0", tk.END)).pack(side=tk.RIGHT)

    def _build_files_tab(self):
        btn_frame = tk.Frame(self.tab_files, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, padx=10, pady=8)

        tk.Button(btn_frame, text="🔄 Refresh Files", font=("Helvetica", 9, "bold"), command=self._refresh_files).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="📂 Open Storage Directory", font=("Helvetica", 9), command=self._open_storage_folder).pack(side=tk.LEFT, padx=4)

        columns = ("filename", "size", "owner", "sha256", "date")
        self.tree_files = ttk.Treeview(self.tab_files, columns=columns, show="headings", height=15)
        self.tree_files.heading("filename", text="Filename")
        self.tree_files.heading("size", text="Size (Bytes)")
        self.tree_files.heading("owner", text="Uploader")
        self.tree_files.heading("sha256", text="SHA-256 Digest")
        self.tree_files.heading("date", text="Received At")

        self.tree_files.column("filename", width=180)
        self.tree_files.column("size", width=90, anchor="e")
        self.tree_files.column("owner", width=90, anchor="center")
        self.tree_files.column("sha256", width=260)
        self.tree_files.column("date", width=140)

        self.tree_files.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

    def _build_users_tab(self):
        top_bar = tk.Frame(self.tab_users, bg=self.bg_color)
        top_bar.pack(fill=tk.X, padx=10, pady=8)

        tk.Button(top_bar, text="🔄 Refresh Users", font=("Helvetica", 9, "bold"), command=self._refresh_users).pack(side=tk.LEFT, padx=4)

        # Quick add user frame
        add_frame = tk.LabelFrame(self.tab_users, text=" Register New User (Server Admin) ", bg=self.bg_color, font=("Helvetica", 10, "bold"))
        add_frame.pack(fill=tk.X, padx=10, pady=6)

        tk.Label(add_frame, text="Username:", bg=self.bg_color).grid(row=0, column=0, padx=8, pady=8)
        self.ent_new_uname = tk.Entry(add_frame, width=16)
        self.ent_new_uname.grid(row=0, column=1, padx=6, pady=8)

        tk.Label(add_frame, text="Password:", bg=self.bg_color).grid(row=0, column=2, padx=8, pady=8)
        self.ent_new_pwd = tk.Entry(add_frame, width=18, show="*")
        self.ent_new_pwd.grid(row=0, column=3, padx=6, pady=8)

        tk.Button(add_frame, text="Add Account", font=("Helvetica", 9, "bold"), bg=self.accent_color, fg="#ffffff", command=self._create_user_admin).grid(row=0, column=4, padx=12, pady=8)

        # User List Table
        columns = ("id", "username", "created", "last_login")
        self.tree_users = ttk.Treeview(self.tab_users, columns=columns, show="headings", height=12)
        self.tree_users.heading("id", text="ID")
        self.tree_users.heading("username", text="Username")
        self.tree_users.heading("created", text="Created At")
        self.tree_users.heading("last_login", text="Last Login")

        self.tree_users.column("id", width=50, anchor="center")
        self.tree_users.column("username", width=150)
        self.tree_users.column("created", width=180)
        self.tree_users.column("last_login", width=180)

        self.tree_users.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

    def _build_settings_tab(self):
        settings_frame = tk.Frame(self.tab_settings, bg=self.bg_color)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(settings_frame, text="Server Configuration", font=("Helvetica", 12, "bold"), bg=self.bg_color).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))

        tk.Label(settings_frame, text="Listening Port:", font=("Helvetica", 10), bg=self.bg_color).grid(row=1, column=0, sticky="w", pady=6)
        self.ent_port = tk.Entry(settings_frame, width=12)
        self.ent_port.insert(0, str(config.DEFAULT_PORT))
        self.ent_port.grid(row=1, column=1, sticky="w", pady=6)

        tk.Label(settings_frame, text="Shared Secret Passphrase:", font=("Helvetica", 10), bg=self.bg_color).grid(row=2, column=0, sticky="w", pady=6)
        self.ent_secret = tk.Entry(settings_frame, width=32)
        self.ent_secret.insert(0, "SecureLANFileTransferKey2026")
        self.ent_secret.grid(row=2, column=1, sticky="w", pady=6)

        tk.Label(settings_frame, text="Storage Directory:", font=("Helvetica", 10), bg=self.bg_color).grid(row=3, column=0, sticky="w", pady=6)
        self.lbl_storage_dir = tk.Label(settings_frame, text=str(config.SERVER_STORAGE_DIR), font=("Courier", 9), bg="#e2e8f0", padx=6, pady=4)
        self.lbl_storage_dir.grid(row=3, column=1, sticky="w", pady=6)

    def _build_statusbar(self):
        self.statusbar = tk.Label(
            self.root,
            text="Ready | Academic LAN File Transfer Server (AES-256)",
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

    def _refresh_lan_ip(self):
        lan_ip = FileTransferServer.get_lan_ip()
        self.lbl_ip.config(text=lan_ip)

    def _copy_ip(self):
        ip = self.lbl_ip.cget("text")
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        messagebox.showinfo("Copied", f"LAN IP '{ip}' copied to clipboard!")

    def _append_log(self, level: str, category: str, message: str):
        def _insert():
            ts = time.strftime("%H:%M:%S")
            line = f"[{ts}] [{level:<7}] [{category:<12}] {message}\n"
            tag = level.upper() if level.upper() in ("INFO", "SUCCESS", "WARNING", "ERROR", "CRYPTO", "AUTH") else "INFO"
            self.txt_log.insert(tk.END, line, tag)
            self.txt_log.see(tk.END)
        self.root.after(0, _insert)

    def _toggle_server(self):
        if not self.is_running:
            # Start Server
            try:
                port = int(self.ent_port.get().strip())
                secret = self.ent_secret.get().strip()
            except ValueError:
                messagebox.showerror("Invalid Input", "Port must be an integer.")
                return

            self.server = FileTransferServer(
                host="0.0.0.0",
                port=port,
                shared_secret=secret,
                event_callback=self._append_log
            )
            started = self.server.start()
            if started:
                self.is_running = True
                self.btn_toggle.config(text="⏹ Stop Server", bg="#dc2626", activebackground="#b91c1c")
                self.lbl_status.config(text="RUNNING", fg="#16a34a")
                self.lbl_port.config(text=str(port))
                self.statusbar.config(text=f"Server Active | Listening on 0.0.0.0:{port}")
                self._refresh_users()
                self._refresh_files()
            else:
                messagebox.showerror("Error", "Failed to start socket server. Port may be occupied.")
        else:
            # Stop Server
            if self.server:
                self.server.stop()
            self.is_running = False
            self.btn_toggle.config(text="▶ Start Server", bg="#22c55e", activebackground="#16a34a")
            self.lbl_status.config(text="STOPPED", fg="#dc2626")
            self.statusbar.config(text="Server Stopped.")

    def _refresh_files(self):
        for item in self.tree_files.get_children():
            self.tree_files.delete(item)

        if not self.server:
            return

        files = self.server.storage_manager.list_files()
        for f in files:
            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f["uploaded_at"]))
            self.tree_files.insert("", tk.END, values=(
                f["filename"],
                f"{f['size']:,}",
                f["owner"],
                f"{f['sha256'][:16]}...",
                mtime_str
            ))

    def _open_storage_folder(self):
        folder = str(config.SERVER_STORAGE_DIR.resolve())
        if sys.platform == "darwin":
            subprocess.Popen(["open", folder])
        elif sys.platform == "win32":
            os.startfile(folder)
        else:
            subprocess.Popen(["xdg-open", folder])

    def _refresh_users(self):
        for item in self.tree_users.get_children():
            self.tree_users.delete(item)

        if not self.server:
            return

        users = self.server.auth_manager.list_users()
        for u in users:
            c_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(u["created_at"]))
            l_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(u["last_login"])) if u.get("last_login") else "Never"
            self.tree_users.insert("", tk.END, values=(u["id"], u["username"], c_time, l_time))

    def _create_user_admin(self):
        uname = self.ent_new_uname.get().strip()
        pwd = self.ent_new_pwd.get().strip()
        if not uname or not pwd:
            messagebox.showwarning("Warning", "Enter both username and password.")
            return

        if not self.server:
            messagebox.showerror("Error", "Server must be running.")
            return

        ok, msg = self.server.auth_manager.register(uname, pwd, "localhost-admin")
        if ok:
            messagebox.showinfo("Success", msg)
            self.ent_new_uname.delete(0, tk.END)
            self.ent_new_pwd.delete(0, tk.END)
            self._refresh_users()
        else:
            messagebox.showerror("Failed", msg)

    def _on_close(self):
        if self.is_running and self.server:
            self.server.stop()
        self.root.destroy()


def run_server_gui():
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_server_gui()
