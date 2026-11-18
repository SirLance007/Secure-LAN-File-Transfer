#!/usr/bin/env python3
"""
Client Entry Point for Secure LAN File Transfer System
Supports Graphical User Interface (GUI), Interactive CLI, and One-Shot Automated CLI.
"""

import sys
import argparse
import getpass
from pathlib import Path

import config
from client.client_core import TransferClient


def run_interactive_cli(host: str, port: int):
    """Run interactive text-based terminal menu."""
    client = TransferClient(server_host=host, server_port=port)
    print("=" * 65)
    print("  🚀  SECURE LAN FILE TRANSFER CLIENT (AES-256)  ")
    print("=" * 65)
    print(f"[*] Target Server: {host}:{port}")

    ok, msg = client.connect()
    if not ok:
        print(f"[!] Warning: Could not connect immediately: {msg}")
    else:
        print(f"[+] Connected to server {host}:{port}")

    while True:
        user_str = f"Logged in as: {client.logged_in_user}" if client.logged_in_user else "Not logged in"
        print(f"\n--- Menu [{user_str}] ---")
        print("1. Login")
        print("2. Register New User")
        print("3. Encrypt & Send File (AES-256)")
        print("4. List Server Files")
        print("5. Ping Server")
        print("6. Exit")

        choice = input("Enter choice (1-6): ").strip()

        if choice == "1":
            uname = input("Username: ").strip()
            pwd = getpass.getpass("Password: ").strip()
            ok, msg = client.login(uname, pwd)
            if ok:
                print(f"[+] {msg}")
            else:
                print(f"[!] Login failed: {msg}")

        elif choice == "2":
            uname = input("Choose Username: ").strip()
            pwd = getpass.getpass("Choose Password: ").strip()
            ok, msg = client.register(uname, pwd)
            print(f"[+] {msg}" if ok else f"[!] Registration failed: {msg}")

        elif choice == "3":
            if not client.session_token:
                print("[!] Please login first (Choice 1).")
                continue

            file_input = input("File path to send (e.g. sample_files/sample_document.txt): ").strip()
            file_path = Path(file_input)
            if not file_path.is_file():
                print(f"[!] File not found: {file_path}")
                continue

            print("Select Cipher Mode:")
            print("  1. AES-GCM (Authenticated AEAD - Recommended)")
            print("  2. AES-CBC (PKCS#7 + HMAC-SHA256)")
            m_choice = input("Choice [1]: ").strip()
            mode = "AES-CBC" if m_choice == "2" else "AES-GCM"

            secret = input("Secret passphrase (press Enter for default): ").strip()
            if not secret:
                secret = "SecureLANFileTransferKey2026"

            def print_progress(sent, total, pct, speed):
                bar_len = 30
                filled = int(bar_len * (sent / total)) if total > 0 else bar_len
                bar = "█" * filled + "░" * (bar_len - filled)
                sys.stdout.write(f"\rStreaming: |{bar}| {pct:.1f}% ({sent}/{total} bytes) @ {speed:.1f} KB/s")
                sys.stdout.flush()

            print(f"\n[*] Encrypting with AES-256 ({mode})...")
            res = client.send_file(
                file_path=file_path,
                passphrase=secret,
                mode=mode,
                progress_callback=print_progress
            )
            print()

            if res.get("success"):
                print("\n" + "=" * 60)
                print("  🎉 TRANSFER & DECRYPTION SUCCESSFUL! ")
                print("=" * 60)
                print(f"[*] Filename        : {res['filename']}")
                print(f"[*] Original Size   : {res['original_size']} bytes")
                print(f"[*] Encrypted Size  : {res['encrypted_size']} bytes")
                print(f"[*] Verified SHA256 : {res['original_sha256']}")
                print(f"[*] Duration        : {res['duration_seconds']} seconds")
                print(f"[*] Server Status   : {res['server_message']}")
                print("=" * 60)
            else:
                print(f"[!] Transfer failed: {res.get('message')}")

        elif choice == "4":
            if not client.session_token:
                print("[!] Please login first (Choice 1).")
                continue
            files = client.list_server_files()
            if not files:
                print("[*] No files found on server.")
            else:
                print("\n--- Files on Server ---")
                for f in files:
                    print(f"• {f['filename']} ({f['size']} bytes) - SHA256: {f['sha256'][:16]}...")

        elif choice == "5":
            ok, rtt = client.ping()
            if ok:
                print(f"[+] Pong from server! Latency: {rtt:.2f} ms")
            else:
                print("[!] Server did not respond to ping.")

        elif choice == "6":
            print("[*] Disconnecting...")
            client.disconnect()
            break
        else:
            print("[!] Invalid option.")


def run_automated_cli(args):
    """Run non-interactive one-shot file transfer."""
    client = TransferClient(server_host=args.host, server_port=args.port)
    ok, msg = client.connect()
    if not ok:
        print(f"[!] Failed to connect to server: {msg}")
        sys.exit(1)

    print(f"[+] Connected to {args.host}:{args.port}")

    # Authenticate
    ok, msg = client.login(args.user, args.password)
    if not ok:
        print(f"[!] Authentication failed: {msg}")
        # Try register then login if specified
        ok_reg, reg_msg = client.register(args.user, args.password)
        if ok_reg:
            print(f"[+] Auto-registered '{args.user}'. Logging in...")
            ok, msg = client.login(args.user, args.password)
            if not ok:
                print(f"[!] Login failed after register: {msg}")
                sys.exit(1)
        else:
            sys.exit(1)

    print(f"[+] Authenticated as '{args.user}'")

    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    print(f"[*] Encrypting and sending '{file_path.name}' via {args.mode}...")
    res = client.send_file(
        file_path=file_path,
        passphrase=args.secret,
        mode=args.mode
    )

    if res.get("success"):
        print(f"[+] Transfer verified! SHA-256: {res['original_sha256']}")
        print(f"[+] Server confirmed: {res['server_message']}")
        client.disconnect()
        sys.exit(0)
    else:
        print(f"[!] Transfer failed: {res.get('message')}")
        client.disconnect()
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Secure LAN File Transfer Client (AES-256)")
    parser.add_argument("--cli", action="store_true", help="Run in command-line mode")
    parser.add_argument("--host", default=config.DEFAULT_CLIENT_HOST, help="Server IP address (LAN IP)")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="Server port (default: 5055)")
    parser.add_argument("--user", help="Username for automated transfer")
    parser.add_argument("--password", help="Password for automated transfer")
    parser.add_argument("--file", help="File to send for automated transfer")
    parser.add_argument("--mode", default="AES-GCM", choices=["AES-GCM", "AES-CBC"], help="Cipher mode")
    parser.add_argument("--secret", default="SecureLANFileTransferKey2026", help="Shared secret passphrase")

    args = parser.parse_args()

    # If automated transfer arguments provided
    if args.file and args.user and args.password:
        run_automated_cli(args)
        return

    # If explicit --cli requested
    if args.cli:
        run_interactive_cli(args.host, args.port)
        return

    # Default to GUI with fallback to interactive CLI
    try:
        from gui.client_gui import run_client_gui
        run_client_gui()
    except Exception as e:
        print(f"[!] Graphical environment not available ({e}). Launching Interactive CLI...")
        run_interactive_cli(args.host, args.port)


if __name__ == "__main__":
    main()
