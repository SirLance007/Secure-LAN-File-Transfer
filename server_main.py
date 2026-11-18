#!/usr/bin/env python3
"""
Server Entry Point for Secure LAN File Transfer System
Supports both Graphical User Interface (GUI) and Command-Line Interface (CLI).
"""

import sys
import argparse
import time
import config
from server.server_core import FileTransferServer


def run_cli_server(host: str, port: int, secret: str):
    """Run interactive terminal server."""
    lan_ip = FileTransferServer.get_lan_ip()
    print("=" * 70)
    print("  🛡️  SECURE LAN FILE TRANSFER SERVER (AES-256 + SOCKETS)  ")
    print("=" * 70)
    print(f"[*] Binding to Host : {host}")
    print(f"[*] Local LAN IP    : {lan_ip}")
    print(f"[*] Port            : {port}")
    print(f"[*] Storage Dir     : {config.SERVER_STORAGE_DIR.resolve()}")
    print(f"[*] AES Secret Key  : {secret[:4]}***{secret[-4:]}")
    print("=" * 70)

    server = FileTransferServer(host=host, port=port, shared_secret=secret)
    if not server.start():
        print("[!] Fatal: Server could not bind to port. Exiting.")
        sys.exit(1)

    print("\n[+] Server is RUNNING. Press Ctrl+C to terminate.")
    print(f"[+] Share this IP with other computers on your Wi-Fi/LAN: {lan_ip}")
    print("-" * 70)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        server.stop()
        print("[+] Goodbye!")


def main():
    parser = argparse.ArgumentParser(description="Secure LAN File Transfer Server (AES-256)")
    parser.add_argument("--cli", action="store_true", help="Force command-line mode (headless)")
    parser.add_argument("--host", default=config.DEFAULT_HOST, help="Host/Interface to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=config.DEFAULT_PORT, help="Port to listen (default: 5055)")
    parser.add_argument("--secret", default="SecureLANFileTransferKey2026", help="Shared secret passphrase")

    args = parser.parse_args()

    # If --cli explicitly passed, run CLI
    if args.cli:
        run_cli_server(args.host, args.port, args.secret)
        return

    # Try launching GUI, fallback to CLI if display/X11 unavailable
    try:
        from gui.server_gui import run_server_gui
        run_server_gui()
    except Exception as e:
        print(f"[!] Graphical environment not available ({e}). Launching CLI server...")
        run_cli_server(args.host, args.port, args.secret)


if __name__ == "__main__":
    main()
