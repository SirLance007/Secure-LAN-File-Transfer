# 🛡️ Secure LAN File Transfer System using AES & Socket Programming

An academic, production-grade syllabus project demonstrating secure client-server communication over a Local Area Network (LAN). The system integrates **TCP Socket Programming** with **Advanced Encryption Standard (AES-256)**, **PBKDF2 Password Authentication with Salt**, and **SHA-256 Bit-Level Integrity Verification**.

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Cryptography](https://img.shields.io/badge/AES--256-GCM%20%26%20CBC-green.svg)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[![Networking](https://img.shields.io/badge/Sockets-TCP%2FIP%20Framing-orange.svg)](https://docs.python.org/3/library/socket.html)
[![License](https://img.shields.io/badge/Academic-Coursework%20Project-purple.svg)]()

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Architecture & Protocol Design](#-architecture--protocol-design)
4. [Cryptographic Principles](#-cryptographic-principles)
5. [Directory Structure](#-directory-structure)
6. [Installation & Setup](#-installation--setup)
7. [Running the Application](#-running-the-application)
   - [A. Graphical User Interface (GUI)](#a-graphical-user-interface-gui)
   - [B. Command-Line Interface (CLI)](#b-command-line-interface-cli)
   - [C. Testing on a Real LAN / Wi-Fi Network](#c-testing-on-a-real-lan--wi-fi-network)
8. [Automated Test Suite](#-automated-test-suite)
9. [Pre-Seeded Test Credentials](#-pre-seeded-test-credentials)
10. [Viva Voce & Examination Q&A](#-viva-voce--examination-qa)

---

## 🎯 Project Overview

In standard LAN environments (such as universities, office networks, and home Wi-Fi), traditional file transfer mechanisms (standard FTP, HTTP, SMB) transmit data in plaintext or rely on complex enterprise infrastructure. Anyone on the same subnet using packet analyzers like **Wireshark** or **tcpdump** can intercept confidential documents, credentials, and binary files.

This project solves this problem from first principles by designing a **Zero-Trust Client-Server Secure File Transfer Protocol** using low-level socket programming and military-grade AES-256 encryption.

### Security Guarantees:
- **Confidentiality**: Files are encrypted on the client machine *before* hitting the network wire using AES-256. Even full packet captures reveal only pseudo-random ciphertext.
- **Authenticity**: Implements AES-GCM (Galois/Counter Mode AEAD) and AES-CBC with Encrypt-then-MAC (HMAC-SHA256) to detect any packet tampering by Man-in-the-Middle (MITM) adversaries.
- **Integrity**: Computes and compares pre- and post-transfer SHA-256 cryptographic digests to verify 100% bit-exact transmission.
- **Identity Authentication**: Salted PBKDF2-HMAC-SHA256 password hashing (100,000 rounds) backed by an SQLite database, preventing unauthorized file transmission.

---

## ✨ Key Features

- **Dual Cryptographic Modes**:
  - `AES-256-GCM`: Modern Authenticated Encryption with Associated Data (AEAD) with 96-bit Nonce and 128-bit Authentication Tag.
  - `AES-256-CBC`: Classical syllabus-taught mode with PKCS#7 block padding and HMAC-SHA256 (Encrypt-then-MAC).
- **Custom Application Framing Protocol**:
  - 12-byte binary header (`Magic Bytes` + `Version` + `Opcode` + `Payload Length`) preventing TCP stream fragmentation and partial reads.
- **Buffered Chunk Streaming**:
  - Transfers files in 64 KB blocks, enabling smooth transfer of small scripts up to multi-gigabyte video or archive files without RAM exhaustion.
- **Multi-Threaded Server**:
  - Handles concurrent client connections smoothly using Python threading.
- **Modern User Interfaces**:
  - **Tkinter GUI**: Dark/light dashboard with LAN IP auto-detection, copy buttons, live progress bars, speed monitors (KB/s), user manager, and received files inspector.
  - **Interactive CLI & Automated CLI**: For headless environments, automated shell scripts, SSH terminals, and quick grading demos.
- **Built-in LAN Auto-Discovery**:
  - Server automatically detects and displays its routable local IP (e.g. `192.168.1.15`) for easy connection by other computers on the same Wi-Fi.

---

## 🏗️ Architecture & Protocol Design

### Wire Protocol Framing (12-Byte Fixed Header)
TCP is a byte-stream protocol without inherent message boundaries. To guarantee complete, unfragmented message delivery, our protocol prefixes every packet with a 12-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Magic Bytes: "SFTP"                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Protocol Version (2B)   |          Opcode (2B)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (4B, >I)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (N Bytes) ...                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### End-to-End Handshake Sequence
```
Client (Sender)                                              Server (Receiver)
      |                                                             |
      |-------------------- 1. TCP Connect (SYN/ACK) -------------->|
      |                                                             |
      |--- 2. OP_REQ_LOGIN (username, password) ------------------->|
      |                                                             | [Verifies PBKDF2 hash]
      |<-- 3. OP_RESP_LOGIN (STATUS_OK, session_token) -------------|
      |                                                             |
  [Encrypt File with AES-256]                                       |
  [Generate Salt, IV, Tag]                                          |
  [Compute SHA-256 Hash]                                            |
      |                                                             |
      |--- 4. OP_REQ_UPLOAD_INIT (Filename, Size, Salt, IV, Tag) --->| [Prepares Temp File]
      |<-- 5. OP_RESP_UPLOAD_INIT (Ready) --------------------------|
      |                                                             |
      |--- 6. OP_FILE_CHUNK (64 KB Encrypted Bytes) --------------->| [Appends to disk]
      |--- 7. OP_FILE_CHUNK (64 KB Encrypted Bytes) --------------->| [Appends to disk]
      |--- ...                                                      |
      |                                                             |
      |--- 8. OP_REQ_UPLOAD_FINISH (Token) ------------------------>|
      |                                                             | [Derives Key from Salt]
      |                                                             | [Decrypts Ciphertext]
      |                                                             | [Validates GCM Tag]
      |                                                             | [Compares SHA-256]
      |<-- 9. OP_RESP_UPLOAD_FINISH (Verified Bit-Exact) ----------|
      |                                                             |
```

---

## 🔐 Cryptographic Principles

### 1. Key Derivation Function (PBKDF2-HMAC-SHA256)
Users supply a secret passphrase. The client generates a cryptographically secure 16-byte random salt (`os.urandom(16)`):
$$K_{\text{AES}} = \text{PBKDF2-HMAC-SHA256}(\text{Passphrase}, \text{Salt}, 100000, 32)$$
- Derives a 256-bit (32-byte) key resistant to brute-force dictionary attacks.

### 2. AES-256-GCM (Authenticated Encryption)
- Cipher: AES in Galois/Counter Mode (GCM).
- Nonce: 12 bytes (96 bits) unique per file transfer.
- Authenticated Data (AAD): File name bound to encryption so attackers cannot rename ciphertexts.
- Authentication Tag: 16 bytes (128 bits) computed over ciphertext and AAD using the polynomial GHASH function. Any modification results in instant rejection (`AuthenticationFailedError`).

### 3. AES-256-CBC with PKCS#7 & Encrypt-then-MAC
- Cipher: AES in Cipher Block Chaining (CBC) mode with 16-byte IV.
- Padding: PKCS#7 padding up to the 16-byte block boundary.
- MAC: Sub-key derivation produces an independent encryption key and authentication key:
  $$\text{MAC} = \text{HMAC-SHA256}(K_{\text{MAC}}, \text{IV} \parallel \text{Ciphertext} \parallel \text{AAD})$$
- Verification occurs *before* decryption to prevent padding oracle exploits.

---

## 📁 Directory Structure

```
Prankur Project/
├── config.py                 # System configuration, ports, timeouts, buffer sizes
├── server_main.py            # Server launcher (GUI or CLI)
├── client_main.py            # Client launcher (GUI or CLI)
├── requirements.txt          # Minimal Python dependencies
├── README.md                 # Project documentation and Viva guide
├── PROJECT_REPORT.md         # Full formal academic project report
│
├── crypto/                   # Cryptographic Engine
│   ├── __init__.py
│   ├── aes_cipher.py         # AES-256-GCM & CBC encryption/decryption
│   ├── key_manager.py        # PBKDF2 derivation, salt/IV generation
│   └── integrity.py          # SHA-256 chunk hashing and HMAC utilities
│
├── protocol/                 # Sockets & Networking Protocol Layer
│   ├── __init__.py
│   ├── constants.py          # Opcodes (LOGIN, UPLOAD, CHUNKS, etc.)
│   └── packet.py             # 12-byte header framing and socket recv_exact
│
├── server/                   # Server Implementation
│   ├── __init__.py
│   ├── server_core.py        # Multi-threaded TCP socket listener & decryptor
│   ├── auth.py               # SQLite credential storage & PBKDF2 hashing
│   └── storage.py            # Sandboxed storage & path-traversal prevention
│
├── client/                   # Client Implementation
│   ├── __init__.py
│   └── client_core.py        # TCP client engine, local AES encryption & streamer
│
├── gui/                      # Graphical User Interfaces (Tkinter)
│   ├── __init__.py
│   ├── server_gui.py         # Server monitoring dashboard & file viewer
│   └── client_gui.py         # Client transfer dashboard & progress monitor
│
├── tests/                    # Automated Test Suite
│   ├── test_crypto.py        # Unit tests for AES-GCM, AES-CBC & tampering
│   ├── test_auth.py          # Unit tests for PBKDF2 password authentication
│   └── test_end_to_end.py    # Complete socket file transfer integration tests
│
├── sample_files/             # Ready-to-transfer demo files
│   ├── sample_document.txt   # Academic specification document
│   ├── research_notes.csv    # Structured CSV dataset
│   └── project_spec.json     # JSON protocol specification
│
└── server_storage/           # Destination folder for received decrypted files
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8 or higher (Python 3.10/3.11/3.12/3.13 recommended)
- `pip` package manager

### 1. Clone or Open Workspace
```bash
cd "Prankur Project"
```

### 2. Install Dependencies
```bash
pip3 install -r requirements.txt
```
*(Dependencies are `cryptography` and `pycryptodome`. All socket, hashing, GUI, and threading utilities use Python's built-in standard library).*

---

## 🚀 Running the Application

### A. Graphical User Interface (GUI)

#### 1. Start the Server:
```bash
python3 server_main.py
```
- The dashboard displays your **LAN Host IP** (e.g. `192.168.1.15`).
- Click **"Copy IP"** to share with clients.
- Click **"▶ Start Server"** (auto-starts by default).
- You can inspect connected clients, live activity logs, registered users, and received decrypted files.

#### 2. Start the Client (in another terminal or on another machine):
```bash
python3 client_main.py
```
1. **Connect**: Enter the Server IP (e.g. `127.0.0.1` for local, or the server's LAN IP) and Port (`5055`). Click **Connect**.
2. **Authenticate**: Go to the **Login** tab and sign in using `student` / `Student@123` (or register a new user in the **Register** tab).
3. **Choose File**: Click **📁 Choose File...** and select any file (e.g. `sample_files/sample_document.txt`).
4. **Select Cipher**: Choose `AES-GCM` or `AES-CBC`.
5. **Send**: Click **🔒 Encrypt & Send File Across LAN**.
6. **Verify**: Watch the real-time progress bar. Upon completion, a green verification card shows the bit-exact matching SHA-256 checksum!

---

### B. Command-Line Interface (CLI)

#### 1. Interactive Terminal Mode:
- **Server**:
  ```bash
  python3 server_main.py --cli --port 5055
  ```
- **Client**:
  ```bash
  python3 client_main.py --cli --host 127.0.0.1 --port 5055
  ```
  *(Presents an interactive menu to Login, Register, Send Encrypted Files, or List Server Files).*

#### 2. One-Shot Automated Transfer (Ideal for Scripts & Grading Demos):
```bash
python3 client_main.py --cli \
  --host 127.0.0.1 \
  --port 5055 \
  --user student \
  --password Student@123 \
  --file sample_files/sample_document.txt \
  --mode AES-GCM
```

---

### C. Testing on a Real LAN / Wi-Fi Network

To transfer files between two physical computers (e.g., Computer A as Server, Computer B as Client):

1. **Connect both computers to the same Wi-Fi or LAN switch**.
2. **On Computer A (Server)**:
   - Launch `python3 server_main.py`.
   - Note down the **LAN IP** shown on the screen (e.g., `192.168.1.45`).
   - Ensure your firewall allows incoming traffic on port `5055`.
3. **On Computer B (Client)**:
   - Launch `python3 client_main.py`.
   - Enter `192.168.1.45` in the **Server IP** field.
   - Click **Connect**, log in, and send any file!

---

## 🧪 Automated Test Suite

The project includes unit and integration tests covering cryptography, authentication, and full TCP socket streaming:

```bash
# 1. Run Cryptography Unit Tests (AES-GCM, AES-CBC, Tamper Detection)
python3 -m unittest tests/test_crypto.py

# 2. Run Database & Authentication Tests (PBKDF2 Hashing, Salt, Tokens)
python3 -m unittest tests/test_auth.py

# 3. Run Full End-to-End Socket Integration Tests
python3 -m unittest tests/test_end_to_end.py
```

---

## 🔑 Pre-Seeded Test Credentials

The server automatically seeds the following credentials into `server/users.db` on first boot for testing convenience:

| Username | Password | Role / Description |
| :--- | :--- | :--- |
| `student` | `Student@123` | Standard student user account |
| `faculty` | `Faculty@2026` | Academic faculty account |
| `admin` | `AdminSecure123!` | System administrator |

*(You can also register any new account directly through the Client GUI or CLI).*

---

## 🎓 Viva Voce & Examination Q&A

Here are common questions asked by university professors and external examiners:

<details>
<summary><b>1. Why did you use TCP instead of UDP for this project?</b></summary>

**Answer**: TCP is a connection-oriented, reliable transport protocol that guarantees ordered delivery and error-checked transmission through acknowledgments (ACKs) and retransmissions. In file transfer, missing or out-of-order packets would corrupt the ciphertext or result in incomplete files. UDP is connectionless and does not guarantee delivery.
</details>

<details>
<summary><b>2. What is TCP stream fragmentation, and how did you solve it?</b></summary>

**Answer**: TCP is a byte-stream protocol, not a message-based protocol. A sender writing 1000 bytes might be segmented by the OS network stack into two chunks of 600 and 400 bytes. We solved this by designing a **12-byte fixed header** that contains a 4-byte `Payload Length` field, combined with an iterative `recv_exact()` socket reader loop that reads until the exact number of bytes is received.
</details>

<details>
<summary><b>3. Why is AES-256-GCM superior to AES-256-CBC?</b></summary>

**Answer**: AES-GCM is an Authenticated Encryption with Associated Data (AEAD) mode. It provides both **confidentiality** and **integrity/authenticity** in a single pass using GHASH. In CBC mode, encryption alone does not protect against active bit-flipping attacks, requiring a separate HMAC (Encrypt-then-MAC). Furthermore, GCM operates in counter mode and can be parallelized in hardware.
</details>

<details>
<summary><b>4. What happens if an attacker on the LAN modifies one bit of the file during transit?</b></summary>

**Answer**: In AES-GCM mode, the 16-byte Authentication Tag will fail verification at the receiver, raising an `AuthenticationFailedError`. In CBC mode, the HMAC-SHA256 tag verification fails. In both cases, the server immediately aborts, deletes the temporary ciphertext, and refuses to output corrupted plaintext.
</details>

<details>
<summary><b>5. Why do you use PBKDF2 instead of plain SHA-256 for user passwords?</b></summary>

**Answer**: Plain SHA-256 is designed to be extremely fast in hardware, making it vulnerable to brute-force and GPU dictionary attacks (billions of hashes per second). PBKDF2 (Password-Based Key Derivation Function 2) applies HMAC-SHA256 iteratively (100,000 rounds) with a unique cryptographic salt, increasing computation cost for adversaries while preventing rainbow table lookups.
</details>

<details>
<summary><b>6. What is the role of the IV / Nonce? Can it be reused?</b></summary>

**Answer**: The Initialization Vector (IV in CBC) or Nonce (in GCM) ensures that encrypting identical plaintexts with the same key produces completely different ciphertexts. **A Nonce must NEVER be reused with the same key in GCM mode**, as doing so allows an attacker to recover the authentication key and forge messages. Our system generates a fresh `os.urandom()` nonce for every file transfer.
</details>

<details>
<summary><b>7. How does the server prevent Directory Traversal attacks?</b></summary>

**Answer**: In `server/storage.py`, incoming file names are sanitized using `os.path.basename()` and non-alphanumeric character filtering. Paths are resolved and strictly asserted to stay within `server_storage/`, blocking attempts like `../../etc/passwd`.
</details>

---

## 📜 Academic Attribution

- **Project Topic**: Secure LAN File Transfer using AES & Socket Programming
- **Technology Stack**: Python 3, Sockets API, AES-256 (GCM & CBC), PBKDF2, SHA-256, SQLite3, Tkinter.
- **Repository Prepared for**: College / University Syllabus Examination & Project Submission.
