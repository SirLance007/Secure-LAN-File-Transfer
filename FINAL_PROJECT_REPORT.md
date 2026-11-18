# Mini Project Report
### on
## **“Secure LAN File Transfer using AES & Socket Programming”**

**Project Code: CSL-G52**  
**Submitted in partial fulfilment of the requirements of**  
**Cyber Security Lab (7CIT4-22)**  
**Bachelor of Technology — VII Semester**  
**in**  
**Computer Science & Engineering (Internet of Things)**  
**Session 2026-27**  

---

<br>

<div align="center">
  <h2><b>Swami Keshvanand Institute of Technology, Management & Gramothan, Jaipur</b></h2>
  <p><i>(Approved by AICTE | Affiliated to Rajasthan Technical University, Kota)</i></p>
  <p><b>Ramnagaria, Jagatpura, Jaipur, Rajasthan 302017</b></p>
</div>

<br>

---

<br>

**Submitted By:**  
- **Name:** Prankur Sharma  
- **Roll No.:** 23ESKCY041  
- **Class / Batch:** CS-IOT-A-G1  
- **Semester:** VII  

**Submitted To:**  
- **Vikash Dhankar**  
- Assistant Professor  
- Department of CSE SKIT, Jaipur  

<br>

<div align="center">
  <b>Department of Computer Science & Engineering</b><br>
  Swami Keshvanand Institute of Technology, Management & Gramothan, Jaipur
</div>

<div style="page-break-after: always;"></div>

---

## **CANDIDATE'S DECLARATION**

I, **Prankur Sharma**, Roll No. **23ESKCY041**, a student of B.Tech VII Semester, [CSE / CSE (IoT)], [CS-IOT-A-G1], hereby declare that the mini project titled **"Secure LAN File Transfer using AES & Socket Programming"** (Project Code **CSL-G52**) submitted for the Cyber Security Lab (7CIT4-22) is my own original work, carried out under the guidance of **Vikash Dhankar**, Assistant Professor, Department of CSE, SKIT Jaipur. The code and report have not been copied from any other student or source, and all external material used has been properly cited.

<br>

---

## **ETHICAL DECLARATION**

I declare that all network transmission, socket communication, cryptographic hashing, and encryption/decryption activities performed in this project were carried out strictly on my own systems, virtual machines or an isolated laboratory local area network (LAN) environment using test data. No unauthorised system, network, account, or person was targeted. I understand that unauthorized interception, eavesdropping, or tampering with network communications is an offence under the Information Technology Act, 2000 of India.

<br><br>

**Date:** \_\_\_\_\_\_\_\_\_\_\_\_\_\_  
**Place:** Jaipur  

<br>
<div align="right">
  _____________________________<br>
  <b>Signature of Student</b><br>
  Prankur Sharma (23ESKCY041)
</div>

<div style="page-break-after: always;"></div>

---

## **ABSTRACT**

In modern local computing environments such as university campus intranets, research laboratories, and corporate networks, Local Area Networks (LANs) frequently carry proprietary files, academic records, and sensitive credentials. However, legacy transfer mechanisms (plain FTP, TFTP, Samba, unencrypted HTTP) transmit data across the wire in cleartext, exposing the communication to packet sniffing, ARP cache poisoning, and Man-in-the-Middle (MITM) tampering.

This project implements a secure, authenticated, and verifiable client–server file transfer system over raw TCP sockets in Python. The system guarantees end-to-end confidentiality by applying Advanced Encryption Standard (AES-256) encryption locally on the sender machine before data dispatch, followed by remote authenticated decryption at the server. Two cipher operating modes are designed: modern **AES-256-GCM** (Galois/Counter Mode) providing Authenticated Encryption with Associated Data (AEAD), and classical **AES-256-CBC** (Cipher Block Chaining) with PKCS#7 block padding and an Encrypt-then-MAC (HMAC-SHA256) integrity tag. 

User identity and access control are enforced using salted **PBKDF2-HMAC-SHA256** password hashing (100,000 iterations) backed by an embedded SQLite database. Network framing is governed by a custom 12-byte binary header protocol that guarantees transmission integrity and eliminates TCP stream fragmentation anomalies. Experimental evaluations confirm that the protocol prevents packet eavesdropping via Wireshark, instantly detects ciphertext tampering, and achieves 100% bit-exact transmission verified by matching SHA-256 cryptographic checksums. The project aligns with the practical syllabus objectives of the RTU Cyber Security Lab (7CIT4-22).

**Keywords:** *secure file transfer, socket programming, AES-256-GCM, AES-256-CBC, PBKDF2, TCP stream framing, SHA-256 integrity, authenticated encryption, network security.*

<div style="page-break-after: always;"></div>

---

## **TABLE OF CONTENTS**

| Section / Chapter | Title | Page No. |
| :--- | :--- | :---: |
| | **Title Page** | i |
| | **Candidate’s Declaration & Ethical Declaration** | ii |
| | **Abstract** | iii |
| **Chapter 1** | **Introduction** | **1** |
| 1.1 | Problem Statement | 1 |
| 1.2 | Objectives | 1 |
| 1.3 | Scope | 2 |
| 1.4 | Link to the RTU Syllabus Experiment | 2 |
| 1.5 | Organisation of the Report | 3 |
| **Chapter 2** | **Background and Theory** | **4** |
| 2.1 | Socket Programming & Transport Layer (TCP Stream Semantics) | 4 |
| 2.2 | Advanced Encryption Standard (AES) & Operating Modes | 4 |
| 2.3 | Password Authentication & Key Derivation (PBKDF2-HMAC-SHA256) | 5 |
| 2.4 | Hash Functions & Bit-Level Integrity (SHA-256) | 6 |
| 2.5 | Ethical and Legal Considerations | 6 |
| **Chapter 3** | **Tools and Environment** | **7** |
| 3.1 | Hardware and Software | 7 |
| 3.2 | Libraries Used | 7 |
| 3.3 | Lab Set-up | 8 |
| 3.4 | Project Structure | 8 |
| 3.5 | Installation and Execution | 9 |
| **Chapter 4** | **Codes** | **10** |
| 4.1 | Wire Protocol & Framing Engine (`packet.py`) | 10 |
| 4.2 | AES Cryptography Engine (`aes_cipher.py`) | 11 |
| 4.3 | Socket Server Core & Authentication Handshake (`server_core.py`) | 12 |
| 4.4 | Client Transmission & Verification Engine (`client_core.py`) | 13 |
| **Chapter 5** | **Results and Testing** | **14** |
| 5.1 | Test Plan | 14 |
| 5.2 | Unit Testing & Benchmark Results | 14 |
| 5.3 | End-to-End File Transfer & Active Tampering Demonstration | 15 |
| 5.4 | Observations and Analysis | 16 |
| **Chapter 6** | **Conclusion and Future Scope** | **17** |
| 6.1 | Conclusion | 17 |
| 6.2 | Future Scope | 17 |
| | **References** | **18** |

<div style="page-break-after: always;"></div>

---

## **CHAPTER 1: INTRODUCTION**

### 1.1 Problem Statement
In institutional campus LANs and industrial intranet setups, internal network traffic is conventionally regarded as trusted. However, standard network utilities like FTP (File Transfer Protocol, RFC 959), TFTP, and HTTP send credentials and file contents in cleartext. Any workstation on the local broadcast domain or wireless access point running packet analyzers like Wireshark or tcpdump can capture files, credentials, and sensitive internal communications. 

Enterprise solutions like SSH File Transfer Protocol (SFTP) or FTPS exist, but they demand complex server infrastructure, domain certificates, and operating-system daemons that obscure core transport concepts. The educational problem addressed here is to engineer a compact, readable, and syllabus-aligned client–server system from first principles using **low-level Berkeley socket programming** in Python that guarantees:
1. Strong identity authentication before accepting any incoming file.
2. Client-side **AES-256** symmetric encryption before packets traverse the LAN wire.
3. Strict wire framing to resolve the classic TCP stream segmentation problem.
4. Server-side authenticated decryption with bit-level **SHA-256** integrity verification.

### 1.2 Objectives
1. **To study socket programming principles**: Explore low-level TCP streaming (`SOCK_STREAM`), connection lifecycles, and chunked buffered I/O.
2. **To design an application-layer framing protocol**: Build a 12-byte binary header containing Magic Bytes, Version, Opcode, and Payload Length to avoid TCP stream fragmentation.
3. **To implement AES-256 in both GCM and CBC modes**: Implement modern Authenticated Encryption with Associated Data (GCM) and classical Encrypt-then-MAC (CBC with PKCS#7).
4. **To secure user credentials with salted PBKDF2**: Construct a persistent SQLite authentication vault with PBKDF2-HMAC-SHA256 (100,000 iterations) and 16-byte random salts.
5. **To provide bit-level integrity verification**: Calculate and validate SHA-256 cryptographic digests before sending and after decryption to ensure zero transmission corruption.
6. **To implement dual interfaces**: Provide both a modern Tkinter graphical user interface (GUI) with LAN IP auto-detection and an automated command-line interface (CLI) for lab evaluations.

### 1.3 Scope
The project covers client–server file transmission over local IP networks (LAN / Wi-Fi / localhost) using raw TCP streaming sockets. The cryptographic scope covers symmetric AES-256 in Galois/Counter Mode (GCM) and Cipher Block Chaining (CBC) mode, accompanied by salted PBKDF2 password authentication and SHA-256 verification. 

Public Key Infrastructure (PKI), TLS certificates, hardware cryptographic accelerators, and wide-area cloud deployments are outside the educational scope of this mini project. All experimental testing is restricted to self-owned workstations and isolated laboratory LAN subnets.

### 1.4 Link to the RTU Syllabus Experiment
The project directly links to the practical curriculum of the **RTU Cyber Security Lab (7CIT4-22)**:
- **Socket Programming**: Implementing client–server architectures using standard socket APIs.
- **Symmetric Encryption**: Practical application of NIST Advanced Encryption Standard (AES-256).
- **Integrity Verification**: Demonstrating cryptographic hash functions (SHA-256) to detect network packet tampering.
- **Access Control & Password Security**: Understanding salt and iterative hashing (PBKDF2) versus unsafe plaintext storage.

### 1.5 Organisation of the Report
- **Chapter 2** presents the cryptographic and transport-layer theoretical foundations.
- **Chapter 3** outlines the hardware, software, libraries, and lab configuration.
- **Chapter 4** explains the core source code listings and architectural algorithms.
- **Chapter 5** presents unit test results, end-to-end benchmarks, and tampering analysis.
- **Chapter 6** concludes the report and discusses prospective future enhancements.

<div style="page-break-after: always;"></div>

---

## **CHAPTER 2: BACKGROUND AND THEORY**

### 2.1 Socket Programming & Transport Layer (TCP Stream Semantics)
Sockets provide an endpoint abstraction for inter-process network communication across the transport layer. In this project, TCP stream sockets (`AF_INET`, `SOCK_STREAM`) provide reliable, ordered, error-checked delivery of byte streams. 

However, TCP is a continuous byte stream with no intrinsic packet boundaries. A sender executing a `send()` of 64 KB may have its data segmented across multiple TCP Maximum Segment Sizes (MSS ~1460 bytes). If the receiving server performs a naive `recv(64 * 1024)`, it might receive only a partial slice. To guarantee packet integrity, our application layer defines a **12-byte fixed binary header**:
$$\text{Header} = \text{Magic Bytes (4B)} \parallel \text{Version (2B)} \parallel \text{Opcode (2B)} \parallel \text{Payload Length (4B)}$$
Coupled with a deterministic `recv_exact()` reader, the receiver always reads exactly the required payload bytes before dispatching the packet to the handler.

### 2.2 Advanced Encryption Standard (AES) & Operating Modes
AES is a symmetric-key block cipher published in NIST FIPS PUB 197. Operating on 128-bit blocks, AES-256 transforms plaintext across 14 rounds consisting of four core operations:
1. **SubBytes**: Non-linear byte substitution using the Rijndael S-box generated via multiplicative inversion in the finite field $GF(2^8)$.
2. **ShiftRows**: Cyclic left transposition of matrix rows.
3. **MixColumns**: Linear column mixing modulo $x^4 + 1$ over $GF(2^8)$.
4. **AddRoundKey**: Bitwise XOR with round keys generated by the AES Key Expansion schedule.

```
       Plaintext (P)
             │
             ▼
     ┌───────────────┐
     │  AES Encrypt  │ ◄── Key Expansion (K_AES)
     └───────┬───────┘
             │
             ▼
      Ciphertext (C)
```

The system implements two distinct operational modes:
- **AES-256-GCM (Galois/Counter Mode)**: An Authenticated Encryption with Associated Data (AEAD) mode. GCM combines Counter (CTR) mode encryption with an authentication tag computed using universal hashing over $GF(2^{128})$ (GHASH). A unique 96-bit Nonce is generated per file. The receiver validates the 128-bit tag before completing decryption; any modification causes instant failure.
- **AES-256-CBC (Cipher Block Chaining)**: Uses a 128-bit random Initialization Vector (IV). Plaintext blocks are XORed with previous ciphertext blocks before encryption. PKCS#7 padding is applied. To defend against padding oracle attacks, **Encrypt-then-MAC** is enforced: an HMAC-SHA256 tag is computed over $(\text{IV} \parallel \text{Ciphertext} \parallel \text{Filename})$ and verified before unpadding.

| Feature | AES-256-GCM | AES-256-CBC | Plain FTP / HTTP |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | AES-256 Encryption | AES-256 Encryption | None (Cleartext) |
| **Integrity & Authenticity** | Built-in (GHASH Tag) | Encrypt-then-MAC (HMAC-SHA256) | None |
| **Tamper Detection** | Instant bit-level detection | Instant HMAC verification | Undetected |
| **Padding Required** | No (Stream-like CTR mode) | Yes (PKCS#7, 16-byte blocks) | N/A |
| **Primary Use Case** | Modern AEAD Standard | Classical Academic Syllabus | Insecure Legacy |

*Table 2.1: Comparison of Cryptographic Modes in File Transfer*

### 2.3 Password Authentication & Key Derivation (PBKDF2-HMAC-SHA256)
User credentials must never be stored in plaintext. The project implements PBKDF2 (RFC 2898) with HMAC-SHA256:
$$\text{Hash} = \text{PBKDF2-HMAC-SHA256}(\text{Password}, \text{Salt}, \text{Iterations}=100000, \text{dkLen}=32)$$
Each account maintains a cryptographically generated 16-byte random salt (`os.urandom(16)`), defeating pre-computed rainbow table attacks. Verification uses constant-time comparison (`secrets.compare_digest`) to prevent timing side-channel attacks.

### 2.4 Hash Functions & Bit-Level Integrity (SHA-256)
Prior to transmission, the sender computes the SHA-256 digest of the raw file. After decryption, the receiver computes the SHA-256 digest of the reconstructed file. Only if both 256-bit hexadecimal digests match identically is the transfer stamped as **"VERIFIED"**.

### 2.5 Ethical and Legal Considerations
Under Sections 43 and 66 of the Information Technology Act, 2000 (India), unauthorized interception of network data, hacking, and denial-of-service are criminal offences. This project was developed strictly for academic evaluation within an isolated laboratory testbed.

<div style="page-break-after: always;"></div>

---

## **CHAPTER 3: TOOLS AND ENVIRONMENT**

### 3.1 Hardware and Software
| Item | Specification | Item | Specification |
| :--- | :--- | :--- | :--- |
| **Processor** | Intel Core i5/i7 / Apple M-Series | **Language** | Python 3.11+ |
| **RAM** | 8 GB / 16 GB | **Transport Protocol** | TCP/IP (AF_INET, SOCK_STREAM) |
| **Operating System** | macOS / Ubuntu Linux / Windows 11 | **GUI Framework** | Python Tkinter / ttk |
| **Code Editor** | Visual Studio Code / Terminal | **Database** | SQLite3 (Embedded with WAL mode) |

*Table 3.1: Hardware and software environment*

### 3.2 Libraries Used
| Library | Type | Purpose in this project |
| :--- | :--- | :--- |
| `socket` | Standard Library | Low-level Berkeley TCP/IP client and server socket operations |
| `struct` | Standard Library | Binary packing and unpacking of the 12-byte protocol framing header |
| `hashlib` & `hmac` | Standard Library | SHA-256 integrity hashing and PBKDF2-HMAC-SHA256 password derivation |
| `secrets` & `os` | Standard Library | Cryptographically secure random nonces, salts, and constant-time compare |
| `sqlite3` | Standard Library | Embedded user credentials database and transaction logging |
| `tkinter` / `ttk` | Standard Library | Desktop GUI dashboards for both server and client |
| `cryptography` / `pycryptodome` | External Library | Fast AES-256-GCM AEAD and AES-256-CBC cipher primitives |

*Table 3.2: Libraries and their purpose*

### 3.3 Lab Set-up
The application operates either on a single loopback interface (`127.0.0.1`) or across multiple physical workstations connected to an isolated laboratory Wi-Fi router or Ethernet switch (e.g., `192.168.1.0/24`). Workstation A runs the Server; Workstation B runs the Client.

### 3.4 Project Structure
```
Prankur Project/
├── config.py                 # System configuration, ports, timeouts, buffer sizes
├── server_main.py            # Server launcher (GUI or CLI)
├── client_main.py            # Client launcher (GUI or CLI)
├── requirements.txt          # Minimal Python dependencies
├── README.md                 # Project documentation and Viva guide
├── FINAL_PROJECT_REPORT.md   # Final submitted academic project report
│
├── crypto/                   # Cryptographic Engine
│   ├── aes_cipher.py         # AES-256-GCM & CBC encryption/decryption
│   ├── key_manager.py        # PBKDF2 derivation, salt/IV generation
│   └── integrity.py          # SHA-256 chunk hashing and HMAC utilities
│
├── protocol/                 # Sockets & Networking Protocol Layer
│   ├── constants.py          # Opcodes (LOGIN, UPLOAD, CHUNKS, etc.)
│   └── packet.py             # 12-byte header framing and socket recv_exact
│
├── server/                   # Server Implementation
│   ├── server_core.py        # Multi-threaded TCP socket listener & decryptor
│   ├── auth.py               # SQLite credential storage & PBKDF2 hashing
│   └── storage.py            # Sandboxed storage & path-traversal prevention
│
├── client/                   # Client Implementation
│   └── client_core.py        # TCP client engine, local AES encryption & streamer
│
├── gui/                      # Graphical User Interfaces (Tkinter)
│   ├── server_gui.py         # Server monitoring dashboard & file viewer
│   └── client_gui.py         # Client transfer dashboard & progress monitor
│
├── tests/                    # Automated Test Suite (17 Tests)
│   ├── test_crypto.py        # Unit tests for AES-GCM, AES-CBC & tampering
│   ├── test_auth.py          # Unit tests for PBKDF2 password authentication
│   └── test_end_to_end.py    # Complete socket file transfer integration tests
│
└── sample_files/             # Ready-to-transfer demo files
```
*Figure 3.1: Directory structure of the project*

### 3.5 Installation and Execution
```bash
# 1. Install prerequisites
pip3 install -r requirements.txt

# 2. Run automated test suite
python3 -m unittest discover tests

# 3. Launch Server Dashboard (GUI Mode)
python3 server_main.py

# 4. Launch Client Dashboard (GUI Mode)
python3 client_main.py

# 5. One-Shot Automated CLI Transfer (Lab Grading Demo)
python3 client_main.py --cli --host 127.0.0.1 --port 5055 \
  --user student --password Student@123 \
  --file sample_files/sample_document.txt --mode AES-GCM
```
*Listing 3.1: Commands used to test, run, and evaluate the system*

<div style="page-break-after: always;"></div>

---

## **CHAPTER 4: CODES**

### 4.1 Wire Protocol & Framing Engine (`protocol/packet.py`)
To prevent partial-read fragmentation in stream sockets, `recv_exact` guarantees that exactly $N$ bytes are read from the kernel socket buffer before processing:

```python
HEADER_FORMAT = "!4sHHI"  # 4B Magic + 2B Version + 2B Opcode + 4B Length = 12 Bytes
HEADER_SIZE = 12

def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Guarantees reading exactly num_bytes from a TCP stream socket."""
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionClosedError("Remote endpoint closed socket connection.")
        buffer.extend(chunk)
    return bytes(buffer)

def pack_packet(opcode: int, payload: Union[bytes, dict, str]) -> bytes:
    """Encapsulates payload into a 12-byte binary framed packet."""
    payload_bytes = json.dumps(payload).encode("utf-8") if isinstance(payload, dict) else payload
    header = struct.pack(HEADER_FORMAT, config.MAGIC_BYTES, config.PROTOCOL_VERSION, opcode, len(payload_bytes))
    return header + payload_bytes
```
*Listing 4.1: Binary framing and guaranteed stream reader*

### 4.2 AES Cryptography Engine (`crypto/aes_cipher.py`)
Implements AES-256-GCM AEAD encryption and verified decryption with tamper detection:

```python
class AESCipher:
    @staticmethod
    def encrypt_bytes(plaintext: bytes, key: bytes, mode="AES-GCM", associated_data=b""):
        if mode == "AES-GCM":
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
            ciphertext = ct_with_tag[:-16]
            tag = ct_with_tag[-16:]
            return ciphertext, nonce, tag
        elif mode == "AES-CBC":
            iv = os.urandom(16)
            enc_key, mac_key = derive_encryption_and_mac_keys(key)
            padder = padding.PKCS7(128).padder()
            padded = padder.update(plaintext) + padder.finalize()
            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), default_backend())
            ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
            mac = compute_hmac_sha256(mac_key, iv + ciphertext + associated_data)
            return ciphertext, iv, mac

    @staticmethod
    def decrypt_bytes(ciphertext: bytes, key: bytes, iv_nonce: bytes, tag_hmac: bytes, mode="AES-GCM", associated_data=b""):
        if mode == "AES-GCM":
            aesgcm = AESGCM(key)
            try:
                return aesgcm.decrypt(iv_nonce, ciphertext + tag_hmac, associated_data)
            except Exception as e:
                raise AuthenticationFailedError("GCM authentication tag failed. Tampering detected!") from e
        elif mode == "AES-CBC":
            enc_key, mac_key = derive_encryption_and_mac_keys(key)
            if not verify_hmac_sha256(mac_key, iv_nonce + ciphertext + associated_data, tag_hmac):
                raise AuthenticationFailedError("HMAC verification failed. Ciphertext corrupted!")
            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv_nonce), default_backend())
            padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
```
*Listing 4.2: AES-256 GCM/CBC encryption and decryption routines*

### 4.3 Socket Server Core & Authentication Handshake (`server/server_core.py`)
Handles incoming client requests, verifies PBKDF2 tokens, streams chunks, and decrypts:

```python
def _handle_client(self, client_sock: socket.socket, client_addr: tuple):
    while self._is_running:
        opcode, payload = recv_packet(client_sock)
        if opcode == OP_REQ_LOGIN:
            success, msg, token = self.auth_manager.authenticate(payload["username"], payload["password"])
            send_packet(client_sock, OP_RESP_LOGIN, {"status": "SUCCESS" if success else "UNAUTHORIZED", "token": token})
            continue

        if opcode == OP_REQ_UPLOAD_INIT:
            current_upload_state = payload
            current_upload_state["file_handle"] = open(temp_enc_path, "wb")
            send_packet(client_sock, OP_RESP_UPLOAD_INIT, {"status": "SUCCESS"})
            continue

        if opcode == OP_FILE_CHUNK:
            current_upload_state["file_handle"].write(payload)
            continue

        if opcode == OP_REQ_UPLOAD_FINISH:
            current_upload_state["file_handle"].close()
            derived_key = derive_key(current_upload_state["passphrase"], current_upload_state["salt"])
            decrypt_res = AESCipher.decrypt_file(temp_enc_path, final_dest, derived_key, mode=current_upload_state["mode"])
            send_packet(client_sock, OP_RESP_UPLOAD_FINISH, {"status": "SUCCESS", "verified": True, "sha256": decrypt_res["decrypted_sha256"]})
```
*Listing 4.3: Threaded socket event loop handling upload and decryption*

<div style="page-break-after: always;"></div>

---

## **CHAPTER 5: RESULTS AND TESTING**

### 5.1 Test Plan
| Test ID | Module Tested | Test Conditions & Methodology | Expected Result | Status |
| :---: | :--- | :--- | :--- | :---: |
| **TC-01** | `test_crypto` | AES-256-GCM encryption & round-trip decryption | Plaintext reconstructed bit-exact | **PASS** |
| **TC-02** | `test_crypto` | Single-bit modification in GCM ciphertext | Raises `AuthenticationFailedError` | **PASS** |
| **TC-03** | `test_crypto` | AES-256-CBC Encrypt-then-MAC round-trip | Verified PKCS#7 unpad & HMAC match | **PASS** |
| **TC-04** | `test_auth` | PBKDF2 hashing with 100,000 rounds and unique salt | Salt prevents identical hashes | **PASS** |
| **TC-05** | `test_auth` | User login with valid and invalid passwords | Valid returns token; invalid rejected | **PASS** |
| **TC-06** | `test_end_to_end` | Complete TCP socket transfer of 78 KB file via GCM | Server decrypts, verified SHA-256 | **PASS** |
| **TC-07** | `test_end_to_end` | Binary file transfer via AES-CBC across socket | Receiver SHA-256 matches sender | **PASS** |
| **TC-08** | `test_end_to_end` | File transfer without login authentication | Server responds with `UNAUTHORIZED` | **PASS** |

*Table 5.1: Test plan and summary of results*

### 5.2 Unit Testing & Benchmark Results
Execution of `python3 -m unittest discover tests` confirms 100% test passage across all modules:

```
Ran 17 tests in 0.717s
OK
```

| Transfer Mode | File Size (Bytes) | Encryption Time (ms) | Socket Stream Time (ms) | Decryption Time (ms) | Total Time | SHA-256 Match |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **AES-GCM (Text)** | 1,149 B | 0.8 ms | 12.4 ms | 1.1 ms | **0.02 s** | **Exact Match** |
| **AES-GCM (Binary)** | 78,000 B | 3.2 ms | 18.6 ms | 3.9 ms | **0.03 s** | **Exact Match** |
| **AES-CBC (CSV)** | 340 B | 0.9 ms | 11.8 ms | 1.3 ms | **0.02 s** | **Exact Match** |
| **AES-CBC (Binary)** | 10,240 B | 1.8 ms | 14.1 ms | 2.1 ms | **0.03 s** | **Exact Match** |

*Table 5.2: Experimental file transfer performance benchmarks*

### 5.3 End-to-End File Transfer & Active Tampering Demonstration
A live test using the automated CLI transfer engine demonstrated end-to-end execution:

```
=== AUTOMATED FILE TRANSFER EXECUTION ===
[10:01:02] [INFO] Connected to server at 127.0.0.1:5055
[+] Authenticated as 'student' (Session Token: e7b209fa...)
[*] Encrypting and sending 'sample_document.txt' via AES-GCM...
[10:01:02] [CRYPTO] Encrypting file with AES-256 (AES-GCM)...
[10:01:02] [CRYPTO] Local Encryption Complete!
           Original SHA-256: d22df22866b4562caeec76c305b7b8b0d49e2bf9f6b452ef9f8532e9dcb7cfcb
[10:01:02] [TRANSFER] Streaming 1,149 encrypted bytes in 64KB chunks...
[10:01:02] [SERVER] Chunk stream completed. Initiating AES-256-GCM authenticated decryption...
[10:01:02] [SERVER] Authentication Tag Verified! Checksum Bit-Exact Match!
[+] Transfer verified! SHA-256: d22df22866b4562caeec76c305b7b8b0d49e2bf9f6b452ef9f8532e9dcb7cfcb
[+] Server confirmed: File 'sample_document.txt' received, decrypted, and verified successfully.
```
*Figure 5.1: Excerpt of a successful client-server transfer and verification report*

When an active tampering test was injected by flipping a single byte in the ciphertext payload in transit:
```
[ERROR] Decryption/Integrity check failed: GCM authentication tag verification failed. 
        Ciphertext has been tampered with.
```
The server immediately aborted, erased the temporary ciphertext, and refused to emit corrupted data.

### 5.4 Observations and Analysis
1. **Network Sniffing Immunity**: Inspection via Wireshark confirmed that while legacy FTP exposes cleartext credentials and file strings, our protocol shows only high-entropy pseudorandom bytes.
2. **Mitigation of TCP Segmentation**: The 12-byte header with pre-allocated payload length successfully eliminated partial chunk loss even under rapid transmission.
3. **AEAD Superiority**: AES-GCM executed faster than CBC due to native hardware pipelining while eliminating the need for an external HMAC calculation pass.

<div style="page-break-after: always;"></div>

---

## **CHAPTER 6: CONCLUSION AND FUTURE SCOPE**

### 6.1 Conclusion
A complete, self-contained **Secure LAN File Transfer System** was implemented in Python using TCP socket programming, AES-256 symmetric encryption (GCM/CBC), salted PBKDF2 password authentication, and SHA-256 integrity verification. The system successfully addresses the vulnerabilities inherent in unencrypted local file transfers (FTP/HTTP) without demanding complex enterprise certificate infrastructure. 

All project syllabus objectives were fulfilled:
- Reliable client–server socket communication with custom 12-byte framing.
- Zero-trust client-side encryption protecting files before network transmission.
- Multi-user authentication backed by a secure SQLite database.
- 100% bit-exact delivery validated through cryptographic SHA-256 hash checks.
- Dual interface support through an intuitive Tkinter GUI and a headless terminal CLI.

### 6.2 Future Scope
- **Asymmetric Key Exchange**: Integrate Elliptic-Curve Diffie-Hellman (ECDH over Curve25519) to negotiate session keys dynamically without pre-shared secrets.
- **Transport Layer Security (TLS 1.3 / mTLS)**: Add mutual certificate authentication at the socket layer.
- **Multi-Client Group Broadcast**: Implement authenticated multicast file distribution across multiple LAN nodes simultaneously.
- **Parallel Multi-Socket Streaming**: Distribute file chunks across multiple parallel TCP connections to saturate 10Gbps LAN connections.
- **Chunk-Level Resume Capability**: Implement offset resuming for large file transfers interrupted by network drops.
- **Web-Based Dashboard**: Build an optional lightweight browser dashboard using WebSockets.

<div style="page-break-after: always;"></div>

---

## **REFERENCES**

[1] National Institute of Standards and Technology (NIST), "Advanced Encryption Standard (AES)," *Federal Information Processing Standards Publication (FIPS PUB 197)*, 2001.  
[2] M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," *NIST Special Publication 800-38D*, 2007.  
[3] B. Kaliski, "PKCS #5: Password-Based Cryptography Specification Version 2.0," *RFC 2898*, Internet Engineering Task Force (IETF), 2000.  
[4] D. Eastlake and T. Hansen, "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)," *RFC 6234*, IETF, 2011.  
[5] J. Postel and J. Reynolds, "File Transfer Protocol (FTP)," *RFC 959*, IETF, 1985.  
[6] Python Software Foundation, "socket — Low-level networking interface," *Python 3 Documentation*, 2026. [Online]. Available: https://docs.python.org/3/library/socket.html  
[7] Python Software Foundation, "hashlib — Secure hashes and message digests," *Python 3 Documentation*, 2026. [Online]. Available: https://docs.python.org/3/library/hashlib.html  
[8] Cryptography Development Team, "cryptography: A package which provides cryptographic recipes and primitives," *Python Package Index*, 2026. [Online]. Available: https://cryptography.io  
[9] Government of India, *The Information Technology Act, 2000 (Sections 43, 66)*, Ministry of Electronics and Information Technology, 2000.  
[10] J. F. Kurose and K. W. Ross, *Computer Networking: A Top-Down Approach*, 8th ed., Pearson, 2021.  
[11] W. Stallings, *Cryptography and Network Security: Principles and Practice*, 8th ed., Pearson, 2020.  
[12] OWASP Foundation, "Password Storage Cheat Sheet," *OWASP Cheat Sheet Series*, 2025. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html  
