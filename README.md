# Cryptography Lib Lab
### Path 3 — Hybrid Encryption: AES-256-CBC + RSA-2048
**Course:** Information Security / Cryptography Lab
**Scenario:** Secure Student Records (CSV)
**Language:** Python 3
**Library:** PyCryptodome
**Interface:** Tkinter GUI + CLI (both included)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [How Hybrid Encryption Works](#2-how-hybrid-encryption-works)
3. [Algorithms Used](#3-algorithms-used)
4. [Project Structure](#4-project-structure)
5. [File Descriptions](#5-file-descriptions)
6. [Setup & Installation](#6-setup--installation)
7. [Running the Application](#7-running-the-application)
8. [GUI Walkthrough](#8-gui-walkthrough)
9. [CLI Walkthrough](#9-cli-walkthrough)
10. [Program Flow](#10-program-flow)
11. [Functions Reference](#11-functions-reference)
12. [Output Files](#12-output-files)
13. [Security Notes](#13-security-notes)
14. [Security Understanding Q&A](#14-security-understanding-qa)

---

## 1. Project Overview

This project is a **real-data encryption/decryption application** built for the Cryptography Lab course. It demonstrates **Path 3: Hybrid Encryption**, which is the closest implementation to how real-world secure systems (such as TLS/HTTPS) handle data protection.

The application encrypts a CSV file containing fake student records using a two-layer approach:

- **AES-256-CBC** encrypts the actual file data (fast, symmetric encryption).
- **RSA-2048** encrypts the AES session key (secure asymmetric key exchange).
- **SHA-256** verifies that the decrypted output is byte-for-byte identical to the original.

The project ships with two interfaces: a dark-themed **Tkinter GUI** for demonstration and an interactive **CLI menu** as a fallback.

---

## 2. How Hybrid Encryption Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENCRYPTION FLOW                              │
│                                                                     │
│  students.csv                                                       │
│       │                                                             │
│       ▼                                                             │
│  ┌──────────────┐     Random 256-bit     ┌───────────────────────┐ │
│  │  AES-256-CBC │ ◄── AES Session Key ── │  generate_aes_key()   │ │
│  │  + Random IV │                        └───────────────────────┘ │
│  └──────────────┘                                  │               │
│       │                                            │ AES key       │
│       ▼                                            ▼               │
│  students_encrypted.bin              ┌─────────────────────────┐   │
│                                      │  RSA-2048 Public Key    │   │
│                                      │  PKCS1_OAEP.encrypt()   │   │
│                                      └─────────────────────────┘   │
│                                                    │               │
│                                                    ▼               │
│                                           metadata.json            │
│                                      { iv, encrypted_aes_key }     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                        DECRYPTION FLOW                              │
│                                                                     │
│  metadata.json                                                      │
│       │                                                             │
│       ▼                                                             │
│  ┌─────────────────────────┐                                        │
│  │  RSA-2048 Private Key   │ ──► Recovered AES Session Key         │
│  │  PKCS1_OAEP.decrypt()   │                  │                    │
│  └─────────────────────────┘                  ▼                    │
│                                      ┌──────────────────┐          │
│  students_encrypted.bin ────────────►│   AES-256-CBC    │          │
│                                      │   + IV from meta │          │
│                                      └──────────────────┘          │
│                                                │                    │
│                                                ▼                    │
│                                      students_decrypted.csv         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     INTEGRITY VERIFICATION                          │
│                                                                     │
│  students.csv           ──► SHA-256 ──► hash_A ──┐                 │
│                                                   ├──► MATCH? ✔/✘  │
│  students_decrypted.csv ──► SHA-256 ──► hash_B ──┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Why Hybrid and Not RSA Alone?

RSA-2048 can only encrypt a maximum of ~245 bytes directly. A real file can be kilobytes or megabytes. The hybrid approach solves this by using AES (which has no practical size limit) for the file data, and RSA only to securely transport the small AES key. This is exactly the technique used in TLS, PGP, and SSH.

---

## 3. Algorithms Used

### AES-256-CBC (Advanced Encryption Standard)

| Property | Value |
|----------|-------|
| Type | Symmetric block cipher |
| Key size | 256 bits (32 bytes) |
| Block size | 128 bits (16 bytes) |
| Mode | CBC (Cipher Block Chaining) |
| IV size | 128 bits (16 bytes), randomly generated per encryption |
| Padding | PKCS7 |
| Library call | `AES.new(key, AES.MODE_CBC, iv)` |

CBC mode chains each block's encryption to the previous block's ciphertext using XOR, which means identical plaintext blocks produce different ciphertext blocks. A fresh random IV is generated every time a file is encrypted, ensuring that encrypting the same file twice produces completely different ciphertext.

### RSA-2048 with OAEP (Rivest-Shamir-Adleman)

| Property | Value |
|----------|-------|
| Type | Asymmetric cipher |
| Key size | 2048 bits |
| Padding | OAEP (Optimal Asymmetric Encryption Padding) |
| Used for | Encrypting the 32-byte AES session key only |
| Library call | `PKCS1_OAEP.new(key).encrypt(aes_key)` |

OAEP padding adds randomness to the RSA encryption, preventing several classical attacks against raw RSA. The public key encrypts the AES key; only the matching private key can decrypt it.

### SHA-256 (Secure Hash Algorithm)

| Property | Value |
|----------|-------|
| Type | Cryptographic hash function |
| Output size | 256 bits (64 hex characters) |
| Used for | Integrity verification after decryption |
| Library call | `hashlib.sha256()` |

SHA-256 produces a fixed-size fingerprint of a file. If even a single byte differs between two files their SHA-256 hashes will be completely different, making it a reliable tool for proving that decryption recovered the exact original data.

---

## 4. Project Structure

```
crypto_project/
│
├── gui.py                        ← Tkinter GUI (main interface — run this)
├── main.py                       ← CLI menu (alternative interface)
├── crypto_utils.py               ← All cryptographic functions (core logic)
├── requirements.txt              ← Python dependencies
├── README.md                     ← This file
│
├── data/
│   └── students.csv              ← Input: 15 fake student records
│
├── output/                       ← Generated after running the program
│   ├── students_encrypted.bin    ← AES-256 ciphertext (binary)
│   ├── metadata.json             ← IV + RSA-encrypted AES key (Base64)
│   └── students_decrypted.csv    ← Recovered file after decryption
│
└── keys/                         ← Generated after Step 1
    ├── private_key.pem           ← RSA-2048 private key (PEM format)
    └── public_key.pem            ← RSA-2048 public key  (PEM format)
```

---

## 5. File Descriptions

### `gui.py` — Tkinter GUI Application
The primary interface. A dark cybersecurity-themed window (1100x780) built with Tkinter. Uses a two-panel layout with a scrollable terminal output on the right and action controls on the left. All operations run in background threads so the UI stays responsive. Color-coded log messages use teal for info, green for success, red for errors, amber for warnings, and blue for encryption steps.

### `main.py` — CLI Menu Application
A terminal-based alternative. Presents a numbered menu (options 0-6) and prints all output with ANSI colors directly to the terminal. Useful if Tkinter is unavailable or for running in a headless environment.

### `crypto_utils.py` — Core Cryptographic Functions
Contains all cryptographic logic with no UI code. Functions are clean, documented, and independently testable. This is the module both `gui.py` and `main.py` import from. It has zero knowledge of the interface layer.

### `data/students.csv` — Sample Input Data
A generated CSV file with 15 fake student records. Fields: StudentID, FirstName, LastName, Email, GPA, Major, Year. No real personal data is used.

### `output/metadata.json` — Encryption Metadata
Saved automatically after encryption. Contains:
```json
{
  "iv": "<base64-encoded 16-byte IV>",
  "encrypted_aes_key": "<base64-encoded RSA-encrypted AES key>",
  "aes_mode": "AES-256-CBC",
  "rsa_bits": 2048,
  "padding": "PKCS7"
}
```
This file is required for decryption. Without it (or the private key), the ciphertext cannot be recovered.

---

## 6. Setup & Installation

### Requirements
- Python 3.7 or higher
- `pip` package manager
- Tkinter (included with most Python installations on Windows and macOS)

### Install dependency

```bash
pip install pycryptodome
```

On some systems you may need:
```bash
pip3 install pycryptodome
```

With Anaconda:
```bash
conda install -c conda-forge pycryptodome
```

### Linux only — install Tkinter if missing
```bash
sudo apt-get install python3-tk
```

---

## 7. Running the Application

### Option A — GUI (recommended)
```bash
python gui.py
```

### Option B — CLI menu
```bash
python main.py
```

Both interfaces use the same `crypto_utils.py` backend and produce identical output files.

---

## 8. GUI Walkthrough

When you launch `gui.py` a 1100x780 window opens with this layout:

```
┌──────────────────────────────────────────────────────────────────────┐
│  ⬡  CRYPTOGRAPHY LAB          [AES-256] [RSA-2048] [SHA-256]        │
├───────────────────────┬──────────────────────────────────────────────┤
│  FILE PATHS           │  TERMINAL OUTPUT                   [Clear]  │
│  Input CSV   [path…]  │                                              │
│  Encrypted   [path…]  │  > color-coded log messages                 │
│  Metadata    [path…]  │  > previews, hashes, summaries              │
│  Decrypted   [path…]  │  > errors shown in red                      │
│  Keys folder [path…]  │                                              │
│                       │                                              │
│  ACTIONS              │                                              │
│  [🔑 Generate Keys  ] │                                              │
│  [🔒 Encrypt File   ] │                                              │
│  [🔓 Decrypt File   ] │                                              │
│  [✔  Verify         ] │                                              │
│  [📋 Base64 Output  ] │                                              │
│  [▶  Full Pipeline  ] │                                              │
│                       │                                              │
│  LAST RUN STATS       │                                              │
│  [Plaintext][Cipher ] │                                              │
│  [Enc time ][Dec time]│                                              │
├───────────────────────┴──────────────────────────────────────────────┤
│  Status message…                              ● KEYS LOADED / NO KEYS│
└──────────────────────────────────────────────────────────────────────┘
```

### Button Descriptions

| Button | Color | What it does |
|--------|-------|--------------|
| 🔑 Generate RSA Key Pair | Teal | Generates RSA-2048 public/private key pair and saves both as `.pem` files in the `keys/` folder. Status bar updates to KEYS LOADED. |
| 🔒 Encrypt File | Blue | Loads the input CSV, generates a random AES-256 key and IV, encrypts with AES-CBC, then wraps the AES key with RSA OAEP. Saves ciphertext and metadata. |
| 🔓 Decrypt File | Purple | Reads `metadata.json` for the IV and encrypted AES key, decrypts the AES key with the RSA private key, then decrypts the ciphertext to recover the original file. |
| ✔ Verify Integrity | Green | Computes SHA-256 hashes of both the original and decrypted files and compares them byte-for-byte. Prints SUCCESS or FAILED. |
| 📋 Show Base64 Output | Amber | Reads the binary ciphertext and displays it as Base64 text in the terminal for inspection and copying. |
| ▶ Full Pipeline Demo | Teal | Runs all four steps in sequence automatically: Generate Keys → Encrypt → Decrypt → Verify. Best option for a live demonstration. |

### Status Bar Indicators

- `● NO KEYS` in red — RSA keys have not been generated yet. Encryption and decryption will fail.
- `● KEYS LOADED` in green — RSA `.pem` files found in the keys folder. Ready to encrypt and decrypt.

### File Path Fields
All path fields are editable. You can browse for a different input file using the `…` button. This allows you to encrypt any CSV, TXT, JSON, or binary file, not just the default `students.csv`.

---

## 9. CLI Walkthrough

Run `python main.py` to see the numbered menu:

```
  Main Menu:
  [1] Generate RSA Key Pair
  [2] Encrypt student records
  [3] Decrypt student records
  [4] Verify integrity (SHA-256)
  [5] Show Base64 ciphertext
  [6] Full pipeline demo
  [0] Exit
```

The CLI produces identical results to the GUI. Use option `6` for a full automated demonstration.

---

## 10. Program Flow

The program always follows this exact sequence, whether triggered step-by-step or via the Full Pipeline Demo:

```
Step 1 — Load original data
         students.csv is read from the data/ folder.
         A preview of the first 3 rows is displayed.

Step 2 — Generate encryption material
         A random 256-bit AES session key is created in memory.
         A random 128-bit IV is created in memory.
         (RSA key pair must already exist from the Generate Keys step.)

Step 3 — Encrypt the file
         AES-256-CBC encrypts the entire file content using the session
         key and IV. PKCS7 padding is applied to the final block.
         RSA-2048 OAEP encrypts the AES session key with the public key.
         Ciphertext  → output/students_encrypted.bin
         IV + encrypted AES key → output/metadata.json

Step 4 — Decrypt the file
         IV and encrypted AES key are loaded from metadata.json.
         RSA-2048 OAEP decrypts the AES key using the private key.
         AES-256-CBC decrypts the ciphertext using the recovered key + IV.
         PKCS7 padding is stripped from the final block.
         Recovered plaintext → output/students_decrypted.csv

Step 5 — Verify integrity
         SHA-256(students.csv)           → hash_A
         SHA-256(students_decrypted.csv) → hash_B
         If hash_A == hash_B:
             VERIFICATION SUCCESS
         Else:
             VERIFICATION FAILED
```

### Expected Terminal Output (Full Pipeline Demo)

```
╔══════════════════════════════════════════════════════════╗
║          FULL PIPELINE DEMO  —  ALL STEPS               ║
╚══════════════════════════════════════════════════════════╝
  Running: Generate Keys → Encrypt → Decrypt → Verify

────────────────────────────────────────────────────────
[ 1/4 ]  GENERATE RSA KEY PAIR
  ✔  RSA-2048 key pair generated and saved.

────────────────────────────────────────────────────────
[ 2/4 ]  ENCRYPT FILE
  ✔  Encrypted → output/students_encrypted.bin
  ℹ  1097 bytes → 1104 bytes  |  8.51 ms

────────────────────────────────────────────────────────
[ 3/4 ]  DECRYPT FILE
  ✔  Decrypted → output/students_decrypted.csv
  ℹ  1097 bytes recovered  |  2.47 ms

────────────────────────────────────────────────────────
[ 4/4 ]  INTEGRITY VERIFICATION
  Original  SHA-256 : 6fb993200b17285bc08a0051e1cf8d6e10f59e3a65daceafdee090fc47a5554f
  Decrypted SHA-256 : 6fb993200b17285bc08a0051e1cf8d6e10f59e3a65daceafdee090fc47a5554f

  ✔  VERIFICATION SUCCESS — decrypted file matches the original.
────────────────────────────────────────────────────────
  ✔  Pipeline complete — all steps finished successfully.
```

---

## 11. Functions Reference

All functions live in `crypto_utils.py`.

### Key Generation

**`generate_aes_key(key_size=32) -> bytes`**
Generates a cryptographically secure random AES key using `Crypto.Random.get_random_bytes`. Default is 32 bytes (256 bits).

**`generate_rsa_keypair(bits=2048) -> (private_key, public_key)`**
Generates an RSA key pair. Returns both keys as PyCryptodome RSA key objects.

**`save_rsa_keys(private_key, public_key, keys_dir="keys") -> (priv_path, pub_path)`**
Exports both keys to PEM format and writes them to disk in the specified directory.

**`load_rsa_keys(keys_dir="keys") -> (private_key, public_key)`**
Reads both PEM files from disk and returns PyCryptodome RSA key objects ready for use.

### Metadata

**`save_metadata(iv, encrypted_aes_key, metadata_path)`**
Base64-encodes the IV and the RSA-encrypted AES key, then saves them as a JSON file alongside algorithm parameters (`aes_mode`, `rsa_bits`, `padding`).

**`load_metadata(metadata_path) -> (iv, encrypted_aes_key)`**
Reads the JSON metadata file and returns the raw IV bytes and encrypted AES key bytes.

### Encryption & Decryption

**`encrypt_file(input_path, output_path, metadata_path, public_key) -> dict`**
Full hybrid encryption pipeline in one call. Internally calls `generate_aes_key`, `AES.new`, `pad`, `PKCS1_OAEP.encrypt`, and `save_metadata`. Returns a stats dict with `plaintext_size`, `ciphertext_size`, `time_seconds`, `aes_key_b64`, `iv_b64`, and `ciphertext_b64_preview`.

**`decrypt_file(input_path, output_path, metadata_path, private_key) -> dict`**
Full hybrid decryption pipeline in one call. Internally calls `load_metadata`, `PKCS1_OAEP.decrypt`, `AES.new`, and `unpad`. Returns a stats dict with `recovered_size` and `time_seconds`.

### Integrity Verification

**`sha256_hash(filepath) -> str`**
Computes the SHA-256 hash of any file in 8 KB chunks to handle large files efficiently. Returns a 64-character lowercase hex string.

**`verify_files(original_path, decrypted_path) -> dict`**
Hashes both files and returns `{"original_hash": str, "decrypted_hash": str, "match": bool}`.

---

## 12. Output Files

After running the full pipeline the `output/` folder contains three files:

### `students_encrypted.bin`
Raw binary AES-256-CBC ciphertext. Completely unreadable without the matching private key and metadata. Opening it in a text editor or hex viewer shows random binary noise with no visible structure.

### `metadata.json`
```json
{
  "iv": "aBcDeFgHiJkLmNoP==",
  "encrypted_aes_key": "Tm9uZSBvZiB5b3VyIGJ1c2luZXNz...",
  "aes_mode": "AES-256-CBC",
  "rsa_bits": 2048,
  "padding": "PKCS7"
}
```
Required for decryption. The AES key is not stored in plaintext — it is RSA-encrypted and can only be recovered with the private key.

### `students_decrypted.csv`
The recovered plaintext after decryption. Byte-for-byte identical to the original `students.csv`, as confirmed by SHA-256 verification.

---

## 13. Security Notes

| Property | Detail |
|----------|--------|
| AES mode | CBC — each block depends on the previous, preventing pattern leakage |
| IV handling | Fresh random IV generated every encryption run, never reused |
| RSA padding | OAEP — resistant to chosen-ciphertext attacks |
| Key storage | RSA keys stored as PEM files in the `keys/` folder |
| Input data | All student records are fake and anonymized |
| Hash function | SHA-256 is collision-resistant for all practical purposes |

### One Security Limitation

The RSA private key (`keys/private_key.pem`) is stored as a plain, unencrypted PEM file on disk. Anyone with access to this file can decrypt any ciphertext produced by the matching public key. In a production system the private key would be protected with a passphrase, derived using a KDF (Key Derivation Function), or stored in dedicated secure hardware such as an HSM or TPM.

---

## 14. Security Understanding Q&A

**Q1: Which algorithm did you choose, and why?**
Path 3 (Hybrid Encryption) was chosen because it combines the strengths of both symmetric and asymmetric cryptography. AES-256-CBC handles the file data due to its speed and unlimited data size. RSA-2048 handles key distribution so no shared secret needs to be transmitted. This mirrors exactly how real-world protocols like TLS/HTTPS work.

**Q2: What is the key used for in your project?**
Two keys are used. The AES-256 session key encrypts and decrypts the actual CSV file content. The RSA-2048 key pair handles key exchange: the public key encrypts the AES session key for safe storage, and the private key decrypts it at the start of every decryption operation.

**Q3: What is the role of the IV in your project?**
The Initialization Vector (IV) is a random 16-byte value generated fresh for every encryption. In CBC mode it is XORed with the first plaintext block before encryption begins. This guarantees that encrypting the same file twice with the same AES key produces completely different ciphertext, which prevents an attacker from detecting that the same data was encrypted twice. The IV is not secret and is stored openly in `metadata.json`.

**Q4: What does the encrypted output look like compared to the original data?**
The original `students.csv` is human-readable text containing names, IDs, and grades laid out in comma-separated rows. The encrypted output `students_encrypted.bin` is binary noise with no visible structure. When viewed as Base64, it is an unrecognizable string of random-looking characters with no resemblance to the original content.

**Q5: How did you prove that decryption recovered the original data?**
SHA-256 hashes of both the original file and the decrypted file are computed and compared. If both 64-character hex strings are identical, the files are provably byte-for-byte the same. The terminal displays both hashes side-by-side followed by a clear SUCCESS or FAILED verdict.

**Q6: What is one security limitation of your project?**
The RSA private key is stored as a plain unencrypted PEM file on disk. Any user or process with read access to `keys/private_key.pem` can decrypt any ciphertext produced by this application. A more secure implementation would encrypt the private key with a passphrase using a Key Derivation Function, or store it in dedicated secure hardware such as a Hardware Security Module (HSM).
