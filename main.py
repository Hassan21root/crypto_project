"""
main.py
-------
Cryptography Lib Lab — Main Entry Point
Path 3: Hybrid Encryption (AES-256-CBC + RSA-2048)
Scenario: Secure Student Records (CSV)

Features:
  [1] Generate RSA Key Pair
  [2] Encrypt student records (Hybrid: AES data + RSA wraps AES key)
  [3] Decrypt student records
  [4] Verify integrity (SHA-256)
  [5] Show encrypted output (Base64)
  [6] Full pipeline demo (all steps at once)
  [0] Exit
"""

import os
import sys
import base64

from crypto_utils import (
    generate_rsa_keypair,
    save_rsa_keys,
    load_rsa_keys,
    encrypt_file,
    decrypt_file,
    verify_files,
    sha256_hash,
)

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR      = os.path.join(BASE_DIR, "data")
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")
KEYS_DIR      = os.path.join(BASE_DIR, "keys")

ORIGINAL_FILE  = os.path.join(DATA_DIR,   "students.csv")
ENCRYPTED_FILE = os.path.join(OUTPUT_DIR, "students_encrypted.bin")
METADATA_FILE  = os.path.join(OUTPUT_DIR, "metadata.json")
DECRYPTED_FILE = os.path.join(OUTPUT_DIR, "students_decrypted.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR,   exist_ok=True)


# ─── Helpers ──────────────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║        CRYPTOGRAPHY LIB LAB  —  Path 3              ║
║        Hybrid Encryption: AES-256 + RSA-2048         ║
║        Scenario : Secure Student Records (CSV)       ║
╚══════════════════════════════════════════════════════╝{RESET}
""")

def section(title: str):
    print(f"\n{YELLOW}{BOLD}{'─'*54}")
    print(f"  {title}")
    print(f"{'─'*54}{RESET}")

def ok(msg: str):
    print(f"  {GREEN}✔  {msg}{RESET}")

def info(msg: str):
    print(f"  {CYAN}ℹ  {msg}{RESET}")

def err(msg: str):
    print(f"  {RED}✘  {msg}{RESET}")

def keys_exist() -> bool:
    return (
        os.path.exists(os.path.join(KEYS_DIR, "private_key.pem")) and
        os.path.exists(os.path.join(KEYS_DIR, "public_key.pem"))
    )


# ─── Menu Actions ─────────────────────────────────────────────────────────────

def action_generate_keys():
    section("STEP 1 — Generate RSA-2048 Key Pair")
    info("Generating RSA-2048 key pair … this may take a moment.")
    private_key, public_key = generate_rsa_keypair(bits=2048)
    priv_path, pub_path = save_rsa_keys(private_key, public_key, KEYS_DIR)
    ok(f"Private key saved → {priv_path}")
    ok(f"Public  key saved → {pub_path}")
    info("The PUBLIC key will encrypt the AES session key.")
    info("The PRIVATE key will decrypt it during decryption.")


def action_encrypt():
    section("STEP 2 — Encrypt Student Records (Hybrid AES + RSA)")

    if not os.path.exists(ORIGINAL_FILE):
        err(f"Input file not found: {ORIGINAL_FILE}")
        return

    if not keys_exist():
        err("RSA keys not found. Please generate keys first (Option 1).")
        return

    _, public_key = load_rsa_keys(KEYS_DIR)

    info(f"Loading original file  → {ORIGINAL_FILE}")
    with open(ORIGINAL_FILE, "r") as f:
        preview_lines = f.readlines()[:3]
    print(f"\n  {DIM}[ Original data preview (first 3 rows) ]{RESET}")
    for line in preview_lines:
        print(f"  {DIM}{line.rstrip()}{RESET}")

    print()
    info("Encrypting with AES-256-CBC …")
    info("Wrapping AES key with RSA-2048 (OAEP) …")

    result = encrypt_file(ORIGINAL_FILE, ENCRYPTED_FILE, METADATA_FILE, public_key)

    ok(f"Ciphertext saved       → {ENCRYPTED_FILE}")
    ok(f"Metadata (IV+key) saved→ {METADATA_FILE}")
    print()
    print(f"  {BOLD}Encryption Summary:{RESET}")
    print(f"  {'Plaintext size:':<28} {result['plaintext_size']} bytes")
    print(f"  {'Ciphertext size:':<28} {result['ciphertext_size']} bytes")
    print(f"  {'Encryption time:':<28} {result['time_seconds']*1000:.4f} ms")
    print(f"  {'AES key (Base64):':<28} {result['aes_key_b64']}")
    print(f"  {'IV (Base64):':<28} {result['iv_b64']}")
    print(f"\n  {BOLD}Ciphertext preview (Base64):{RESET}")
    print(f"  {DIM}{result['ciphertext_b64_preview']}{RESET}")


def action_decrypt():
    section("STEP 3 — Decrypt Student Records")

    if not os.path.exists(ENCRYPTED_FILE):
        err(f"Encrypted file not found: {ENCRYPTED_FILE}")
        err("Please encrypt first (Option 2).")
        return

    if not keys_exist():
        err("RSA keys not found. Please generate keys first (Option 1).")
        return

    private_key, _ = load_rsa_keys(KEYS_DIR)

    info("Decrypting RSA-wrapped AES key using private key …")
    info("Decrypting ciphertext using recovered AES key …")
    info("Removing PKCS7 padding …")

    result = decrypt_file(ENCRYPTED_FILE, DECRYPTED_FILE, METADATA_FILE, private_key)

    ok(f"Decrypted file saved   → {DECRYPTED_FILE}")
    print()
    print(f"  {BOLD}Decryption Summary:{RESET}")
    print(f"  {'Recovered size:':<28} {result['recovered_size']} bytes")
    print(f"  {'Decryption time:':<28} {result['time_seconds']*1000:.4f} ms")

    print(f"\n  {DIM}[ Decrypted data preview (first 3 rows) ]{RESET}")
    with open(DECRYPTED_FILE, "r") as f:
        for i, line in enumerate(f):
            if i >= 3:
                break
            print(f"  {DIM}{line.rstrip()}{RESET}")


def action_verify():
    section("STEP 4 — Integrity Verification (SHA-256)")

    if not os.path.exists(ORIGINAL_FILE):
        err(f"Original file not found: {ORIGINAL_FILE}")
        return
    if not os.path.exists(DECRYPTED_FILE):
        err(f"Decrypted file not found: {DECRYPTED_FILE}")
        err("Please decrypt first (Option 3).")
        return

    result = verify_files(ORIGINAL_FILE, DECRYPTED_FILE)

    print(f"\n  {'Original  SHA-256:':<28} {result['original_hash']}")
    print(f"  {'Decrypted SHA-256:':<28} {result['decrypted_hash']}")
    print()

    if result["match"]:
        print(f"  {GREEN}{BOLD}✔  Verification result: SUCCESS — decrypted file matches the original file.{RESET}")
    else:
        print(f"  {RED}{BOLD}✘  Verification result: FAILED — files do not match!{RESET}")


def action_show_base64():
    section("Base64 Encoded Ciphertext")

    if not os.path.exists(ENCRYPTED_FILE):
        err(f"Encrypted file not found: {ENCRYPTED_FILE}")
        err("Please encrypt first (Option 2).")
        return

    with open(ENCRYPTED_FILE, "rb") as f:
        raw = f.read()

    b64 = base64.b64encode(raw).decode()

    info(f"Total ciphertext length : {len(raw)} bytes")
    info(f"Base64 encoded length   : {len(b64)} characters")
    print(f"\n  {BOLD}Full Base64 Ciphertext:{RESET}")

    # Print in 76-char lines for readability
    for i in range(0, min(len(b64), 456), 76):
        print(f"  {DIM}{b64[i:i+76]}{RESET}")
    if len(b64) > 456:
        print(f"  {DIM}... (truncated, showing first 456 chars of {len(b64)} total){RESET}")


def action_full_demo():
    section("FULL PIPELINE DEMO — All Steps Sequentially")
    print(f"  {DIM}Running: Generate Keys → Encrypt → Decrypt → Verify{RESET}\n")
    action_generate_keys()
    action_encrypt()
    action_decrypt()
    action_verify()
    print(f"\n  {GREEN}{BOLD}Pipeline complete!{RESET}")


# ─── Main Menu ────────────────────────────────────────────────────────────────

def menu():
    banner()
    while True:
        print(f"""
{BOLD}  Main Menu:{RESET}
  {CYAN}[1]{RESET} Generate RSA Key Pair
  {CYAN}[2]{RESET} Encrypt student records
  {CYAN}[3]{RESET} Decrypt student records
  {CYAN}[4]{RESET} Verify integrity (SHA-256)
  {CYAN}[5]{RESET} Show Base64 ciphertext
  {CYAN}[6]{RESET} Full pipeline demo  {DIM}(runs all steps at once){RESET}
  {CYAN}[0]{RESET} Exit
""")
        choice = input("  Enter your choice: ").strip()

        if   choice == "1": action_generate_keys()
        elif choice == "2": action_encrypt()
        elif choice == "3": action_decrypt()
        elif choice == "4": action_verify()
        elif choice == "5": action_show_base64()
        elif choice == "6": action_full_demo()
        elif choice == "0":
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            sys.exit(0)
        else:
            err("Invalid choice. Please enter 0–6.")


if __name__ == "__main__":
    menu()
