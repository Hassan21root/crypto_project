"""
crypto_utils.py
---------------
Core cryptographic utility functions for the Cryptography Lib Lab project.
Implements Hybrid Encryption: AES (data) + RSA (AES key).

Algorithms used:
  - AES-256-CBC  : Encrypts the actual file data
  - RSA-2048     : Encrypts the AES session key
  - SHA-256      : Verifies integrity of decrypted output
"""

import os
import json
import time
import base64
import hashlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────────
#  KEY GENERATION
# ─────────────────────────────────────────────

def generate_aes_key(key_size: int = 32) -> bytes:
    """Generate a random AES key (default 256-bit = 32 bytes)."""
    return get_random_bytes(key_size)


def generate_rsa_keypair(bits: int = 2048):
    """
    Generate an RSA public/private key pair.
    Returns (private_key, public_key) as RSA key objects.
    """
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return private_key, public_key


def save_rsa_keys(private_key, public_key, keys_dir: str = "keys"):
    """Save RSA keys to PEM files."""
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path  = os.path.join(keys_dir, "public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.export_key("PEM"))
    with open(pub_path, "wb") as f:
        f.write(public_key.export_key("PEM"))

    return priv_path, pub_path


def load_rsa_keys(keys_dir: str = "keys"):
    """Load RSA keys from PEM files."""
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path  = os.path.join(keys_dir, "public_key.pem")

    with open(priv_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    with open(pub_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    return private_key, public_key


# ─────────────────────────────────────────────
#  METADATA (IV + ENCRYPTED AES KEY)
# ─────────────────────────────────────────────

def save_metadata(iv: bytes, encrypted_aes_key: bytes, metadata_path: str):
    """Save IV and RSA-encrypted AES key to a JSON metadata file (Base64 encoded)."""
    metadata = {
        "iv":                base64.b64encode(iv).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "aes_mode":          "AES-256-CBC",
        "rsa_bits":          2048,
        "padding":           "PKCS7"
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)


def load_metadata(metadata_path: str):
    """Load IV and RSA-encrypted AES key from JSON metadata file."""
    with open(metadata_path, "r") as f:
        metadata = json.load(f)

    iv                = base64.b64decode(metadata["iv"])
    encrypted_aes_key = base64.b64decode(metadata["encrypted_aes_key"])
    return iv, encrypted_aes_key


# ─────────────────────────────────────────────
#  ENCRYPTION
# ─────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, metadata_path: str, public_key) -> dict:
    """
    Hybrid encrypt a file:
      1. Generate a random AES-256 session key
      2. Encrypt the file with AES-CBC
      3. Encrypt the AES key with RSA public key
      4. Save ciphertext to output_path
      5. Save IV + encrypted AES key to metadata_path

    Returns a dict with timing, sizes, and Base64 preview.
    """
    start = time.perf_counter()

    # Step 1 — Generate AES session key + IV
    aes_key = generate_aes_key(32)          # 256-bit AES key
    iv      = get_random_bytes(16)           # 128-bit IV for CBC

    # Step 2 — Encrypt file data with AES-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    # Step 3 — Encrypt AES key with RSA public key (OAEP padding)
    cipher_rsa        = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Step 4 — Save metadata
    save_metadata(iv, encrypted_aes_key, metadata_path)

    elapsed = time.perf_counter() - start

    return {
        "plaintext_size":  len(plaintext),
        "ciphertext_size": len(ciphertext),
        "time_seconds":    elapsed,
        "ciphertext_b64_preview": base64.b64encode(ciphertext[:48]).decode() + "...",
        "aes_key_b64":     base64.b64encode(aes_key).decode(),
        "iv_b64":          base64.b64encode(iv).decode(),
    }


# ─────────────────────────────────────────────
#  DECRYPTION
# ─────────────────────────────────────────────

def decrypt_file(input_path: str, output_path: str, metadata_path: str, private_key) -> dict:
    """
    Hybrid decrypt a file:
      1. Load IV + encrypted AES key from metadata
      2. Decrypt AES key using RSA private key
      3. Decrypt file ciphertext using AES-CBC
      4. Write recovered plaintext to output_path

    Returns a dict with timing info.
    """
    start = time.perf_counter()

    # Step 1 — Load metadata
    iv, encrypted_aes_key = load_metadata(metadata_path)

    # Step 2 — Decrypt AES key with RSA private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key    = cipher_rsa.decrypt(encrypted_aes_key)

    # Step 3 — Decrypt file ciphertext with AES-CBC
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    # Step 4 — Write recovered plaintext
    with open(output_path, "wb") as f:
        f.write(plaintext)

    elapsed = time.perf_counter() - start

    return {
        "recovered_size": len(plaintext),
        "time_seconds":   elapsed,
    }


# ─────────────────────────────────────────────
#  INTEGRITY VERIFICATION (SHA-256)
# ─────────────────────────────────────────────

def sha256_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_files(original_path: str, decrypted_path: str) -> dict:
    """
    Compare SHA-256 hashes of two files.
    Returns dict with both hashes and a match boolean.
    """
    hash_original  = sha256_hash(original_path)
    hash_decrypted = sha256_hash(decrypted_path)
    match          = hash_original == hash_decrypted

    return {
        "original_hash":  hash_original,
        "decrypted_hash": hash_decrypted,
        "match":          match,
    }
