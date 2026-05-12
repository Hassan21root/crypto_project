"""
gui.py
------
Cryptography Lib Lab — Tkinter GUI
Dark cybersecurity-themed interface
Path 3: Hybrid Encryption (AES-256-CBC + RSA-2048)
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64
import time

# ── ensure project root is on path ──────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from crypto_utils import (
    generate_rsa_keypair,
    save_rsa_keys,
    load_rsa_keys,
    encrypt_file,
    decrypt_file,
    verify_files,
    sha256_hash,
)

# ── Default paths ────────────────────────────────────────────────────────────
DATA_DIR      = os.path.join(BASE_DIR, "data")
OUTPUT_DIR    = os.path.join(BASE_DIR, "output")
KEYS_DIR      = os.path.join(BASE_DIR, "keys")
ORIGINAL_FILE  = os.path.join(DATA_DIR,   "students.csv")
ENCRYPTED_FILE = os.path.join(OUTPUT_DIR, "students_encrypted.bin")
METADATA_FILE  = os.path.join(OUTPUT_DIR, "metadata.json")
DECRYPTED_FILE = os.path.join(OUTPUT_DIR, "students_decrypted.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(KEYS_DIR,   exist_ok=True)

# ── Colour palette ───────────────────────────────────────────────────────────
BG        = "#0d1117"   # near-black
PANEL     = "#161b22"   # card background
BORDER    = "#30363d"   # subtle border
ACCENT    = "#00d4aa"   # teal/mint — main accent
ACCENT2   = "#58a6ff"   # electric blue — secondary accent
SUCCESS   = "#3fb950"   # green
WARNING   = "#d29922"   # amber
DANGER    = "#f85149"   # red
TEXT      = "#e6edf3"   # primary text
MUTED     = "#8b949e"   # muted / secondary text
CODE_BG   = "#0d1117"   # terminal background
CODE_FG   = "#00d4aa"   # terminal text


class CryptoLabApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cryptography Lab  —  Hybrid AES-256 + RSA-2048")
        self.geometry("1100x780")
        self.minsize(900, 650)
        self.configure(bg=BG)

        # State
        self.input_path  = tk.StringVar(value=ORIGINAL_FILE)
        self.enc_path    = tk.StringVar(value=ENCRYPTED_FILE)
        self.meta_path   = tk.StringVar(value=METADATA_FILE)
        self.dec_path    = tk.StringVar(value=DECRYPTED_FILE)
        self.keys_dir    = tk.StringVar(value=KEYS_DIR)

        self._build_ui()
        self._log("🔐  Cryptography Lab ready.", color=ACCENT)
        self._log(f"    Algorithm  :  AES-256-CBC  +  RSA-2048 (OAEP)", color=MUTED)
        self._log(f"    Scenario   :  Secure Student Records (CSV)", color=MUTED)
        self._log(f"    Library    :  PyCryptodome", color=MUTED)
        self._update_status_bar()

    # ── UI Construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=PANEL, height=64)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        tk.Label(
            hdr, text="⬡", font=("Courier", 22, "bold"),
            bg=PANEL, fg=ACCENT
        ).pack(side="left", padx=(20, 8), pady=12)

        title_frame = tk.Frame(hdr, bg=PANEL)
        title_frame.pack(side="left", pady=10)
        tk.Label(
            title_frame, text="CRYPTOGRAPHY LAB",
            font=("Courier", 15, "bold"), bg=PANEL, fg=TEXT
        ).pack(anchor="w")
        tk.Label(
            title_frame, text="Hybrid Encryption  ·  AES-256-CBC  +  RSA-2048",
            font=("Courier", 9), bg=PANEL, fg=MUTED
        ).pack(anchor="w")

        # badges top-right
        badge_frame = tk.Frame(hdr, bg=PANEL)
        badge_frame.pack(side="right", padx=20)
        self._badge(badge_frame, "AES-256", ACCENT).pack(side="left", padx=4)
        self._badge(badge_frame, "RSA-2048", ACCENT2).pack(side="left", padx=4)
        self._badge(badge_frame, "SHA-256", SUCCESS).pack(side="left", padx=4)

        # divider
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # ── Main area: left panel + right terminal ─────────────────────────
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=0, pady=0)

        left = tk.Frame(main, bg=BG, width=340)
        left.pack(side="left", fill="y", padx=(16, 8), pady=16)
        left.pack_propagate(False)

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(0, 16), pady=16)

        self._build_left(left)
        self._build_right(right)

        # ── Status bar ────────────────────────────────────────────────────
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Frame(self, bg=PANEL, height=28)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        tk.Label(
            status_bar, textvariable=self.status_var,
            font=("Courier", 9), bg=PANEL, fg=MUTED, anchor="w"
        ).pack(side="left", padx=12, fill="y")
        self.keys_indicator = tk.Label(
            status_bar, text="● NO KEYS",
            font=("Courier", 9, "bold"), bg=PANEL, fg=DANGER
        )
        self.keys_indicator.pack(side="right", padx=12)

    def _build_left(self, parent):
        # ── File Paths section ─────────────────────────────────────────────
        self._section_label(parent, "FILE PATHS")

        self._path_row(parent, "Input CSV",    self.input_path,  self._browse_input)
        self._path_row(parent, "Encrypted",    self.enc_path,    None)
        self._path_row(parent, "Metadata",     self.meta_path,   None)
        self._path_row(parent, "Decrypted",    self.dec_path,    None)
        self._path_row(parent, "Keys folder",  self.keys_dir,    self._browse_keys)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=(12, 8))

        # ── Action Buttons ─────────────────────────────────────────────────
        self._section_label(parent, "ACTIONS")

        buttons = [
            ("🔑  Generate RSA Key Pair",   ACCENT,  self._action_genkeys),
            ("🔒  Encrypt File",            ACCENT2, self._action_encrypt),
            ("🔓  Decrypt File",            "#a371f7", self._action_decrypt),
            ("✔   Verify Integrity",        SUCCESS, self._action_verify),
            ("📋  Show Base64 Output",      WARNING, self._action_base64),
            ("▶   Full Pipeline Demo",      ACCENT,  self._action_full_demo),
        ]
        for label, color, cmd in buttons:
            self._action_btn(parent, label, color, cmd)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=(12, 8))

        # ── Stats panel ────────────────────────────────────────────────────
        self._section_label(parent, "LAST RUN STATS")
        stats_frame = tk.Frame(parent, bg=PANEL, bd=0)
        stats_frame.pack(fill="x", pady=(0, 4))
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)

        self.stat_plain  = self._stat_card(stats_frame, "Plaintext",  "—", 0, 0)
        self.stat_cipher = self._stat_card(stats_frame, "Ciphertext", "—", 0, 1)
        self.stat_enc_t  = self._stat_card(stats_frame, "Enc time",   "—", 1, 0)
        self.stat_dec_t  = self._stat_card(stats_frame, "Dec time",   "—", 1, 1)

    def _build_right(self, parent):
        # header row
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(0, 6))
        tk.Label(
            row, text="TERMINAL OUTPUT",
            font=("Courier", 10, "bold"), bg=BG, fg=MUTED
        ).pack(side="left")
        tk.Button(
            row, text="Clear", font=("Courier", 9),
            bg=PANEL, fg=MUTED, activebackground=BORDER,
            relief="flat", bd=0, padx=10, cursor="hand2",
            command=self._clear_log
        ).pack(side="right")

        # terminal widget
        term_frame = tk.Frame(parent, bg=CODE_BG, bd=0,
                              highlightbackground=BORDER, highlightthickness=1)
        term_frame.pack(fill="both", expand=True)

        self.terminal = tk.Text(
            term_frame,
            bg=CODE_BG, fg=CODE_FG,
            font=("Courier", 11),
            insertbackground=ACCENT,
            selectbackground=BORDER,
            relief="flat", bd=8,
            state="disabled",
            wrap="word",
            cursor="arrow",
        )
        sb = ttk.Scrollbar(term_frame, orient="vertical",
                           command=self.terminal.yview)
        self.terminal.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.terminal.pack(fill="both", expand=True)

        # tag colours
        self.terminal.tag_config("accent",  foreground=ACCENT)
        self.terminal.tag_config("accent2", foreground=ACCENT2)
        self.terminal.tag_config("success", foreground=SUCCESS)
        self.terminal.tag_config("warning", foreground=WARNING)
        self.terminal.tag_config("danger",  foreground=DANGER)
        self.terminal.tag_config("muted",   foreground=MUTED)
        self.terminal.tag_config("text",    foreground=TEXT)
        self.terminal.tag_config("bold",    font=("Courier", 11, "bold"))
        self.terminal.tag_config("purple",  foreground="#a371f7")

    # ── Widget helpers ───────────────────────────────────────────────────────

    def _badge(self, parent, text, color):
        return tk.Label(
            parent, text=text,
            font=("Courier", 8, "bold"),
            bg=color, fg=BG,
            padx=7, pady=2,
        )

    def _section_label(self, parent, text):
        tk.Label(
            parent, text=text,
            font=("Courier", 8, "bold"),
            bg=BG, fg=MUTED, anchor="w"
        ).pack(fill="x", pady=(8, 2))

    def _path_row(self, parent, label, var, browse_cmd):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=2)
        tk.Label(
            row, text=f"{label:<12}", font=("Courier", 8),
            bg=BG, fg=MUTED, width=12, anchor="w"
        ).pack(side="left")
        entry = tk.Entry(
            row, textvariable=var,
            font=("Courier", 8), bg=PANEL, fg=ACCENT,
            insertbackground=ACCENT, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        entry.pack(side="left", fill="x", expand=True, ipady=3)
        if browse_cmd:
            tk.Button(
                row, text="…", font=("Courier", 8),
                bg=BORDER, fg=TEXT, relief="flat",
                padx=4, cursor="hand2",
                command=browse_cmd
            ).pack(side="left", padx=(2, 0))

    def _action_btn(self, parent, label, color, cmd):
        btn = tk.Button(
            parent, text=label,
            font=("Courier", 10, "bold"),
            bg=PANEL, fg=color,
            activebackground=BORDER, activeforeground=color,
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=color,
            padx=12, pady=7,
            anchor="w", cursor="hand2",
            command=cmd,
        )
        btn.pack(fill="x", pady=3)
        # hover effect
        btn.bind("<Enter>", lambda e: btn.configure(bg=BORDER))
        btn.bind("<Leave>", lambda e: btn.configure(bg=PANEL))

    def _stat_card(self, parent, label, value, row, col):
        frame = tk.Frame(parent, bg=PANEL,
                         highlightbackground=BORDER, highlightthickness=1)
        frame.grid(row=row, column=col, padx=3, pady=3, sticky="ew")
        tk.Label(frame, text=label, font=("Courier", 8),
                 bg=PANEL, fg=MUTED).pack(anchor="w", padx=8, pady=(6, 0))
        val_label = tk.Label(frame, text=value, font=("Courier", 12, "bold"),
                             bg=PANEL, fg=TEXT)
        val_label.pack(anchor="w", padx=8, pady=(0, 6))
        return val_label

    # ── Logging ──────────────────────────────────────────────────────────────

    def _log(self, msg, color="accent", newline=True):
        tag_map = {
            ACCENT:   "accent",
            ACCENT2:  "accent2",
            SUCCESS:  "success",
            WARNING:  "warning",
            DANGER:   "danger",
            MUTED:    "muted",
            TEXT:     "text",
            "#a371f7": "purple",
        }
        tag = tag_map.get(color, "accent")
        self.terminal.configure(state="normal")
        self.terminal.insert("end", msg + ("\n" if newline else ""), (tag,))
        self.terminal.configure(state="disabled")
        self.terminal.see("end")

    def _log_divider(self):
        self._log("─" * 68, color=BORDER if True else MUTED)

    def _clear_log(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")

    def _set_status(self, msg):
        self.status_var.set(f"  {msg}")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _keys_exist(self):
        return (
            os.path.exists(os.path.join(self.keys_dir.get(), "private_key.pem")) and
            os.path.exists(os.path.join(self.keys_dir.get(), "public_key.pem"))
        )

    def _update_status_bar(self):
        if self._keys_exist():
            self.keys_indicator.configure(text="● KEYS LOADED", fg=SUCCESS)
        else:
            self.keys_indicator.configure(text="● NO KEYS",     fg=DANGER)

    def _browse_input(self):
        path = filedialog.askopenfilename(
            title="Select input file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            self.input_path.set(path)

    def _browse_keys(self):
        path = filedialog.askdirectory(title="Select keys folder")
        if path:
            self.keys_dir.set(path)

    def _run_in_thread(self, fn):
        """Run a blocking function in a background thread."""
        t = threading.Thread(target=fn, daemon=True)
        t.start()

    # ── Actions ──────────────────────────────────────────────────────────────

    def _action_genkeys(self):
        def _run():
            self._log_divider()
            self._log("[ GENERATE RSA KEY PAIR ]", color=ACCENT)
            self._log("  Generating RSA-2048 key pair …", color=MUTED)
            self._set_status("Generating RSA keys…")
            t0 = time.perf_counter()
            try:
                private_key, public_key = generate_rsa_keypair(2048)
                kdir = self.keys_dir.get()
                os.makedirs(kdir, exist_ok=True)
                priv, pub = save_rsa_keys(private_key, public_key, kdir)
                elapsed = (time.perf_counter() - t0) * 1000
                self._log(f"  ✔  Private key  →  {priv}", color=SUCCESS)
                self._log(f"  ✔  Public key   →  {pub}",  color=SUCCESS)
                self._log(f"  ℹ  Generated in {elapsed:.1f} ms", color=MUTED)
                self._log("")
                self._log("  PUBLIC  KEY  =  encrypts the AES session key", color=MUTED)
                self._log("  PRIVATE KEY  =  decrypts the AES session key", color=MUTED)
                self._set_status("RSA key pair generated.")
                self.after(0, self._update_status_bar)
            except Exception as ex:
                self._log(f"  ✘  Error: {ex}", color=DANGER)
                self._set_status("Key generation failed.")
        self._run_in_thread(_run)

    def _action_encrypt(self):
        def _run():
            self._log_divider()
            self._log("[ ENCRYPT FILE ]", color=ACCENT2)
            inp = self.input_path.get()
            if not os.path.exists(inp):
                self._log(f"  ✘  File not found: {inp}", color=DANGER)
                return
            if not self._keys_exist():
                self._log("  ✘  RSA keys not found — generate keys first.", color=DANGER)
                return
            try:
                self._log(f"  ℹ  Input file     →  {inp}", color=MUTED)
                with open(inp, "r", errors="replace") as f:
                    lines = f.readlines()
                self._log(f"  ℹ  Rows loaded    →  {len(lines)} lines", color=MUTED)
                self._log("", color=MUTED)
                self._log("  [ Original data preview — first 3 rows ]", color=MUTED)
                for line in lines[:3]:
                    self._log(f"  {line.rstrip()}", color=TEXT)
                self._log("")
                self._log("  Generating AES-256 session key …", color=MUTED)
                self._log("  Encrypting file with AES-256-CBC …", color=MUTED)
                self._log("  Wrapping AES key with RSA-2048 (OAEP) …", color=MUTED)
                self._set_status("Encrypting…")

                os.makedirs(os.path.dirname(self.enc_path.get()) or ".", exist_ok=True)
                _, public_key = load_rsa_keys(self.keys_dir.get())
                result = encrypt_file(
                    inp, self.enc_path.get(),
                    self.meta_path.get(), public_key
                )

                self._log("")
                self._log(f"  ✔  Ciphertext     →  {self.enc_path.get()}", color=SUCCESS)
                self._log(f"  ✔  Metadata       →  {self.meta_path.get()}",  color=SUCCESS)
                self._log("")
                self._log("  ┌─ Encryption Summary ────────────────────────┐", color=ACCENT2)
                self._log(f"  │  Plaintext size   {result['plaintext_size']:>7} bytes               │", color=TEXT)
                self._log(f"  │  Ciphertext size  {result['ciphertext_size']:>7} bytes               │", color=TEXT)
                self._log(f"  │  Encryption time  {result['time_seconds']*1000:>7.2f} ms                 │", color=TEXT)
                self._log(f"  │  AES key (b64)    {result['aes_key_b64'][:24]}…  │", color=ACCENT)
                self._log(f"  │  IV (b64)         {result['iv_b64'][:24]}…  │", color=ACCENT)
                self._log(f"  └─────────────────────────────────────────────┘", color=ACCENT2)
                self._log("")
                self._log("  [ Ciphertext preview (Base64) ]", color=MUTED)
                self._log(f"  {result['ciphertext_b64_preview']}", color=ACCENT)

                self.stat_plain .configure(text=f"{result['plaintext_size']} B")
                self.stat_cipher.configure(text=f"{result['ciphertext_size']} B")
                self.stat_enc_t .configure(text=f"{result['time_seconds']*1000:.2f}ms")
                self._set_status("File encrypted successfully.")
            except Exception as ex:
                self._log(f"  ✘  Error: {ex}", color=DANGER)
                self._set_status("Encryption failed.")
        self._run_in_thread(_run)

    def _action_decrypt(self):
        def _run():
            self._log_divider()
            self._log("[ DECRYPT FILE ]", color="#a371f7")
            if not os.path.exists(self.enc_path.get()):
                self._log(f"  ✘  Encrypted file not found — encrypt first.", color=DANGER)
                return
            if not self._keys_exist():
                self._log("  ✘  RSA keys not found — generate keys first.", color=DANGER)
                return
            try:
                self._log("  Decrypting AES key using RSA private key …", color=MUTED)
                self._log("  Decrypting ciphertext with recovered AES key …", color=MUTED)
                self._log("  Removing PKCS7 padding …", color=MUTED)
                self._set_status("Decrypting…")

                private_key, _ = load_rsa_keys(self.keys_dir.get())
                result = decrypt_file(
                    self.enc_path.get(), self.dec_path.get(),
                    self.meta_path.get(), private_key
                )

                self._log(f"\n  ✔  Decrypted file  →  {self.dec_path.get()}", color=SUCCESS)
                self._log(f"  ℹ  Recovered size  →  {result['recovered_size']} bytes", color=MUTED)
                self._log(f"  ℹ  Decryption time →  {result['time_seconds']*1000:.2f} ms", color=MUTED)
                self._log("")
                self._log("  [ Decrypted data preview — first 3 rows ]", color=MUTED)
                with open(self.dec_path.get(), "r", errors="replace") as f:
                    for i, line in enumerate(f):
                        if i >= 3: break
                        self._log(f"  {line.rstrip()}", color=TEXT)

                self.stat_dec_t.configure(text=f"{result['time_seconds']*1000:.2f}ms")
                self._set_status("File decrypted successfully.")
            except Exception as ex:
                self._log(f"  ✘  Error: {ex}", color=DANGER)
                self._set_status("Decryption failed.")
        self._run_in_thread(_run)

    def _action_verify(self):
        def _run():
            self._log_divider()
            self._log("[ INTEGRITY VERIFICATION — SHA-256 ]", color=SUCCESS)
            if not os.path.exists(self.input_path.get()):
                self._log(f"  ✘  Original file not found.", color=DANGER); return
            if not os.path.exists(self.dec_path.get()):
                self._log(f"  ✘  Decrypted file not found — decrypt first.", color=DANGER); return
            try:
                self._set_status("Computing SHA-256 hashes…")
                result = verify_files(self.input_path.get(), self.dec_path.get())
                self._log(f"  Original  SHA-256:", color=MUTED)
                self._log(f"  {result['original_hash']}", color=ACCENT)
                self._log(f"\n  Decrypted SHA-256:", color=MUTED)
                self._log(f"  {result['decrypted_hash']}", color=ACCENT)
                self._log("")
                if result["match"]:
                    self._log("  ✔  VERIFICATION SUCCESS", color=SUCCESS)
                    self._log("      Decrypted file matches the original file exactly.", color=SUCCESS)
                    self._set_status("Verification: SUCCESS ✔")
                else:
                    self._log("  ✘  VERIFICATION FAILED — hashes do not match!", color=DANGER)
                    self._set_status("Verification: FAILED ✘")
            except Exception as ex:
                self._log(f"  ✘  Error: {ex}", color=DANGER)
        self._run_in_thread(_run)

    def _action_base64(self):
        def _run():
            self._log_divider()
            self._log("[ BASE64 CIPHERTEXT OUTPUT ]", color=WARNING)
            if not os.path.exists(self.enc_path.get()):
                self._log("  ✘  Encrypted file not found — encrypt first.", color=DANGER); return
            try:
                with open(self.enc_path.get(), "rb") as f:
                    raw = f.read()
                b64 = base64.b64encode(raw).decode()
                self._log(f"  ℹ  Raw size    : {len(raw)} bytes", color=MUTED)
                self._log(f"  ℹ  Base64 len  : {len(b64)} characters", color=MUTED)
                self._log("")
                self._log("  [ Full Base64 Ciphertext ]", color=WARNING)
                for i in range(0, min(len(b64), 608), 76):
                    self._log(f"  {b64[i:i+76]}", color=ACCENT)
                if len(b64) > 608:
                    self._log(f"  … (showing first 608 of {len(b64)} chars)", color=MUTED)
            except Exception as ex:
                self._log(f"  ✘  Error: {ex}", color=DANGER)
        self._run_in_thread(_run)

    def _action_full_demo(self):
        def _run():
            self._clear_log()
            self._log("╔══════════════════════════════════════════════════════════╗", color=ACCENT)
            self._log("║          FULL PIPELINE DEMO  —  ALL STEPS               ║", color=ACCENT)
            self._log("╚══════════════════════════════════════════════════════════╝", color=ACCENT)
            self._log("  Running: Generate Keys → Encrypt → Decrypt → Verify\n", color=MUTED)
            time.sleep(0.3)
            # run each step inline (not threaded since we're already in a thread)
            steps = [
                self._do_genkeys,
                self._do_encrypt,
                self._do_decrypt,
                self._do_verify,
            ]
            for step in steps:
                step()
                time.sleep(0.2)
            self._log_divider()
            self._log("  ✔  Pipeline complete — all steps finished successfully.", color=SUCCESS)
            self._set_status("Full pipeline demo complete.")
        self._run_in_thread(_run)

    # ── Inline (non-threaded) step implementations for pipeline ─────────────

    def _do_genkeys(self):
        self._log_divider()
        self._log("[ 1/4 ]  GENERATE RSA KEY PAIR", color=ACCENT)
        kdir = self.keys_dir.get()
        os.makedirs(kdir, exist_ok=True)
        private_key, public_key = generate_rsa_keypair(2048)
        save_rsa_keys(private_key, public_key, kdir)
        self._log("  ✔  RSA-2048 key pair generated and saved.", color=SUCCESS)
        self.after(0, self._update_status_bar)

    def _do_encrypt(self):
        self._log_divider()
        self._log("[ 2/4 ]  ENCRYPT FILE", color=ACCENT2)
        inp = self.input_path.get()
        if not os.path.exists(inp):
            self._log(f"  ✘  File not found: {inp}", color=DANGER); return
        os.makedirs(os.path.dirname(self.enc_path.get()) or ".", exist_ok=True)
        _, public_key = load_rsa_keys(self.keys_dir.get())
        result = encrypt_file(inp, self.enc_path.get(), self.meta_path.get(), public_key)
        self._log(f"  ✔  Encrypted → {self.enc_path.get()}", color=SUCCESS)
        self._log(f"  ℹ  {result['plaintext_size']} bytes → {result['ciphertext_size']} bytes  |  {result['time_seconds']*1000:.2f} ms", color=MUTED)
        self.stat_plain .configure(text=f"{result['plaintext_size']} B")
        self.stat_cipher.configure(text=f"{result['ciphertext_size']} B")
        self.stat_enc_t .configure(text=f"{result['time_seconds']*1000:.2f}ms")

    def _do_decrypt(self):
        self._log_divider()
        self._log("[ 3/4 ]  DECRYPT FILE", color="#a371f7")
        private_key, _ = load_rsa_keys(self.keys_dir.get())
        result = decrypt_file(self.enc_path.get(), self.dec_path.get(), self.meta_path.get(), private_key)
        self._log(f"  ✔  Decrypted → {self.dec_path.get()}", color=SUCCESS)
        self._log(f"  ℹ  {result['recovered_size']} bytes recovered  |  {result['time_seconds']*1000:.2f} ms", color=MUTED)
        self.stat_dec_t.configure(text=f"{result['time_seconds']*1000:.2f}ms")

    def _do_verify(self):
        self._log_divider()
        self._log("[ 4/4 ]  INTEGRITY VERIFICATION", color=SUCCESS)
        result = verify_files(self.input_path.get(), self.dec_path.get())
        self._log(f"  Original  SHA-256 : {result['original_hash']}", color=ACCENT)
        self._log(f"  Decrypted SHA-256 : {result['decrypted_hash']}", color=ACCENT)
        self._log("")
        if result["match"]:
            self._log("  ✔  VERIFICATION SUCCESS — decrypted file matches the original.", color=SUCCESS)
        else:
            self._log("  ✘  VERIFICATION FAILED!", color=DANGER)


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = CryptoLabApp()
    app.mainloop()
