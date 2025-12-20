"""
main.py - Secure File System (single-file, final)
Features:
- Tabbed UI: Encrypt | Decrypt
- Shift preview, AES-256-CBC per-file encryption (random key)
- Encrypted file format: [1 byte shift][16 bytes IV][ciphertext bytes]
- AES key saved as base64 in .key file (in encrypted/ folder) — demo only
- Animated modern blue sliding loading bar during encrypt/decrypt
- Logs appended to app.log and visible in GUI
"""

import os
import sys
import base64
import subprocess
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

# ---------------------------
# Configuration
# ---------------------------
APP_TITLE = "Secure File System — Professional UI (Final)"
ROOT = os.path.abspath(os.path.dirname(__file__))
SHIFTED_DIR = os.path.join(ROOT, "shifted")
ENCRYPTED_DIR = os.path.join(ROOT, "encrypted")
LOG_FILE = os.path.join(ROOT, "app.log")

os.makedirs(SHIFTED_DIR, exist_ok=True)
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------------------------
# Helpers
# ---------------------------
def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gui_log(widget, message: str):
    logging.info(message)
    try:
        widget.config(state="normal")
        widget.insert(tk.END, f"{ts()} - {message}\n")
        widget.see(tk.END)
        widget.config(state="disabled")
    except Exception:
        pass


def open_with_default_app(path: str):
    try:
        if sys.platform.startswith("darwin"):
            subprocess.run(["open", path], check=False)
        elif os.name == "nt":
            os.startfile(path)  # type: ignore
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        messagebox.showinfo("Open file", f"File saved at:\n{path}")


# ---------------------------
# Crypto primitives
# ---------------------------
def shift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)


def unshift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)


def shift_text(s: str, shift: int) -> str:
    return "".join(chr((ord(c) + shift) % 0x110000) for c in s)


def aes_encrypt_bytes(data: bytes):
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return key, iv, ct


def aes_decrypt_bytes(key: bytes, iv: bytes, ct: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


# ---------------------------
# Main Application
# ---------------------------
class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("980x700")
        self.resizable(False, False)

        self.enc_selected = ""
        self.shifted_path = ""
        self.last_encrypted = ""
        self.last_keyfile = ""
        self.dec_selected = ""
        self.key_selected = ""
        self.last_decrypted = ""

        self.loading_running = False
        self._anim_widget = None
        self._anim_label = None
        self._anim_prefix = "Processing"

        self._setup_style()
        self._build_tabs()
        self._log_main("Application started")

    # ---------------- Style ----------------
    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "blue.Horizontal.TProgressbar",
            troughcolor="#e6eefc",
            background="#2F6FE6"
        )

    # ---------------- Tabs ----------------
    def _build_tabs(self):
        self.tab_control = ttk.Notebook(self)
        self.tab_control.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_encrypt = ttk.Frame(self.tab_control)
        self.tab_decrypt = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_encrypt, text="Encrypt")
        self.tab_control.add(self.tab_decrypt, text="Decrypt")

        self._build_encrypt_tab()
        self._build_decrypt_tab()

    # ---------------- Encrypt Tab ----------------
    def _build_encrypt_tab(self):
        f = self.tab_encrypt

        ttk.Label(
            f,
            text="Encryption Mode — Shift then AES",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=6)

        main = ttk.Frame(f)
        main.pack(fill="both", expand=True, padx=10)

        left = ttk.Frame(main)
        left.pack(side="left", fill="y", padx=6)

        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True)

        # Select file
        box1 = ttk.Labelframe(left, text="1) Select File", padding=12)
        box1.pack(fill="x", pady=6)
        self.lbl_enc_file = ttk.Label(box1, text="No file selected", wraplength=300)
        self.lbl_enc_file.pack(side="left")
        ttk.Button(box1, text="Browse", command=self._enc_browse).pack(side="right")

        # Shift
        box2 = ttk.Labelframe(left, text="2) Shift", padding=12)
        box2.pack(fill="x", pady=6)
        self.spin_shift = tk.IntVar(value=4)
        ttk.Spinbox(box2, from_=0, to=255, textvariable=self.spin_shift, width=8).pack()
        ttk.Button(box2, text="Preview Shifted", command=self._preview_shift).pack(fill="x", pady=4)

        # Encrypt
        box3 = ttk.Labelframe(left, text="3) Encrypt", padding=12)
        box3.pack(fill="x", pady=6)
        ttk.Button(box3, text="Encrypt", command=self._encrypt_action).pack(fill="x")

        self.progress_enc = ttk.Progressbar(
            left, style="blue.Horizontal.TProgressbar", length=260
        )
        self.progress_enc.pack(pady=6)
        self.label_prog_enc = ttk.Label(left, text="Idle")
        self.label_prog_enc.pack()

        # Preview
        self.text_preview = scrolledtext.ScrolledText(right, height=20)
        self.text_preview.pack(fill="both", expand=True)

        self.text_log = scrolledtext.ScrolledText(right, height=8, state="disabled")
        self.text_log.pack(fill="x", pady=6)

    # ---------------- Decrypt Tab ----------------
    def _build_decrypt_tab(self):
        f = self.tab_decrypt

        ttk.Label(
            f,
            text="Decryption Mode — Auto shift from header",
            font=("Segoe UI", 16, "bold")
        ).pack(pady=6)

        main = ttk.Frame(f)
        main.pack(fill="both", expand=True, padx=10)

        left = ttk.Frame(main)
        left.pack(side="left", fill="y", padx=6)

        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True)

        box1 = ttk.Labelframe(left, text="Encrypted File", padding=12)
        box1.pack(fill="x", pady=6)
        self.lbl_dec_file = ttk.Label(box1, text="No file")
        self.lbl_dec_file.pack(side="left")
        ttk.Button(box1, text="Browse", command=self._dec_browse).pack(side="right")

        box2 = ttk.Labelframe(left, text="Key File", padding=12)
        box2.pack(fill="x", pady=6)
        self.lbl_key_file = ttk.Label(box2, text="No key")
        self.lbl_key_file.pack(side="left")
        ttk.Button(box2, text="Browse", command=self._key_browse).pack(side="right")

        ttk.Button(left, text="Decrypt", command=self._decrypt_action).pack(fill="x", pady=6)

        self.progress_dec = ttk.Progressbar(
            left, style="blue.Horizontal.TProgressbar", length=260
        )
        self.progress_dec.pack(pady=6)
        self.label_prog_dec = ttk.Label(left, text="Idle")
        self.label_prog_dec.pack()

        self.text_log_dec = scrolledtext.ScrolledText(right, height=20, state="disabled")
        self.text_log_dec.pack(fill="both", expand=True)

    # ---------------- Encrypt logic ----------------
    def _enc_browse(self):
        p = filedialog.askopenfilename()
        if p:
            self.enc_selected = p
            self.lbl_enc_file.config(text=os.path.basename(p))
            self._log_main(f"Selected: {p}")

    def _preview_shift(self):
        if not self.enc_selected:
            messagebox.showwarning("Warning", "No file selected for shift preview")
            return
        shift = self.spin_shift.get() & 0xFF
        with open(self.enc_selected, "rb") as f:
            data = f.read()
        shifted = shift_bytes(data, shift)
        out = os.path.join(SHIFTED_DIR, os.path.basename(self.enc_selected) + ".shifted")
        with open(out, "wb") as wf:
            wf.write(shifted)
        self.shifted_path = out
        self.text_preview.delete("1.0", tk.END)
        self.text_preview.insert(tk.END, f"Shifted file saved:\n{out}")
        self._log_main("Shift preview saved")

    def _encrypt_action(self):
        if not self.enc_selected:
            messagebox.showerror("Error", "Select a file first")
            return

        shift = self.spin_shift.get() & 0xFF

        with open(self.enc_selected, "rb") as f:
            data = f.read()

        shifted = shift_bytes(data, shift)
        key, iv, ct = aes_encrypt_bytes(shifted)

        name = os.path.basename(self.enc_selected)
        enc_path = os.path.join(ENCRYPTED_DIR, name + ".encrypted")

        with open(enc_path, "wb") as ef:
            ef.write(bytes([shift]) + iv + ct)

        key_path = os.path.join(ENCRYPTED_DIR, name + ".key")
        with open(key_path, "w") as kf:
            kf.write(base64.b64encode(key).decode())

        self._stop_loading(self.label_prog_enc)
        self._log_main(f"Encryption completed: {enc_path}")
        messagebox.showinfo("Success", f"File encrypted and saved to:\n{enc_path}")

    # ---------------- Decrypt logic ----------------
    def _dec_browse(self):
        p = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.encrypted")])
        if p:
            self.dec_selected = p
            self.lbl_dec_file.config(text=os.path.basename(p))

    def _key_browse(self):
        p = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
        if p:
            self.key_selected = p
            self.lbl_key_file.config(text=os.path.basename(p))

    def _decrypt_action(self):
        if not self.dec_selected or not self.key_selected:
            messagebox.showerror("Error", "Select encrypted file and key first")
            return

        with open(self.dec_selected, "rb") as f:
            shift = f.read(1)[0]
            iv = f.read(16)
            ct = f.read()
        with open(self.key_selected, "r") as kf:
            key = base64.b64decode(kf.read())

        try:
            plain = aes_decrypt_bytes(key, iv, ct)
            data = unshift_bytes(plain, shift)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            self._log_dec(f"Decryption failed: {e}")
            return

        out = os.path.join(ENCRYPTED_DIR, os.path.basename(self.dec_selected).replace(".encrypted", ""))
        with open(out, "wb") as wf:
            wf.write(data)

        self._stop_loading(self.label_prog_dec)
        self._log_dec(f"Decryption completed: {out}")
        messagebox.showinfo("Success", f"File decrypted and saved to:\n{out}")
        open_with_default_app(out)

    # ---------------- Animation ----------------
    def _start_loading(self, bar, label, text):
        self.loading_running = True
        self._anim_widget = bar
        self._anim_label = label
        self._anim_prefix = text
        self.after(10, self._animate)

    def _animate(self):
        if not self.loading_running:
            return
        v = (self._anim_widget["value"] + 3) % 100
        self._anim_widget["value"] = v
        self._anim_label.config(text=f"{self._anim_prefix} {int(v)}%")
        self.after(20, self._animate)

    def _stop_loading(self, label):
        self.loading_running = False
        label.config(text="Done")

    # ---------------- Logging ----------------
    def _log_main(self, msg):
        gui_log(self.text_log, msg)

    def _log_dec(self, msg):
        gui_log(self.text_log_dec, msg)


# ---------------------------
# Entry
# ---------------------------
if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
