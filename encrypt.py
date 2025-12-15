import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def shift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)


def encrypt_file(input_path: str, shift: int, key_path: str = None, output_dir="encrypted"):
    try:
        shift = shift & 0xFF

        # Read input file
        with open(input_path, "rb") as f:
            data = f.read()

        shifted = shift_bytes(data, shift)

        # Load or generate AES key
        if key_path and os.path.isfile(key_path):
            with open(key_path, "rb") as kf:
                key = base64.b64decode(kf.read())
            if len(key) not in (16, 24, 32):
                raise ValueError("Invalid AES key length.")
        else:
            key = get_random_bytes(32)
            if not key_path:
                key_path = os.path.join(output_dir, os.path.basename(input_path) + ".key")
            with open(key_path, "wb") as kf:
                kf.write(base64.b64encode(key))
            print(f"✔ New AES key saved to: {key_path}")

        # AES encryption
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(shifted, AES.block_size))

        # Save encrypted file
        os.makedirs(output_dir, exist_ok=True)
        enc_file = os.path.join(output_dir, os.path.basename(input_path) + ".encrypted")

        with open(enc_file, "wb") as ef:
            ef.write(bytes([shift]))   # 1 byte shift
            ef.write(iv)               # 16 bytes IV
            ef.write(ciphertext)       # ciphertext

        print(f"✔ File encrypted: {enc_file}")
        return enc_file, key_path

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return None, None
