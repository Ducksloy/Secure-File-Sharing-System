import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def shift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)


def encrypt_file(input_path: str, shift: int, key_path: str = None, output_dir="encrypted"):
    try:
        shift &= 0xFF

        with open(input_path, "rb") as f:
            data = f.read()

        shifted = shift_bytes(data, shift)

        if key_path and os.path.isfile(key_path):
            with open(key_path, "rb") as kf:
                key = base64.b64decode(kf.read())
        else:
            key = get_random_bytes(32)
            os.makedirs(output_dir, exist_ok=True)
            key_path = key_path or os.path.join(output_dir, os.path.basename(input_path) + ".key")
            with open(key_path, "wb") as kf:
                kf.write(base64.b64encode(key))

        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(shifted, AES.block_size))

        os.makedirs(output_dir, exist_ok=True)
        enc_path = os.path.join(output_dir, os.path.basename(input_path) + ".encrypted")

        with open(enc_path, "wb") as ef:
            ef.write(bytes([shift]) + iv + ct)

        return enc_path, key_path

    except Exception as e:
        print("Encryption failed:", e)
        return None, None
