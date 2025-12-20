import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def unshift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)


def decrypt_file(enc_path: str, key_path: str, output_dir="decrypted"):
    try:
        with open(enc_path, "rb") as ef:
            shift = ef.read(1)[0]
            iv = ef.read(16)
            ct = ef.read()

        with open(key_path, "rb") as kf:
            key = base64.b64decode(kf.read())

        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(ct), AES.block_size)

        data = unshift_bytes(plain, shift)

        os.makedirs(output_dir, exist_ok=True)
        name = os.path.basename(enc_path).replace(".encrypted", "")
        out_path = os.path.join(output_dir, name)

        with open(out_path, "wb") as f:
            f.write(data)

        return out_path

    except Exception as e:
        print("Decryption failed:", e)
        return None
