import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def unshift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)


def decrypt_file(enc_path: str, key_path: str, output_dir="decrypted"):
    try:
        # Read encrypted file
        with open(enc_path, "rb") as ef:
            shift_byte = ef.read(1)
            if not shift_byte:
                raise ValueError("Missing shift byte.")

            shift = shift_byte[0]
            iv = ef.read(16)
            ct = ef.read()

        # Load AES key
        with open(key_path, "rb") as kf:
            key = base64.b64decode(kf.read())
        if len(key) not in (16, 24, 32):
            raise ValueError("Invalid AES key length.")

        # AES decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_shifted = unpad(cipher.decrypt(ct), AES.block_size)

        # Reverse shift
        plain = unshift_bytes(plain_shifted, shift)

        # Save output
        os.makedirs(output_dir, exist_ok=True)
        base = os.path.basename(enc_path)
        if base.endswith(".encrypted"):
            base = base[:-10]

        out_file = os.path.join(output_dir, base)
        with open(out_file, "wb") as f:
            f.write(plain)

        print(f"✔ File decrypted: {out_file}")
        return out_file

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        return None
