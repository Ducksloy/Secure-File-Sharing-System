import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def unshift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b - shift) % 256 for b in data)

def aes_decrypt_bytes(key: bytes, iv: bytes, ct: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def decrypt_file(enc_path: str, key_path: str, output_dir: str = "decrypted"):
    # Read encrypted file
    with open(enc_path, "rb") as ef:
        header = ef.read(1)
        if len(header) < 1:
            raise ValueError("Encrypted file corrupted (no shift header).")
        shift_val = header[0]
        iv = ef.read(16)
        ct = ef.read()

    # Read AES key
    with open(key_path, "rb") as kf:
        key = base64.b64decode(kf.read())

    # Decrypt AES
    plain_shifted = aes_decrypt_bytes(key, iv, ct)

    # Unshift bytes
    unshifted = unshift_bytes(plain_shifted, shift_val)

    # Save decrypted file
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.basename(enc_path)
    # remove .encrypted extension if present
    if base.endswith(".encrypted"):
        base = base[:-10]
    out_path = os.path.join(output_dir, base + "_decrypted")

    with open(out_path, "wb") as of:
        of.write(unshifted)

    print(f"File decrypted and saved to: {out_path}")
    return out_path
