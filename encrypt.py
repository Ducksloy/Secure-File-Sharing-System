import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def shift_bytes(data: bytes, shift: int) -> bytes:
    return bytes((b + shift) % 256 for b in data)

def aes_encrypt_bytes(plain_bytes: bytes, key: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return iv, ct

def encrypt_file(input_path: str, shift: int, key_path: str = None, output_dir: str = "encrypted"):
    # Read original bytes
    with open(input_path, "rb") as f:
        data = f.read()

    # Apply shift
    shifted = shift_bytes(data, shift & 0xFF)

    # Load or generate AES key
    if key_path and os.path.isfile(key_path):
        with open(key_path, "rb") as kf:
            key = base64.b64decode(kf.read())
    else:
        key = get_random_bytes(32)
        # Save key to key_path if specified
        if key_path:
            with open(key_path, "wb") as kf:
                kf.write(base64.b64encode(key))
            print(f"Generated new AES key saved to: {key_path}")

    # Encrypt with AES
    iv, ciphertext = aes_encrypt_bytes(shifted, key)

    # Prepare output paths
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.basename(input_path)
    enc_file = os.path.join(output_dir, base + ".encrypted")
    if key_path is None:
        key_path = os.path.join(output_dir, base + ".key")

    # Save encrypted file format: [1 byte shift][16 bytes IV][ciphertext]
    with open(enc_file, "wb") as ef:
        ef.write(bytes([shift & 0xFF]))
        ef.write(iv)
        ef.write(ciphertext)

    # Save key file if it was newly generated and no key_path provided
    if not os.path.isfile(key_path):
        with open(key_path, "wb") as kf:
            kf.write(base64.b64encode(key))

    print(f"File encrypted and saved to: {enc_file}")
    print(f"AES key saved to: {key_path}")

    return enc_file, key_path
