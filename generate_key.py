import os
import base64
from Crypto.Random import get_random_bytes

def generate_key(out_path: str):
    if os.path.exists(out_path):
        print("❌ Key file already exists.")
        return

    key = get_random_bytes(32)  # AES-256
    with open(out_path, "wb") as f:
        f.write(base64.b64encode(key))

    print(f"✔ AES-256 key generated and saved to: {out_path}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python generate_key.py <output.key>")
        exit(1)

    generate_key(sys.argv[1])
