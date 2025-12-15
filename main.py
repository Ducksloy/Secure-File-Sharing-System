import sys
import os
from encrypt import encrypt_file
from decrypt import decrypt_file
from generate_key import generate_key


def usage():
    print("""
Usage:
  python main.py generate-key <output.key>
  python main.py encrypt <inputfile> <shift> [keyfile]
  python main.py decrypt <encryptedfile> <keyfile>
""")


def main():
    if len(sys.argv) < 2:
        usage()
        exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "generate-key":
        if len(sys.argv) != 3:
            usage()
            exit(1)
        generate_key(sys.argv[2])

    elif cmd == "encrypt":
        if len(sys.argv) < 4:
            usage()
            exit(1)

        input_file = sys.argv[2]
        if not os.path.isfile(input_file):
            print("❌ Input file not found.")
            exit(1)

        try:
            shift = int(sys.argv[3])
        except ValueError:
            print("❌ Shift must be an integer.")
            exit(1)

        keyfile = sys.argv[4] if len(sys.argv) > 4 else None
        encrypt_file(input_file, shift, keyfile)

    elif cmd == "decrypt":
        if len(sys.argv) != 4:
            usage()
            exit(1)

        enc_file = sys.argv[2]
        key_file = sys.argv[3]

        if not os.path.isfile(enc_file) or not os.path.isfile(key_file):
            print("❌ Encrypted file or key file not found.")
            exit(1)

        decrypt_file(enc_file, key_file)

    else:
        usage()


if __name__ == "__main__":
    main()
