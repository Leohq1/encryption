import sys
import os

from crypto_utils import encrypt_bytes

PNG_HEADER = b'\x89PNG\r\n\x1a\n'


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print(f"Usage: python encrypt.py <input.png> <password> [output.enc]", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    password = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) == 4 else input_path + '.enc'

    if not os.path.isfile(input_path):
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, 'rb') as f:
        header = f.read(8)
        if header != PNG_HEADER:
            print("Not a valid PNG file", file=sys.stderr)
            sys.exit(1)
        f.seek(0)
        plaintext = f.read()

    encrypted = encrypt_bytes(plaintext, password)

    with open(output_path, 'wb') as f:
        f.write(encrypted)


if __name__ == '__main__':
    main()
