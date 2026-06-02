import sys
import os

from crypto_utils import decrypt_bytes


def main():
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print(f"Usage: python decrypt.py <input.enc> <password> [output.png]", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    password = sys.argv[2]

    if len(sys.argv) == 4:
        output_path = sys.argv[3]
    else:
        output_path = input_path[:-4] if input_path.endswith('.enc') else input_path

    if not os.path.isfile(input_path):
        print(f"File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        decrypted = decrypt_bytes(encrypted_data, password)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(decrypted)


if __name__ == '__main__':
    main()
