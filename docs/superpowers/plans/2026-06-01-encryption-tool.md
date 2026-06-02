# PNG Encryption/Decryption Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a password-based PNG encryption/decryption CLI tool using AES-256-GCM.

**Architecture:** Three Python files — `crypto_utils.py` handles all crypto (key derivation via PBKDF2HMAC, AES-256-GCM encrypt/decrypt on bytes), `encrypt.py` and `decrypt.py` are thin CLI wrappers that parse args, read/write files, and call the utils. Tests use pytest and subprocess-based CLI tests.

**Tech Stack:** Python 3.9+, `cryptography` library, `pytest`

---

### Task 1: Set up project and write crypto_utils tests

**Files:**
- Create: `requirements.txt`
- Create: `tests/__init__.py` (empty)
- Create: `tests/test_crypto_utils.py`

- [ ] **Step 1: Create requirements.txt**

```
cryptography>=41.0.0
pytest>=7.0.0
```

- [ ] **Step 2: Create tests directory with __init__.py**

```bash
mkdir -p tests
```

Write `tests/__init__.py` (empty file).

- [ ] **Step 3: Write crypto_utils tests**

```python
import pytest
from crypto_utils import encrypt_bytes, decrypt_bytes


def test_round_trip():
    original = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    password = "swordfish"
    encrypted = encrypt_bytes(original, password)
    decrypted = decrypt_bytes(encrypted, password)
    assert decrypted == original


def test_round_trip_different_data():
    original = b'\x89PNG\r\n\x1a\n' + bytes(range(256))
    password = "another-password"
    encrypted = encrypt_bytes(original, password)
    decrypted = decrypt_bytes(encrypted, password)
    assert decrypted == original


def test_wrong_password_fails():
    original = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    encrypted = encrypt_bytes(original, "correct-password")
    with pytest.raises(Exception):
        decrypt_bytes(encrypted, "wrong-password")


def test_corrupted_file_fails():
    original = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    encrypted = encrypt_bytes(original, "password")
    corrupted = encrypted[:50] + bytes([encrypted[50] ^ 0xFF]) + encrypted[51:]
    with pytest.raises(Exception):
        decrypt_bytes(corrupted, "password")


def test_empty_png_round_trip():
    original = b'\x89PNG\r\n\x1a\n'  # minimal valid PNG header
    password = "password"
    encrypted = encrypt_bytes(original, password)
    decrypted = decrypt_bytes(encrypted, password)
    assert decrypted == original
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
pip install -r requirements.txt
pytest tests/test_crypto_utils.py -v
```

Expected: all 5 tests FAIL with `ModuleNotFoundError: No module named 'crypto_utils'`

- [ ] **Step 5: Commit**

```bash
git add requirements.txt tests/
git commit -m "test: add failing crypto_utils tests"
```

---

### Task 2: Implement crypto_utils.py

**Files:**
- Create: `crypto_utils.py`

- [ ] **Step 1: Write crypto_utils.py**

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32
ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LENGTH)
    key = _derive_key(password, salt)
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:SALT_LENGTH]
    nonce = encrypted_data[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
    ciphertext = encrypted_data[SALT_LENGTH + NONCE_LENGTH:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed: invalid password or corrupted file")
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
pytest tests/test_crypto_utils.py -v
```

Expected: 5 passed

- [ ] **Step 3: Commit**

```bash
git add crypto_utils.py
git commit -m "feat: implement encrypt/decrypt with AES-256-GCM"
```

---

### Task 3: Implement encrypt.py

**Files:**
- Create: `tests/test_encrypt.py`
- Create: `encrypt.py`

- [ ] **Step 1: Write encrypt CLI tests**

```python
import subprocess
import sys
import os
import tempfile


def test_encrypt_creates_enc_file():
    png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(png_data)
        png_path = f.name

    enc_path = png_path + '.enc'

    try:
        result = subprocess.run(
            [sys.executable, 'encrypt.py', png_path, 'testpass'],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert os.path.exists(enc_path)
        assert os.path.getsize(enc_path) > 0
    finally:
        os.unlink(png_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def test_encrypt_custom_output_path():
    png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(png_data)
        png_path = f.name

    enc_path = png_path.replace('.png', '.custom.enc')

    try:
        result = subprocess.run(
            [sys.executable, 'encrypt.py', png_path, 'testpass', enc_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert os.path.exists(enc_path)
    finally:
        os.unlink(png_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def test_encrypt_rejects_non_png():
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b'this is not a png file')
        txt_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, 'encrypt.py', txt_path, 'testpass'],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert 'Not a valid PNG file' in result.stderr
    finally:
        os.unlink(txt_path)


def test_encrypt_file_not_found():
    result = subprocess.run(
        [sys.executable, 'encrypt.py', 'nonexistent.png', 'testpass'],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert 'File not found' in result.stderr
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_encrypt.py -v
```

Expected: FAIL

- [ ] **Step 3: Write encrypt.py**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_encrypt.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add encrypt.py tests/test_encrypt.py
git commit -m "feat: add encrypt CLI"
```

---

### Task 4: Implement decrypt.py

**Files:**
- Create: `tests/test_decrypt.py`
- Create: `decrypt.py`

- [ ] **Step 1: Write decrypt CLI tests**

```python
import subprocess
import sys
import os
import tempfile


def test_decrypt_round_trip():
    png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 200
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(png_data)
        png_path = f.name

    enc_path = png_path + '.enc'

    try:
        result = subprocess.run(
            [sys.executable, 'encrypt.py', png_path, 'mypassword'],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

        result = subprocess.run(
            [sys.executable, 'decrypt.py', enc_path, 'mypassword'],
            capture_output=True, text=True,
        )
        assert result.returncode == 0

        decrypted_path = png_path
        with open(decrypted_path, 'rb') as f:
            decrypted = f.read()
        assert decrypted == png_data
    finally:
        os.unlink(png_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def test_decrypt_custom_output_path():
    png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 200
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(png_data)
        png_path = f.name

    enc_path = png_path + '.enc'
    out_path = png_path.replace('.png', '.out.png')

    try:
        subprocess.run(
            [sys.executable, 'encrypt.py', png_path, 'mypassword'],
            capture_output=True, text=True,
        )
        result = subprocess.run(
            [sys.executable, 'decrypt.py', enc_path, 'mypassword', out_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        with open(out_path, 'rb') as f:
            assert f.read()[:8] == b'\x89PNG\r\n\x1a\n'
    finally:
        os.unlink(png_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


def test_decrypt_wrong_password():
    png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        f.write(png_data)
        png_path = f.name

    enc_path = png_path + '.enc'

    try:
        subprocess.run(
            [sys.executable, 'encrypt.py', png_path, 'correct'],
            capture_output=True, text=True,
        )
        result = subprocess.run(
            [sys.executable, 'decrypt.py', enc_path, 'wrong'],
            capture_output=True, text=True,
        )
        assert result.returncode == 1
        assert 'Decryption failed' in result.stderr
    finally:
        os.unlink(png_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def test_decrypt_file_not_found():
    result = subprocess.run(
        [sys.executable, 'decrypt.py', 'nonexistent.enc', 'testpass'],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert 'File not found' in result.stderr
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_decrypt.py -v
```

Expected: FAIL

- [ ] **Step 3: Write decrypt.py**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_decrypt.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add decrypt.py tests/test_decrypt.py
git commit -m "feat: add decrypt CLI"
```

---

### Task 5: Run full test suite

- [ ] **Step 1: Run all tests**

```bash
pytest tests/ -v
```

Expected: 13 passed (5 crypto_utils + 4 encrypt + 4 decrypt)

- [ ] **Step 2: Manual test with a real PNG (optional)**

```bash
python encrypt.py test_image.png password123
python decrypt.py test_image.png.enc password123 test_decrypted.png
# Verify test_decrypted.png opens correctly and matches original
```
