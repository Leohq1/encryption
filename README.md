# PNG Encryption Tool

Encrypt and decrypt PNG files using AES-256-GCM with a password.

## Prerequisites

- Python 3.9+

## Install

```bash
pip install -r requirements.txt
```

## Usage

**Encrypt a PNG:**

```bash
python encrypt.py image.png mypassword
```

Creates `image.png.enc`.

**Encrypt with a custom output path:**

```bash
python encrypt.py image.png mypassword secret.enc
```

**Decrypt:**

```bash
python decrypt.py image.png.enc mypassword
```

Restores the original `image.png`.

**Decrypt to a custom path:**

```bash
python decrypt.py image.png.enc mypassword restored.png
```

## How it works

- Password is stretched into a 256-bit key using PBKDF2 (600,000 iterations of SHA-256)
- Encryption uses AES-256-GCM, which provides both confidentiality and tamper detection
- If the password is wrong or the file was modified, decryption fails with an error

## Run tests

```bash
pytest tests/ -v
```
