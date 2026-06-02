# PNG Encryption/Decryption Tool

## Overview

A CLI tool to encrypt PNG files into `.enc` files and decrypt them back. Password-based encryption using AES-256-GCM.

## Files

```
encryption/
├── crypto_utils.py    # Key derivation, encrypt/decrypt byte functions
├── encrypt.py         # CLI: reads PNG, outputs .enc
└── decrypt.py         # CLI: reads .enc, outputs PNG
```

## Dependencies

- Python 3.9+
- `cryptography` (pip) — for PBKDF2HMAC, AES-GCM

## Crypto Design

- **Key derivation**: PBKDF2HMAC with SHA-256, 16-byte random salt, 600,000 iterations → 256-bit key
- **Encryption**: AES-256-GCM, 12-byte random nonce per encryption
- **Integrity**: GCM authentication tag (16 bytes) detects wrong passwords and tampering
- **Output format** (`.enc` file): `salt (16) | nonce (12) | GCM tag (16) | ciphertext`

## CLI Interface

```
python encrypt.py <input.png> <password>          # writes input.png.enc
python encrypt.py <input.png> <password> <out.enc> # writes out.enc
python decrypt.py <input.enc> <password>           # writes input.png
python decrypt.py <input.enc> <password> <out.png>  # writes out.png
```

- Default output: encrypt appends `.enc`, decrypt strips `.enc`
- Encrypt validates PNG header (first 8 bytes) before proceeding
- Exit code 0 on success, 1 on failure (message to stderr)

## crypto_utils.py API

```python
def encrypt_bytes(plaintext: bytes, password: str) -> bytes
def decrypt_bytes(encrypted_data: bytes, password: str) -> bytes
```

## Error Handling

- Missing input file → "File not found: ..."
- Wrong password or tampered file → "Decryption failed: invalid password or corrupted file" (caught via GCM tag mismatch)
- Non-PNG input to encrypt → "Not a valid PNG file"

## Testing

- Round-trip test: encrypt a known PNG, decrypt it, verify bytes match
- Wrong password test: verify decryption fails with wrong password
- Corrupted file test: verify decryption fails on truncated/modified `.enc` file
- PNG validation test: verify encrypt rejects non-PNG input
