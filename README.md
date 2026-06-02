# PNG Encryption Tool

Encrypt and decrypt PNG files using AES-256-GCM with a password. Perfect for sending sensitive images securely — your friend only needs the password to decrypt.

---

## How to use

### Step 1: Clone the repository

```bash
git clone https://github.com/Leohq1/encryption.git
cd encryption
```

### Step 2: Install the dependency

This project needs Python 3.9 or newer. Check your version:

```bash
python --version
```

If you see 3.9 or higher, install the one dependency:

```bash
pip install -r requirements.txt
```

### Step 3: Encrypt a PNG

Put your PNG file in the project folder, then run:

```bash
python encrypt.py image.png mypassword
```

This creates `image.png.enc` — your encrypted file. The original PNG is untouched.

To give the output a custom name:

```bash
python encrypt.py image.png mypassword secret.enc
```

### Step 4: Decrypt a file

Send the `.enc` file and the password to your friend. They run:

```bash
python decrypt.py image.png.enc mypassword
```

This restores the original `image.png`.

To save the decrypted file to a specific path:

```bash
python decrypt.py image.png.enc mypassword restored.png
```

---

## Example session

```
> python encrypt.py vacation.png swordfish
  (no output — success)

> python decrypt.py vacation.png.enc swordfish
  (no output — vacation.png restored)

> python decrypt.py vacation.png.enc wrongpassword
  Decryption failed: invalid password or corrupted file
```

---

## If something goes wrong

| Problem | What to do |
|---------|-------------|
| "File not found: ..." | Check the file path is correct. It must be in the project folder or you need to give the full path. |
| "Not a valid PNG file" | The input must be a real PNG. Other image formats (JPG, GIF, etc.) won't work. |
| "Decryption failed: invalid password or corrupted file" | Either the password is wrong, or the `.enc` file was modified or damaged. |
| "No module named 'cryptography'" | Run `pip install -r requirements.txt` from Step 2. |
| Command not found: python | Use `python3` instead of `python`, or install Python from https://python.org. |

---

## How it works

1. A 16-byte random **salt** is generated and used with your password to derive a 256-bit key (PBKDF2 with SHA-256, 600,000 iterations).
2. A 12-byte random **nonce** is generated for each encryption.
3. The file is encrypted with **AES-256-GCM**, which provides both confidentiality and integrity protection.
4. The output `.enc` file contains: salt (16 bytes) + nonce (12 bytes) + encrypted data (with GCM tag).

On decryption, the salt and nonce are read from the file header, the key is re-derived from the password, and GCM verifies the data hasn't been tampered with. Wrong password? GCM tag check fails and decryption is refused.

## Run tests

```bash
pytest tests/ -v
```
