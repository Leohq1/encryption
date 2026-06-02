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
