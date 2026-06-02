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
