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
    with pytest.raises(ValueError):
        decrypt_bytes(encrypted, "wrong-password")


def test_corrupted_file_fails():
    original = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100
    encrypted = encrypt_bytes(original, "password")
    corrupted = encrypted[:50] + bytes([encrypted[50] ^ 0xFF]) + encrypted[51:]
    with pytest.raises(ValueError):
        decrypt_bytes(corrupted, "password")


def test_empty_png_round_trip():
    original = b'\x89PNG\r\n\x1a\n'  # minimal valid PNG header
    password = "password"
    encrypted = encrypt_bytes(original, password)
    decrypted = decrypt_bytes(encrypted, password)
    assert decrypted == original
