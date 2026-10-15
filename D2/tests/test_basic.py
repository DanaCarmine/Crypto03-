import os

from src.encryption import encrypt_file
from src.decryption import decrypt_file


def test_encrypt_decrypt(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("Hello, this is a test!", encoding="utf-8")

    encrypted = tmp_path / "encrypted.vault"
    key = tmp_path / "secret.key"
    decrypted = tmp_path / "decrypted.txt"

    encrypt_file(original, encrypted, key)
    result = decrypt_file(encrypted, key, decrypted)

    assert result is True
    assert original.read_bytes() == decrypted.read_bytes()


def test_wrong_key(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text(
        "This is confidential information.",
        encoding="utf-8"
    )

    encrypted = tmp_path / "encrypted.vault"
    correct_key = tmp_path / "correct.key"
    wrong_key = tmp_path / "wrong.key"
    decrypted = tmp_path / "decrypted.txt"

    encrypt_file(original, encrypted, correct_key)

    wrong_key.write_bytes(os.urandom(32))

    result = decrypt_file(encrypted, wrong_key, decrypted)

    assert result is False
    assert not decrypted.exists()