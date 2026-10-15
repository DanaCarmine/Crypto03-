import json

from src.encryption import encrypt_file
from src.decryption import decrypt_file


def test_modified_ciphertext(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("Confidential document", encoding="utf-8")

    encrypted = tmp_path / "encrypted.vault"
    key = tmp_path / "secret.key"
    decrypted = tmp_path / "decrypted.txt"

    encrypt_file(original, encrypted, key)

    # Modify the encrypted content
    with open(encrypted, "r", encoding="utf-8") as file:
        container = json.load(file)

    ciphertext = container["ciphertext"]
    container["ciphertext"] = (
        ("0" if ciphertext[0] != "0" else "1") + ciphertext[1:]
    )

    with open(encrypted, "w", encoding="utf-8") as file:
        json.dump(container, file)

    result = decrypt_file(encrypted, key, decrypted)

    print("Modified ciphertext result:", result)

    assert result is False
    assert not decrypted.exists()


def test_modified_metadata(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("Protected metadata test", encoding="utf-8")

    encrypted = tmp_path / "encrypted.vault"
    key = tmp_path / "secret.key"
    decrypted = tmp_path / "decrypted.txt"

    encrypt_file(original, encrypted, key)

    # Modify authenticated metadata
    with open(encrypted, "r", encoding="utf-8") as file:
        container = json.load(file)

    container["metadata"]["filename"] = "modified.txt"

    with open(encrypted, "w", encoding="utf-8") as file:
        json.dump(container, file)

    result = decrypt_file(encrypted, key, decrypted)

    print("Modified metadata result:", result)

    assert result is False
    assert not decrypted.exists()
    