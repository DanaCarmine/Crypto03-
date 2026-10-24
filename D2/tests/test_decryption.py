
import json

import pytest

from src.encryption import encrypt_file
from src.decryption import decrypt_file
from src.key_management import generate_key_pair


@pytest.fixture
def vault_data(tmp_path):
    """
    Create an encrypted document for two authorized recipients.
    """

    original = tmp_path / "original.txt"
    original.write_text(
        "Confidential document for D3 testing.",
        encoding="utf-8"
    )

    encrypted = tmp_path / "document.vault"

    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    wrong_private, wrong_public = generate_key_pair()

    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    return {
        "original": original,
        "encrypted": encrypted,
        "alice_private": alice_private,
        "bob_private": bob_private,
        "wrong_private": wrong_private,
        "tmp_path": tmp_path
    }


def test_alice_can_decrypt(vault_data):
    """
    Alice can decrypt the document with her private key.
    """

    data = vault_data
    output = data["tmp_path"] / "alice_output.txt"

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output
    )

    assert result is True
    assert output.read_bytes() == data["original"].read_bytes()


def test_bob_can_decrypt(vault_data):
    """
    Bob can decrypt the same document with his private key.
    """

    data = vault_data
    output = data["tmp_path"] / "bob_output.txt"

    result = decrypt_file(
        data["encrypted"],
        data["bob_private"],
        output
    )

    assert result is True
    assert output.read_bytes() == data["original"].read_bytes()


def test_unauthorized_recipient(vault_data):
    """
    An unauthorized recipient cannot decrypt the document.
    """

    data = vault_data
    output = data["tmp_path"] / "unauthorized.txt"

    result = decrypt_file(
        data["encrypted"],
        data["wrong_private"],
        output
    )

    assert result is False
    assert not output.exists()


def test_modified_metadata(vault_data):
    """
    Modified metadata must cause authentication failure.
    """

    data = vault_data
    output = data["tmp_path"] / "modified_output.txt"

    with open(data["encrypted"], "r", encoding="utf-8") as file:
        container = json.load(file)

    container["metadata"]["filename"] = "modified.txt"

    with open(data["encrypted"], "w", encoding="utf-8") as file:
        json.dump(container, file)

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output
    )

    assert result is False
    assert not output.exists()


def test_modified_ciphertext(vault_data):
    """
    Modified ciphertext must cause authentication failure.
    """

    data = vault_data
    output = data["tmp_path"] / "tampered_output.txt"

    with open(data["encrypted"], "r", encoding="utf-8") as file:
        container = json.load(file)

    ciphertext = bytearray.fromhex(container["ciphertext"])
    ciphertext[0] ^= 1

    container["ciphertext"] = ciphertext.hex()

    with open(data["encrypted"], "w", encoding="utf-8") as file:
        json.dump(container, file)

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output
    )

    assert result is False
    assert not output.exists()


def test_invalid_private_key(vault_data):
    """
    An invalid private key must be rejected.
    """

    data = vault_data
    output = data["tmp_path"] / "invalid_output.txt"

    result = decrypt_file(
        data["encrypted"],
        b"invalid_key",
        output
    )

    assert result is False
    assert not output.exists()


def test_existing_output_not_overwritten(vault_data):
    """
    Decryption must not overwrite an existing output file.
    """

    data = vault_data
    output = data["tmp_path"] / "existing.txt"
    output.write_text("Existing content", encoding="utf-8")

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output
    )

    assert result is False
    assert output.read_text(encoding="utf-8") == "Existing content"
def test_modified_recipient_key(vault_data):
    """
    Verify that modifying a recipient's encrypted key
    causes the complete decryption process to fail.
    """

    data = vault_data
    output = data["tmp_path"] / "modified_recipient.txt"

    with open(data["encrypted"], "r", encoding="utf-8") as file:
        container = json.load(file)

    # Modify Bob's encrypted AES key
    encrypted_key = bytearray.fromhex(
        container["recipients"][1]["encrypted_key"]
    )

    encrypted_key[0] ^= 1

    container["recipients"][1]["encrypted_key"] = encrypted_key.hex()

    with open(data["encrypted"], "w", encoding="utf-8") as file:
        json.dump(container, file)

    # Alice should not be able to decrypt the modified container
    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output
    )

    assert result is False
    assert not output.exists()
