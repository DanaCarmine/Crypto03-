
import json

import pytest

from src.key_management import generate_key_pair
from src.digital_signature import generate_signing_key_pair
from src.encryption import encrypt_file, encrypt_file_legacy
from src.decryption import decrypt_file


@pytest.fixture
def vault_data(tmp_path):
    """Create a valid signed D5 container for two recipients."""

    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    signer_private, signer_public = generate_signing_key_pair()

    original = tmp_path / "original.txt"
    original.write_bytes(b"Confidential document for Alice and Bob.")

    encrypted = tmp_path / "document.vault"

    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public],
        signer_private,
        signer_public
    )

    return {
        "tmp_path": tmp_path,
        "original": original,
        "encrypted": encrypted,
        "alice_private": alice_private,
        "bob_private": bob_private,
        "alice_public": alice_public,
        "bob_public": bob_public,
        "signer_private": signer_private,
        "signer_public": signer_public
    }


def modify_container(vault_data, change):
    """Modify a container and save it as a separate file."""

    with vault_data["encrypted"].open("r", encoding="utf-8") as file:
        container = json.load(file)

    change(container)

    modified = vault_data["tmp_path"] / "modified.vault"

    with modified.open("w", encoding="utf-8") as file:
        json.dump(container, file)

    return modified


def test_alice_can_decrypt_signed_file(vault_data):
    output = vault_data["tmp_path"] / "alice.txt"

    result = decrypt_file(
        vault_data["encrypted"],
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is True
    assert output.read_bytes() == vault_data["original"].read_bytes()


def test_bob_can_decrypt_signed_file(vault_data):
    output = vault_data["tmp_path"] / "bob.txt"

    result = decrypt_file(
        vault_data["encrypted"],
        vault_data["bob_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is True
    assert output.read_bytes() == vault_data["original"].read_bytes()


def test_wrong_signer_public_key(vault_data):
    _, wrong_public = generate_signing_key_pair()
    output = vault_data["tmp_path"] / "wrong_signer.txt"

    result = decrypt_file(
        vault_data["encrypted"],
        vault_data["alice_private"],
        output,
        wrong_public
    )

    assert result is False
    assert not output.exists()


def test_modified_signature(vault_data):
    def change(container):
        signature = container["signature"]
        container["signature"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )

    modified = modify_container(vault_data, change)
    output = vault_data["tmp_path"] / "invalid_signature.txt"

    result = decrypt_file(
        modified,
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is False
    assert not output.exists()


def test_modified_ciphertext(vault_data):
    def change(container):
        ciphertext = container["ciphertext"]
        container["ciphertext"] = (
            ("0" if ciphertext[0] != "0" else "1") + ciphertext[1:]
        )

    modified = modify_container(vault_data, change)
    output = vault_data["tmp_path"] / "modified_ciphertext.txt"

    result = decrypt_file(
        modified,
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is False
    assert not output.exists()


def test_modified_metadata(vault_data):
    def change(container):
        container["metadata"]["filename"] = "another_file.txt"

    modified = modify_container(vault_data, change)
    output = vault_data["tmp_path"] / "modified_metadata.txt"

    result = decrypt_file(
        modified,
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is False
    assert not output.exists()


def test_missing_signature(vault_data):
    def change(container):
        del container["signature"]

    modified = modify_container(vault_data, change)
    output = vault_data["tmp_path"] / "missing_signature.txt"

    result = decrypt_file(
        modified,
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is False
    assert not output.exists()


def test_unsigned_d3_container_rejected(vault_data):
    legacy = vault_data["tmp_path"] / "legacy.vault"

    encrypt_file_legacy(
        vault_data["original"],
        legacy,
        [vault_data["alice_public"], vault_data["bob_public"]]
    )

    output = vault_data["tmp_path"] / "legacy_output.txt"

    result = decrypt_file(
        legacy,
        vault_data["alice_private"],
        output,
        vault_data["signer_public"]
    )

    assert result is False
    assert not output.exists()
