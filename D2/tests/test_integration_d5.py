"""D5 - Integration Tests

Verify the complete encryption, digital signature, signature verification,
and decryption workflow.
"""

import json
import pytest

from src.decryption import decrypt_file
from src.digital_signature import generate_signing_key_pair
from src.encryption import encrypt_file
from src.key_management import generate_key_pair


@pytest.fixture
def integration_data(tmp_path):
    """Prepare a complete D5 environment with two recipients and one trusted sender."""
    # Generate recipient keys
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()
    eve_private, _ = generate_key_pair()

    # Generate sender signing keys
    signer_private, signer_public = generate_signing_key_pair()

    # Create original document
    original = tmp_path / "confidential.txt"
    original.write_bytes(
        b"Secure Digital Document Vault - D5 Integration Test"
    )

    # Encrypt and sign document
    encrypted = tmp_path / "document.vault"
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public],
        signer_private,
        signer_public,
    )

    return {
        "tmp_path": tmp_path,
        "original": original,
        "encrypted": encrypted,
        "alice_private": alice_private,
        "bob_private": bob_private,
        "eve_private": eve_private,
        "signer_public": signer_public,
    }


def test_complete_d5_workflow(integration_data):
    """Verify the complete encryption-signing-decryption process."""
    data = integration_data
    output = data["tmp_path"] / "recovered.txt"

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output,
        data["signer_public"],
    )

    assert result is True
    assert output.exists()
    assert output.read_bytes() == data["original"].read_bytes()


def test_multiple_authorized_recipients(integration_data):
    """Verify that Alice and Bob can recover the same document."""
    data = integration_data
    alice_output = data["tmp_path"] / "alice.txt"
    bob_output = data["tmp_path"] / "bob.txt"

    alice_result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        alice_output,
        data["signer_public"],
    )
    bob_result = decrypt_file(
        data["encrypted"],
        data["bob_private"],
        bob_output,
        data["signer_public"],
    )

    assert alice_result is True
    assert bob_result is True
    assert alice_output.read_bytes() == bob_output.read_bytes()
    assert alice_output.read_bytes() == data["original"].read_bytes()


def test_unauthorized_recipient_rejected(integration_data):
    """Verify that an unauthorized recipient cannot decrypt."""
    data = integration_data
    output = data["tmp_path"] / "eve.txt"

    result = decrypt_file(
        data["encrypted"],
        data["eve_private"],
        output,
        data["signer_public"],
    )

    assert result is False
    assert not output.exists()


def test_tampered_container_rejected(integration_data):
    """Verify that modifying signed metadata invalidates the signature."""
    data = integration_data

    with data["encrypted"].open("r", encoding="utf-8") as file:
        container = json.load(file)

    container["metadata"]["filename"] = "modified.txt"
    modified = data["tmp_path"] / "modified.vault"

    with modified.open("w", encoding="utf-8") as file:
        json.dump(container, file)

    output = data["tmp_path"] / "modified_output.txt"
    result = decrypt_file(
        modified,
        data["alice_private"],
        output,
        data["signer_public"],
    )

    assert result is False
    assert not output.exists()


def test_untrusted_signer_rejected(integration_data):
    """Verify that a different sender's public key is rejected."""
    data = integration_data
    _, wrong_public = generate_signing_key_pair()
    output = data["tmp_path"] / "untrusted.txt"

    result = decrypt_file(
        data["encrypted"],
        data["alice_private"],
        output,
        wrong_public,
    )

    assert result is False
    assert not output.exists()