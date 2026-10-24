import json

import pytest

from ecies.keys import PrivateKey

from src.encryption import encrypt_file
from src.key_management import decrypt_file_key, get_key_fingerprint
from src.container import build_aad, load_container

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@pytest.fixture
def encryption_data(tmp_path):
    """Create a test document and two ECIES key pairs."""

    file_path = tmp_path / "document.txt"
    output_path = tmp_path / "document.vault"

    original_content = b"Confidential document for D3 testing."

    file_path.write_bytes(original_content)

    alice = PrivateKey("secp256k1")
    bob = PrivateKey("secp256k1")

    alice_public_key = alice.public_key.to_bytes(True)
    bob_public_key = bob.public_key.to_bytes(True)

    return {
        "file_path": file_path,
        "output_path": output_path,
        "original_content": original_content,
        "alice": alice,
        "bob": bob,
        "alice_public_key": alice_public_key,
        "bob_public_key": bob_public_key
    }


def test_encrypt_file_creates_vault(encryption_data):
    """Verify that encryption creates a valid vault file."""

    data = encryption_data

    encrypt_file(
        data["file_path"],
        data["output_path"],
        [data["alice_public_key"], data["bob_public_key"]]
    )

    assert data["output_path"].exists()

    container = load_container(data["output_path"])

    assert container["metadata"]["algorithm"] == "AES-256-GCM"
    assert container["metadata"]["key_encryption"] == "ECIES-secp256k1"
    assert container["metadata"]["version"] == "3.0"


def test_encrypt_file_has_two_recipients(encryption_data):
    """Verify that both recipients are included in the vault."""

    data = encryption_data

    encrypt_file(
        data["file_path"],
        data["output_path"],
        [data["alice_public_key"], data["bob_public_key"]]
    )

    container = load_container(data["output_path"])

    assert len(container["recipients"]) == 2

    recipient_ids = [
        recipient["id"]
        for recipient in container["recipients"]
    ]

    assert get_key_fingerprint(data["alice_public_key"]) in recipient_ids
    assert get_key_fingerprint(data["bob_public_key"]) in recipient_ids


def test_both_recipients_can_recover_document(encryption_data):
    """Verify that both recipients can recover the original document."""

    data = encryption_data

    encrypt_file(
        data["file_path"],
        data["output_path"],
        [data["alice_public_key"], data["bob_public_key"]]
    )

    container = load_container(data["output_path"])

    aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])

    recipients = {
        recipient["id"]: recipient["encrypted_key"]
        for recipient in container["recipients"]
    }

    for person in ("alice", "bob"):

        public_key = data[f"{person}_public_key"]
        private_key = data[person].secret

        fingerprint = get_key_fingerprint(public_key)

        encrypted_key = bytes.fromhex(recipients[fingerprint])

        aes_key = decrypt_file_key(
            private_key,
            encrypted_key
        )

        plaintext = AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            aad
        )

        assert plaintext == data["original_content"]


def test_reject_duplicate_recipients(encryption_data):
    """Verify that duplicate recipients are rejected."""

    data = encryption_data

    with pytest.raises(ValueError):
        encrypt_file(
            data["file_path"],
            data["output_path"],
            [
                data["alice_public_key"],
                data["alice_public_key"]
            ]
        )


def test_reject_single_recipient(encryption_data):
    """Verify that at least two recipients are required."""

    data = encryption_data

    with pytest.raises(ValueError):
        encrypt_file(
            data["file_path"],
            data["output_path"],
            [data["alice_public_key"]]
        )


def test_no_plaintext_aes_key_file(encryption_data):
    """Verify that encryption does not create an unprotected AES key file."""

    data = encryption_data

    encrypt_file(
        data["file_path"],
        data["output_path"],
        [data["alice_public_key"], data["bob_public_key"]]
    )

    key_files = list(data["output_path"].parent.glob("*.key"))

    assert key_files == []