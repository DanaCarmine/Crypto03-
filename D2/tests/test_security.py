import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption import encrypt_file
from src.key_management import (
    generate_key_pair,
    get_key_fingerprint,
    decrypt_file_key
)
from src.container import (
    load_container,
    build_aad
)


def recover_aes_key(container, private_key, public_key):
    """
    Recover the AES key belonging to an authorized recipient.
    """

    recipient_id = get_key_fingerprint(public_key)

    recipient = next(
        item
        for item in container["recipients"]
        if item["id"] == recipient_id
    )

    encrypted_key = bytes.fromhex(recipient["encrypted_key"])

    return decrypt_file_key(private_key, encrypted_key)


def test_modified_ciphertext(tmp_path):
    """
    Verify that AES-GCM rejects modified ciphertext.
    """

    # 1. Create the original document
    original = tmp_path / "original.txt"
    original.write_text(
        "Confidential document",
        encoding="utf-8"
    )

    encrypted = tmp_path / "encrypted.vault"

    # 2. Generate two authorized recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # 3. Encrypt the document
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # 4. Load the container
    container = load_container(encrypted)

    # 5. Recover Alice's AES key
    aes_key = recover_aes_key(
        container,
        alice_private,
        alice_public
    )

    # 6. Reconstruct the original AAD
    aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytearray.fromhex(container["ciphertext"])

    # 7. Modify one byte of the ciphertext
    ciphertext[0] ^= 1

    # 8. Verify that authentication fails
    with pytest.raises(InvalidTag):
        AESGCM(aes_key).decrypt(
            nonce,
            bytes(ciphertext),
            aad
        )


def test_modified_metadata(tmp_path):
    """
    Verify that AES-GCM rejects modified metadata.
    """

    # 1. Create the original document
    original = tmp_path / "original.txt"
    original.write_text(
        "Protected metadata test",
        encoding="utf-8"
    )

    encrypted = tmp_path / "encrypted.vault"

    # 2. Generate two authorized recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # 3. Encrypt the document
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # 4. Load the container
    container = load_container(encrypted)

    # 5. Recover Alice's AES key
    aes_key = recover_aes_key(
        container,
        alice_private,
        alice_public
    )

    # 6. Modify the metadata
    container["metadata"]["filename"] = "modified.txt"

    # 7. Reconstruct AAD with modified metadata
    modified_aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    # 8. Verify that authentication fails
    with pytest.raises(InvalidTag):
        AESGCM(aes_key).decrypt(
            bytes.fromhex(container["nonce"]),
            bytes.fromhex(container["ciphertext"]),
            modified_aad
        )

def test_modified_recipient_key(tmp_path):
    """
    Verify that modifying another recipient's encrypted key
    invalidates AES-GCM authentication.
    """

    original = tmp_path / "original.txt"
    original.write_text("Confidential document", encoding="utf-8")

    encrypted = tmp_path / "encrypted.vault"

    # Generate two authorized recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # Encrypt the document
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # Load the original container
    container = load_container(encrypted)

    # Recover Alice's AES key before modifying the container
    aes_key = recover_aes_key(
        container,
        alice_private,
        alice_public
    )

    # Modify Bob's encrypted AES key
    bob_key = bytearray.fromhex(
        container["recipients"][1]["encrypted_key"]
    )

    bob_key[0] ^= 1

    container["recipients"][1]["encrypted_key"] = bob_key.hex()

    # Reconstruct AAD using the modified recipient list
    modified_aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    # Authentication must fail, even for Alice
    with pytest.raises(InvalidTag):
        AESGCM(aes_key).decrypt(
            bytes.fromhex(container["nonce"]),
            bytes.fromhex(container["ciphertext"]),
            modified_aad
        )


def test_removed_recipient(tmp_path):
    """
    Verify that removing a recipient invalidates
    AES-GCM authentication.
    """

    original = tmp_path / "original.txt"
    original.write_text("Protected document", encoding="utf-8")

    encrypted = tmp_path / "encrypted.vault"

    # Generate two authorized recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # Encrypt the document
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # Load the original container
    container = load_container(encrypted)

    # Recover Alice's AES key
    aes_key = recover_aes_key(
        container,
        alice_private,
        alice_public
    )

    # Remove Bob from the recipient list
    container["recipients"].pop(1)

    # Reconstruct AAD using the modified recipient list
    modified_aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    # Authentication must fail
    with pytest.raises(InvalidTag):
        AESGCM(aes_key).decrypt(
            bytes.fromhex(container["nonce"]),
            bytes.fromhex(container["ciphertext"]),
            modified_aad
        )