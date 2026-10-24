import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

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


def test_encrypt_decrypt(tmp_path):
    """
    Verify that an authorized recipient can decrypt
    the original document.
    """

    # 1. Create the original document
    original = tmp_path / "original.txt"
    original.write_text(
        "Hello, this is a test!",
        encoding="utf-8"
    )

    encrypted = tmp_path / "encrypted.vault"

    # 2. Generate key pairs for two recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # 3. Encrypt the document for both recipients
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # 4. Load the encrypted container
    container = load_container(encrypted)

    # 5. Find Alice's encrypted AES key
    alice_id = get_key_fingerprint(alice_public)

    alice_recipient = next(
        recipient
        for recipient in container["recipients"]
        if recipient["id"] == alice_id
    )

    # 6. Recover the AES key using Alice's private key
    aes_key = decrypt_file_key(
        alice_private,
        bytes.fromhex(alice_recipient["encrypted_key"])
    )

    # 7. Reconstruct the authenticated data
    aad = build_aad(
        container["metadata"],
        container["recipients"]
    )

    # 8. Decrypt the document
    plaintext = AESGCM(aes_key).decrypt(
        bytes.fromhex(container["nonce"]),
        bytes.fromhex(container["ciphertext"]),
        aad
    )

    # 9. Verify the original content
    assert plaintext == original.read_bytes()


def test_wrong_key(tmp_path):
    """
    Verify that an unauthorized private key
    cannot recover the AES file key.
    """

    # 1. Create the original document
    original = tmp_path / "original.txt"
    original.write_text(
        "This is confidential information.",
        encoding="utf-8"
    )

    encrypted = tmp_path / "encrypted.vault"

    # 2. Generate authorized recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # 3. Generate an unauthorized private key
    wrong_private, wrong_public = generate_key_pair()

    # 4. Encrypt for Alice and Bob
    encrypt_file(
        original,
        encrypted,
        [alice_public, bob_public]
    )

    # 5. Load the container
    container = load_container(encrypted)

    # 6. Find Alice's encrypted AES key
    alice_id = get_key_fingerprint(alice_public)

    alice_recipient = next(
        recipient
        for recipient in container["recipients"]
        if recipient["id"] == alice_id
    )

    encrypted_aes_key = bytes.fromhex(
        alice_recipient["encrypted_key"]
    )

    # 7. Attempt to recover the key with an unauthorized private key
    with pytest.raises(Exception):
        decrypt_file_key(
            wrong_private,
            encrypted_aes_key
        )