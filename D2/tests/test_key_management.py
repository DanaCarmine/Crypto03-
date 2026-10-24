import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.key_management import (
    generate_key_pair,
    get_key_fingerprint,
    encrypt_file_key,
    decrypt_file_key
)


def test_generate_key_pair():
    """Verify that ECIES generates valid key lengths."""

    private_key, public_key = generate_key_pair()

    assert len(private_key) == 32
    assert len(public_key) == 33


def test_key_fingerprint():
    """Verify that fingerprints are deterministic and unique."""

    _, public_key_1 = generate_key_pair()
    _, public_key_2 = generate_key_pair()

    fingerprint_1 = get_key_fingerprint(public_key_1)
    fingerprint_2 = get_key_fingerprint(public_key_2)

    assert len(fingerprint_1) == 64
    assert fingerprint_1 == get_key_fingerprint(public_key_1)
    assert fingerprint_1 != fingerprint_2


def test_two_recipients():
    """Verify that two recipients can recover the same AES key."""

    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    alice_encrypted = encrypt_file_key(alice_public, file_key)
    bob_encrypted = encrypt_file_key(bob_public, file_key)

    assert decrypt_file_key(alice_private, alice_encrypted) == file_key
    assert decrypt_file_key(bob_private, bob_encrypted) == file_key


def test_wrong_private_key():
    """Verify that an unauthorized private key cannot decrypt."""

    _, alice_public = generate_key_pair()
    bob_private, _ = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    encrypted_key = encrypt_file_key(alice_public, file_key)

    with pytest.raises(Exception):
        decrypt_file_key(bob_private, encrypted_key)


def test_invalid_aes_key_length():
    """Verify that invalid AES key lengths are rejected."""

    _, public_key = generate_key_pair()

    invalid_key = b"short_key"

    with pytest.raises(ValueError):
        encrypt_file_key(public_key, invalid_key)


def test_modified_encrypted_key():
    """Verify that tampering with an encrypted AES key is detected."""

    private_key, public_key = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    encrypted_key = encrypt_file_key(public_key, file_key)

    modified_key = bytearray(encrypted_key)
    modified_key[-1] ^= 1

    with pytest.raises(Exception):
        decrypt_file_key(private_key, bytes(modified_key))