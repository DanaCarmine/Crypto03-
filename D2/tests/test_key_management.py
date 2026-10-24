import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.key_management import (
    generate_key_pair,
    get_key_fingerprint,
    encrypt_file_key,
    decrypt_file_key
)


# TEST 1: Generate ECIES key pair
def test_generate_key_pair():
    """Verify that ECIES generates valid key lengths."""

    private_key, public_key = generate_key_pair()

    assert len(private_key) == 32
    assert len(public_key) == 33


# TEST 2: Generate SHA-256 fingerprint
def test_key_fingerprint():
    """Verify that fingerprints are deterministic and unique."""

    _, public_key_1 = generate_key_pair()
    _, public_key_2 = generate_key_pair()

    fingerprint_1 = get_key_fingerprint(public_key_1)
    fingerprint_2 = get_key_fingerprint(public_key_2)

    assert len(fingerprint_1) == 64
    assert fingerprint_1 == get_key_fingerprint(public_key_1)
    assert fingerprint_1 != fingerprint_2


# TEST 3: Two recipients recover the same AES key
def test_two_recipients():
    """Verify that two recipients can recover the same AES key."""

    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    alice_encrypted = encrypt_file_key(alice_public, file_key)
    bob_encrypted = encrypt_file_key(bob_public, file_key)

    alice_recovered = decrypt_file_key(
        alice_private,
        alice_encrypted
    )

    bob_recovered = decrypt_file_key(
        bob_private,
        bob_encrypted
    )

    assert alice_recovered == file_key
    assert bob_recovered == file_key


# TEST 4: Reject incorrect private key
def test_wrong_private_key():
    """Verify that an unauthorized private key cannot decrypt."""

    _, alice_public = generate_key_pair()
    bob_private, _ = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    encrypted_key = encrypt_file_key(
        alice_public,
        file_key
    )

    with pytest.raises(Exception):
        decrypt_file_key(bob_private, encrypted_key)


# TEST 5: Reject invalid AES key length
def test_invalid_aes_key_length():
    """Verify that invalid AES key lengths are rejected."""

    _, public_key = generate_key_pair()

    invalid_key = b"short_key"

    with pytest.raises(ValueError):
        encrypt_file_key(public_key, invalid_key)


# TEST 6: Detect modified encrypted AES key
def test_modified_encrypted_key():
    """Verify that tampering with an encrypted AES key is detected."""

    private_key, public_key = generate_key_pair()

    file_key = AESGCM.generate_key(bit_length=256)

    encrypted_key = encrypt_file_key(
        public_key,
        file_key
    )

    modified_key = bytearray(encrypted_key)
    modified_key[-1] ^= 1

    with pytest.raises(Exception):
        decrypt_file_key(
            private_key,
            bytes(modified_key)
        )


# TEST 7: Reject invalid public key format
def test_invalid_public_key():
    """Verify that invalid public key formats are rejected."""

    file_key = AESGCM.generate_key(bit_length=256)

    invalid_public_key = b"invalid_key"

    with pytest.raises(ValueError):
        encrypt_file_key(
            invalid_public_key,
            file_key
        )


# TEST 8: Reject invalid private key format
def test_invalid_private_key():
    """Verify that invalid private key formats are rejected."""

    invalid_private_key = b"invalid_key"
    encrypted_key = b"encrypted_data"

    with pytest.raises(ValueError):
        decrypt_file_key(
            invalid_private_key,
            encrypted_key
        )


# TEST 9: Reject invalid public key prefix
def test_invalid_public_key_prefix():
    """Verify that invalid compressed public key prefixes are rejected."""

    file_key = AESGCM.generate_key(bit_length=256)

    invalid_public_key = b"\x04" + b"\x00" * 32

    with pytest.raises(ValueError):
        encrypt_file_key(
            invalid_public_key,
            file_key
        )