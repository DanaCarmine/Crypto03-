import hashlib

import pytest

from src.digital_signature import (
    generate_signing_key_pair,
    get_signer_fingerprint,
    sign_data,
    verify_signature
)


def test_generate_signing_key_pair():
    """
    Verify that Ed25519 keys have the correct format.
    """

    private_key, public_key = generate_signing_key_pair()

    assert isinstance(private_key, bytes)
    assert isinstance(public_key, bytes)

    assert len(private_key) == 32
    assert len(public_key) == 32


def test_generate_unique_key_pairs():
    """
    Verify that different calls generate different key pairs.
    """

    private_key_1, public_key_1 = generate_signing_key_pair()
    private_key_2, public_key_2 = generate_signing_key_pair()

    assert private_key_1 != private_key_2
    assert public_key_1 != public_key_2


def test_signer_fingerprint():
    """
    Verify that the fingerprint is a SHA-256 hexadecimal string.
    """

    _, public_key = generate_signing_key_pair()

    fingerprint = get_signer_fingerprint(public_key)

    assert fingerprint == hashlib.sha256(public_key).hexdigest()
    assert len(fingerprint) == 64


def test_valid_signature():
    """
    Verify that a valid signature is accepted.
    """

    private_key, public_key = generate_signing_key_pair()

    data = b"Confidential document for D5"

    signature = sign_data(private_key, data)

    assert len(signature) == 64

    assert verify_signature(
        public_key,
        data,
        signature
    ) is True


def test_modified_data():
    """
    Verify that modified data is rejected.
    """

    private_key, public_key = generate_signing_key_pair()

    original_data = b"Original confidential document"
    modified_data = b"Modified confidential document"

    signature = sign_data(private_key, original_data)

    assert verify_signature(
        public_key,
        modified_data,
        signature
    ) is False


def test_wrong_public_key():
    """
    Verify that a different public key cannot validate the signature.
    """

    private_key, _ = generate_signing_key_pair()

    _, wrong_public_key = generate_signing_key_pair()

    data = b"Confidential document"

    signature = sign_data(private_key, data)

    assert verify_signature(
        wrong_public_key,
        data,
        signature
    ) is False


def test_modified_signature():
    """
    Verify that a modified signature is rejected.
    """

    private_key, public_key = generate_signing_key_pair()

    data = b"Confidential document"

    signature = sign_data(private_key, data)

    modified_signature = bytearray(signature)
    modified_signature[0] ^= 0x01

    assert verify_signature(
        public_key,
        data,
        bytes(modified_signature)
    ) is False


def test_missing_signature():
    """
    Verify that a missing signature is rejected.
    """

    _, public_key = generate_signing_key_pair()

    data = b"Confidential document"

    assert verify_signature(
        public_key,
        data,
        None
    ) is False


def test_empty_file_signature():
    """
    Verify that empty data can be signed and verified.
    """

    private_key, public_key = generate_signing_key_pair()

    data = b""

    signature = sign_data(private_key, data)

    assert verify_signature(
        public_key,
        data,
        signature
    ) is True


@pytest.mark.parametrize(
    "invalid_key",
    [
        b"short",
        b"\x00" * 31,
        "not_bytes",
        None
    ]
)
def test_invalid_private_key(invalid_key):
    """
    Verify that invalid private keys are rejected.
    """

    with pytest.raises(ValueError):
        sign_data(
            invalid_key,
            b"Test document"
        )


@pytest.mark.parametrize(
    "invalid_key",
    [
        b"short",
        b"\x00" * 31,
        "not_bytes",
        None
    ]
)
def test_invalid_public_key(invalid_key):
    """
    Verify that invalid public keys are rejected.
    """

    assert verify_signature(
        invalid_key,
        b"Test document",
        b"\x00" * 64
    ) is False


def test_invalid_data_type():
    """
    Verify that signing rejects non-byte data.
    """

    private_key, _ = generate_signing_key_pair()

    with pytest.raises(ValueError):
        sign_data(
            private_key,
            "This is a string"
        )