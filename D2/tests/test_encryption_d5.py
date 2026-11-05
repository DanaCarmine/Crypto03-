import json
import hashlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey
)
from cryptography.hazmat.primitives import serialization

from src.encryption import encrypt_file
from src.key_management import generate_key_pair


@pytest.fixture
def signing_keys():
    """Generate a valid Ed25519 signing key pair."""

    private_key = Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes, public_bytes


@pytest.fixture
def recipient_keys():
    """Generate two ECIES recipients."""

    _, alice_public = generate_key_pair()
    _, bob_public = generate_key_pair()

    return [alice_public, bob_public]


def test_d5_encryption_adds_signature(
    tmp_path,
    monkeypatch,
    signing_keys,
    recipient_keys
):
    """
    Verify that encryption adds signer_id and signature
    to the resulting vault container.
    """

    private_key, public_key = signing_keys

    input_file = tmp_path / "document.txt"
    output_file = tmp_path / "document.vault"

    input_file.write_text(
        "Confidential document for D5",
        encoding="utf-8"
    )

    expected_signer_id = hashlib.sha256(
        public_key
    ).hexdigest()

    expected_signature = b"\xAB" * 64

    def mock_fingerprint(key):
        assert key == public_key
        return expected_signer_id

    def mock_payload(container):
        assert container["signer_id"] == expected_signer_id
        assert "signature" not in container
        return b"canonical-signature-payload"

    def mock_sign(key, data):
        assert key == private_key
        assert data == b"canonical-signature-payload"
        return expected_signature

    monkeypatch.setattr(
        "src.encryption.get_signer_fingerprint",
        mock_fingerprint
    )

    monkeypatch.setattr(
        "src.encryption.build_signature_payload",
        mock_payload
    )

    monkeypatch.setattr(
        "src.encryption.sign_data",
        mock_sign
    )

    encrypt_file(
        input_file,
        output_file,
        recipient_keys,
        private_key,
        public_key
    )

    assert output_file.exists()

    container = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert container["signer_id"] == expected_signer_id
    assert container["signature"] == expected_signature.hex()

    assert container["metadata"]["signature_algorithm"] == "Ed25519"
    assert container["metadata"]["version"] == "5.0"

    assert len(container["recipients"]) == 2
    assert "nonce" in container
    assert "ciphertext" in container


def test_d5_rejects_mismatched_signing_keys(
    tmp_path,
    signing_keys,
    recipient_keys
):
    """
    Reject signing keys that do not belong to the same pair.
    """

    private_key, _ = signing_keys

    other_private_key = Ed25519PrivateKey.generate()

    wrong_public_key = other_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    input_file = tmp_path / "document.txt"
    output_file = tmp_path / "document.vault"

    input_file.write_text("Test document", encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="Signing private and public keys do not match"
    ):
        encrypt_file(
            input_file,
            output_file,
            recipient_keys,
            private_key,
            wrong_public_key
        )

    assert not output_file.exists()


@pytest.mark.parametrize(
    "invalid_key",
    [
        b"short",
        b"\x00" * 31,
        "not_bytes",
        None
    ]
)
def test_d5_rejects_invalid_private_key(
    tmp_path,
    invalid_key,
    signing_keys,
    recipient_keys
):
    """
    Reject invalid Ed25519 private key formats.
    """

    _, public_key = signing_keys

    input_file = tmp_path / "document.txt"
    output_file = tmp_path / "document.vault"

    input_file.write_text("Test document", encoding="utf-8")

    with pytest.raises(ValueError):
        encrypt_file(
            input_file,
            output_file,
            recipient_keys,
            invalid_key,
            public_key
        )

    assert not output_file.exists()


@pytest.mark.parametrize(
    "invalid_key",
    [
        b"short",
        b"\x00" * 31,
        "not_bytes",
        None
    ]
)
def test_d5_rejects_invalid_public_key(
    tmp_path,
    invalid_key,
    signing_keys,
    recipient_keys
):
    """
    Reject invalid Ed25519 public key formats.
    """

    private_key, _ = signing_keys

    input_file = tmp_path / "document.txt"
    output_file = tmp_path / "document.vault"

    input_file.write_text("Test document", encoding="utf-8")

    with pytest.raises(ValueError):
        encrypt_file(
            input_file,
            output_file,
            recipient_keys,
            private_key,
            invalid_key
        )

    assert not output_file.exists()