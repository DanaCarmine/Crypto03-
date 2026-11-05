import hashlib

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from cryptography.hazmat.primitives import serialization


def generate_signing_key_pair():
    """
    Generate an Ed25519 public/private key pair.

    Returns:
        tuple: (private_key, public_key) as bytes.

    The private and public keys are 32 bytes each.
    """

    # 1. Generate a new Ed25519 private key
    private_key = Ed25519PrivateKey.generate()

    # 2. Export the private key as raw bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 3. Derive the corresponding public key
    public_key = private_key.public_key()

    # 4. Export the public key as raw bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key_bytes, public_key_bytes


def get_signer_fingerprint(public_key):
    """
    Generate a SHA-256 fingerprint for an Ed25519 public key.

    Args:
        public_key (bytes): Sender's Ed25519 public key.

    Returns:
        str: SHA-256 fingerprint in hexadecimal format.
    """

    # 1. Validate the public key
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError(
            "Ed25519 public key must be 32 bytes."
        )

    # 2. Generate the SHA-256 fingerprint
    fingerprint = hashlib.sha256(public_key).hexdigest()

    return fingerprint


def sign_data(private_key, data):
    """
    Sign data using an Ed25519 private key.

    Args:
        private_key (bytes): Sender's Ed25519 private key.
        data (bytes): Data to be digitally signed.

    Returns:
        bytes: A 64-byte Ed25519 digital signature.
    """

    # 1. Validate the private key
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError(
            "Ed25519 private key must be 32 bytes."
        )

    # 2. Validate the data
    if not isinstance(data, bytes):
        raise ValueError(
            "Data to sign must be bytes."
        )

    # 3. Load the Ed25519 private key
    private_key_object = Ed25519PrivateKey.from_private_bytes(
        private_key
    )

    # 4. Generate the digital signature
    signature = private_key_object.sign(data)

    return signature


def verify_signature(public_key, data, signature):
    """
    Verify an Ed25519 digital signature.

    Args:
        public_key (bytes): Sender's Ed25519 public key.
        data (bytes): Original signed data.
        signature (bytes): Digital signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """

    # 1. Validate the public key
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return False

    # 2. Validate the signed data
    if not isinstance(data, bytes):
        return False

    # 3. Validate the signature
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False

    try:
        # 4. Load the Ed25519 public key
        public_key_object = Ed25519PublicKey.from_public_bytes(
            public_key
        )

        # 5. Verify the digital signature
        public_key_object.verify(
            signature,
            data
        )

        return True

    except (InvalidSignature, ValueError):
        return False