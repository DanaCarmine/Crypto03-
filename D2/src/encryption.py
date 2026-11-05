import os

from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from src.key_management import (
    get_key_fingerprint,
    encrypt_file_key
)

from src.container import (
    build_aad,
    build_signature_payload,
    create_container,
    save_container
)

from src.digital_signature import (
    get_signer_fingerprint,
    sign_data
)



def encrypt_file(file_path, output_path, recipient_public_keys, signing_private_key, signing_public_key):
    """
    Encrypt a file using AES-256-GCM and protect the AES key
    for multiple recipients using ECIES.

     The resulting vault container is digitally signed using
    the sender's Ed25519 private key.

    Args:
        file_path (str): Path to the original file.
        output_path (str): Path to the encrypted .vault file.
        recipient_public_keys (list): List of recipient public keys.
        signing_private_key (bytes): Sender's Ed25519 private key.
        signing_public_key (bytes): Sender's Ed25519 public key.

    Returns:
        None
    """

    # 1. Validate the recipient list
    if not isinstance(recipient_public_keys, list):
        raise ValueError("Recipient public keys must be provided as a list.")

    if len(recipient_public_keys) < 2:
        raise ValueError("At least two recipients are required.")

    # 2. Validate the sender's signing keys
    if not isinstance(signing_private_key, bytes):
        raise ValueError("Signing private key must be bytes.")

    if len(signing_private_key) != 32:
        raise ValueError(
            "Ed25519 private key must be 32 bytes."
        )

    if not isinstance(signing_public_key, bytes):
        raise ValueError("Signing public key must be bytes.")

    if len(signing_public_key) != 32:
        raise ValueError(
            "Ed25519 public key must be 32 bytes."
        )

    # 3. Verify that both signing keys belong to the same pair
    try:
        private_key_object = Ed25519PrivateKey.from_private_bytes(
            signing_private_key
        )

        derived_public_key = private_key_object.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    except (ValueError, TypeError) as error:
        raise ValueError(
            f"Invalid Ed25519 signing key: {error}"
        ) from error

    if derived_public_key != signing_public_key:
        raise ValueError(
            "Signing private and public keys do not match."
        )

    # 4. Read the original file
    file_path = Path(file_path)

    with file_path.open("rb") as file:
        plaintext = file.read()

    # 5. Generate a random 256-bit AES key
    key = AESGCM.generate_key(bit_length=256)

    # 6. Generate a random 96-bit nonce
    nonce = os.urandom(12)

    # 7. Create file metadata
    metadata = {
        "filename": file_path.name,
        "algorithm": "AES-256-GCM",
        "key_encryption": "ECIES-secp256k1",
        "signature_algorithm": "Ed25519",
        "version": "5.0",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    # 8. Encrypt the AES key for each recipient using ECIES
    recipients = []
    recipient_ids = set()

    for public_key in recipient_public_keys:

        # Generate the recipient's SHA-256 fingerprint
        recipient_id = get_key_fingerprint(public_key)

        # Prevent duplicate recipients
        if recipient_id in recipient_ids:
            raise ValueError(
                "Duplicate recipients are not allowed."
            )

        recipient_ids.add(recipient_id)

        # Encrypt the AES key using the recipient's public key
        encrypted_key = encrypt_file_key(public_key, key)

        # Store the recipient information
        recipients.append({
            "id": recipient_id,
            "encrypted_key": encrypted_key.hex()
        })

    # 9. Generate AAD using metadata and the complete recipient list
    aad = build_aad(metadata, recipients)

    # 10. Create the AES-GCM object
    aesgcm = AESGCM(key)

    # 11. Encrypt the document
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad
    )

    # 12. Create the encrypted vault container
    container = create_container(
        metadata,
        recipients,
        nonce,
        ciphertext
    )

    # 13. Identify the sender using the Ed25519 public key
    signer_id = get_signer_fingerprint(signing_public_key)

    # 14. Add the sender identifier to the container
    container["signer_id"] = signer_id

    # 15. Build the data that will be digitally signed
    signature_payload = build_signature_payload(container)

    # 16. Generate the digital signature
    signature = sign_data(
        signing_private_key,
        signature_payload
    )

    # 17. Store the signature in hexadecimal format
    container["signature"] = signature.hex()

    # 18. Save the signed and encrypted container
    save_container(container, output_path)

    print("File encrypted and signed successfully!")
    print(f"Recipients: {len(recipients)}")
    print(f"Signer ID: {signer_id}")
    print(f"Encrypted file: {output_path}")

def encrypt_file_legacy(file_path, output_path, recipient_public_keys):
    """
    Encrypt a file using the legacy D3 container format.

    This function is provided only for backward compatibility.
    New D5 files must use encrypt_file() with mandatory signing keys.
    """

    if not isinstance(recipient_public_keys, list):
        raise ValueError("Recipient public keys must be provided as a list.")

    if len(recipient_public_keys) < 2:
        raise ValueError("At least two recipients are required.")

    file_path = Path(file_path)

    with file_path.open("rb") as file:
        plaintext = file.read()

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    metadata = {
        "filename": file_path.name,
        "algorithm": "AES-256-GCM",
        "key_encryption": "ECIES-secp256k1",
        "version": "3.0",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    recipients = []
    recipient_ids = set()

    for public_key in recipient_public_keys:
        recipient_id = get_key_fingerprint(public_key)

        if recipient_id in recipient_ids:
            raise ValueError("Duplicate recipients are not allowed.")

        recipient_ids.add(recipient_id)

        encrypted_key = encrypt_file_key(public_key, key)

        recipients.append({
            "id": recipient_id,
            "encrypted_key": encrypted_key.hex()
        })

    aad = build_aad(metadata, recipients)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    container = create_container(
        metadata,
        recipients,
        nonce,
        ciphertext
    )

    save_container(container, output_path)

    print("Legacy D3 file encrypted successfully!")