import os

from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.key_management import (
    get_key_fingerprint,
    encrypt_file_key
)

from src.container import (
    build_aad,
    create_container,
    save_container
)


def encrypt_file(file_path, output_path, recipient_public_keys):
    """
    Encrypt a file using AES-256-GCM and protect the AES key
    for multiple recipients using ECIES.

    Args:
        file_path (str): Path to the original file.
        output_path (str): Path to the encrypted .vault file.
        recipient_public_keys (list): List of recipient public keys.

    Returns:
        None
    """

    # 1. Validate the recipient list
    if not isinstance(recipient_public_keys, list):
        raise ValueError("Recipient public keys must be provided as a list.")

    if len(recipient_public_keys) < 2:
        raise ValueError("At least two recipients are required.")

    # 2. Read the original file
    file_path = Path(file_path)

    with file_path.open("rb") as file:
        plaintext = file.read()

    # 3. Generate a random 256-bit AES key
    key = AESGCM.generate_key(bit_length=256)

    # 4. Generate a random 96-bit nonce
    nonce = os.urandom(12)

    # 5. Create file metadata
    metadata = {
        "filename": file_path.name,
        "algorithm": "AES-256-GCM",
        "key_encryption": "ECIES-secp256k1",
        "version": "3.0",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    # 6. Encrypt the AES key for each recipient using ECIES
    recipients = []
    recipient_ids = set()

    for public_key in recipient_public_keys:

        # Generate the recipient's SHA-256 fingerprint
        recipient_id = get_key_fingerprint(public_key)

        # Prevent duplicate recipients
        if recipient_id in recipient_ids:
            raise ValueError("Duplicate recipients are not allowed.")

        recipient_ids.add(recipient_id)

        # Encrypt the AES key using the recipient's public key
        encrypted_key = encrypt_file_key(public_key, key)

        # Store the recipient information
        recipients.append({
            "id": recipient_id,
            "encrypted_key": encrypted_key.hex()
        })

    # 7. Generate AAD using metadata and the complete recipient list
    aad = build_aad(metadata, recipients)

    # 8. Create the AES-GCM object
    aesgcm = AESGCM(key)

    # 9. Encrypt the document
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad
    )

    # 10. Create the encrypted vault container
    container = create_container(
        metadata,
        recipients,
        nonce,
        ciphertext
    )

    # 11. Save the encrypted container
    save_container(container, output_path)

    print("File encrypted successfully!")
    print(f"Recipients: {len(recipients)}")
    print(f"Encrypted file: {output_path}")