"""
D6 - Secure Key Backup and Recovery.

Create and restore encrypted private key backups
without exposing plaintext private keys.
"""

import json
from pathlib import Path

from src.secure_keystore import (
    load_encrypted_key,
    save_encrypted_key,
    decrypt_private_key,
)


def create_key_backup(
    keystore_path: str,
    backup_path: str,
) -> str:
    """
    Create a backup of an encrypted private key.

    The private key remains encrypted during the process.
    """

    source = Path(keystore_path)
    destination = Path(backup_path)

    if not source.is_file():
        raise FileNotFoundError(
            "Source keystore does not exist."
        )

    if source.resolve() == destination.resolve():
        raise ValueError(
            "Source and backup paths must be different."
        )

    if destination.exists():
        raise FileExistsError(
            "Backup file already exists."
        )

    # Load and validate the encrypted keystore
    keystore = load_encrypted_key(str(source))

    # Save the encrypted keystore as a backup
    save_encrypted_key(
        keystore,
        str(destination),
    )

    return str(destination)


def restore_key_backup(
    backup_path: str,
    restore_path: str,
    password: str,
) -> str:
    """
    Restore an encrypted private key after verifying
    its authenticity with the original password.
    """

    source = Path(backup_path)
    destination = Path(restore_path)

    if not source.is_file():
        raise FileNotFoundError(
            "Backup file does not exist."
        )

    if source.resolve() == destination.resolve():
        raise ValueError(
            "Backup and restore paths must be different."
        )

    if destination.exists():
        raise FileExistsError(
            "Restore destination already exists."
        )

    if not isinstance(password, str) or not password:
        raise ValueError(
            "A valid password is required."
        )

    # Load and validate the encrypted backup.
    keystore = load_encrypted_key(str(source))

    # Verify password and ciphertext integrity using AES-GCM.
    decrypt_private_key(
        keystore,
        password,
    )

    # Restore only encrypted key material.
    save_encrypted_key(
        keystore,
        str(destination),
    )

    return str(destination)