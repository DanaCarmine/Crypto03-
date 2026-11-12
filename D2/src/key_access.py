
"""
D6 - Password-based access to encrypted private keys.

This module provides user access to the secure keystore
without storing passwords or caching private keys.
"""

from getpass import getpass

from src.secure_keystore import (
    load_encrypted_key,
    decrypt_private_key,
)


def unlock_private_key(
    keystore_path: str,
    password: str,
    expected_algorithm: str,
    expected_purpose: str,
    expected_key_id: str,
) -> bytes:
    """
    Unlock a private key after checking its identity and purpose.
    """

    keystore = load_encrypted_key(keystore_path)

    if (
        keystore["algorithm"] != expected_algorithm
        or keystore["purpose"] != expected_purpose
        or keystore["key_id"] != expected_key_id
    ):
        raise ValueError(
            "Key identity, algorithm, or purpose mismatch."
        )

    return decrypt_private_key(keystore, password)


def prompt_and_unlock_private_key(
    keystore_path: str,
    expected_algorithm: str,
    expected_purpose: str,
    expected_key_id: str,
) -> bytes:
    """
    Prompt the user for a password and unlock the key.
    """

    password = getpass("Enter your keystore password: ")

    try:
        return unlock_private_key(
            keystore_path,
            password,
            expected_algorithm,
            expected_purpose,
            expected_key_id,
        )
    finally:
        password = None

def decrypt_file_key_with_keystore(
    keystore_path: str,
    password: str,
    expected_key_id: str,
    encrypted_file_key: bytes,
) -> bytes:
    """
    Recover an AES file key using an encrypted ECIES private key.

    The private key is unlocked from the secure keystore
    and used with the existing D3 ECIES implementation.
    """
    from src.key_management import decrypt_file_key

    private_key = unlock_private_key(
        keystore_path=keystore_path,
        password=password,
        expected_algorithm="secp256k1",
        expected_purpose="decryption",
        expected_key_id=expected_key_id,
    )

    return decrypt_file_key(private_key, encrypted_file_key)
