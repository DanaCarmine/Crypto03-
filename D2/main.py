"""
Secure File Exchange - Command Line Interface.

Main entry point for the application.
"""

import argparse

from src.key_management import generate_key_pair
from src.digital_signature import generate_signing_key_pair

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from ecies.keys import PrivateKey

from src.key_access import prompt_and_unlock_private_key

from src.encryption import encrypt_file
from src.digital_signature import get_signer_fingerprint 

from src.decryption import decrypt_file

from getpass import getpass
from pathlib import Path

from src.secure_keystore import (
    encrypt_private_key,
    save_encrypted_key
)

def generate_keys():
    """
    Generate ECIES and Ed25519 key pairs
    and securely store their private keys.
    """

    # Directory for encrypted private keys
    keys_directory = Path("keys")
    keys_directory.mkdir(exist_ok=True)

    encryption_path = keys_directory / "encryption_key.json"
    signing_path = keys_directory / "signing_key.json"

    # Prevent overwriting existing keys
    if encryption_path.exists() or signing_path.exists():
        print("ERROR: Key files already exist.")
        print("Existing keys will not be overwritten.")
        return

    # Request password
    password = getpass("Enter a password to protect your keys: ")
    confirm_password = getpass("Confirm password: ")

    if not password:
        print("ERROR: Password cannot be empty.")
        return

    if password != confirm_password:
        print("ERROR: Passwords do not match.")
        return

    # Generate ECIES key pair
    encryption_private_key, encryption_public_key = generate_key_pair()

    # Generate Ed25519 key pair
    signing_private_key, signing_public_key = generate_signing_key_pair()

    # Encrypt ECIES private key
    encryption_keystore = encrypt_private_key(
        private_key=encryption_private_key,
        password=password,
        key_id="encryption-key-001",
        algorithm="secp256k1",
        purpose="decryption"
    )

    # Encrypt Ed25519 private key
    signing_keystore = encrypt_private_key(
        private_key=signing_private_key,
        password=password,
        key_id="signing-key-001",
        algorithm="Ed25519",
        purpose="signing"
    )

    # Save encrypted private keys
    save_encrypted_key(
        encryption_keystore,
        str(encryption_path)
    )

    save_encrypted_key(
        signing_keystore,
        str(signing_path)
    )


    # Directory for public keys
    public_keys_directory = Path("public_keys")
    public_keys_directory.mkdir(exist_ok=True)

    # Save ECIES public key
    encryption_public_path = (
        public_keys_directory / "encryption_public.hex"
    )

    encryption_public_path.write_text(
        encryption_public_key.hex(),
        encoding="utf-8"
    )

    # Save Ed25519 public key
    signing_public_path = (
        public_keys_directory / "signing_public.hex"
    )

    signing_public_path.write_text(
        signing_public_key.hex(),
        encoding="utf-8"
    )

    print("\nPublic keys exported successfully!")
    print(f"ECIES public key: {encryption_public_path}")
    print(f"Ed25519 public key: {signing_public_path}")

    print("\nKeys generated and securely stored!")
    print(f"Encryption keystore: {encryption_path}")
    print(f"Signing keystore: {signing_path}")
    print("Private keys are protected with AES-256-GCM.")


def export_public_keys():
    """
    Export existing ECIES and Ed25519 public keys
    without generating new private keys.
    """

    keys_directory = Path("keys")
    public_keys_directory = Path("public_keys")

    encryption_path = keys_directory / "encryption_key.json"
    signing_path = keys_directory / "signing_key.json"

    # Verify that both encrypted keystores exist
    if not encryption_path.is_file() or not signing_path.is_file():
        print("ERROR: Encrypted keystores were not found.")
        return

    # Unlock ECIES private key
    encryption_private_key = prompt_and_unlock_private_key(
        keystore_path=str(encryption_path),
        expected_algorithm="secp256k1",
        expected_purpose="decryption",
        expected_key_id="encryption-key-001"
    )

    # Unlock Ed25519 private key
    signing_private_key = prompt_and_unlock_private_key(
        keystore_path=str(signing_path),
        expected_algorithm="Ed25519",
        expected_purpose="signing",
        expected_key_id="signing-key-001"
    )

    # Derive ECIES public key
    encryption_key_pair = PrivateKey(
        "secp256k1",
        encryption_private_key
    )

    encryption_public_key = (
        encryption_key_pair.public_key.to_bytes(True)
    )

    # Derive Ed25519 public key
    signing_key_pair = ed25519.Ed25519PrivateKey.from_private_bytes(
        signing_private_key
    )

    signing_public_key = signing_key_pair.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    # Create public keys directory
    public_keys_directory.mkdir(exist_ok=True)

    # Export ECIES public key
    encryption_public_path = (
        public_keys_directory / "encryption_public.hex"
    )

    encryption_public_path.write_text(
        encryption_public_key.hex(),
        encoding="utf-8"
    )

    # Export Ed25519 public key
    signing_public_path = (
        public_keys_directory / "signing_public.hex"
    )

    signing_public_path.write_text(
        signing_public_key.hex(),
        encoding="utf-8"
    )

    print("\nPublic keys exported successfully!")
    print(f"ECIES public key: {encryption_public_path}")
    print(f"Ed25519 public key: {signing_public_path}")

def encrypt_document():
    """
    Encrypt and sign a document for multiple recipients.
    """

    # Request input file
    file_path = Path(input("Enter file path: ").strip().strip('"'))

    if not file_path.is_file():
        print("ERROR: File not found.")
        return

    # Define output file
    output_path = file_path.with_suffix(".vault")

    if output_path.exists():
        print("ERROR: Encrypted file already exists.")
        return

    # Load recipient public keys
    recipient_public_keys = []

    try:
        num_recipients = int(
            input("Enter number of recipients (minimum 2): ").strip()
        )

        if num_recipients < 2:
            print("ERROR: At least two recipients are required.")
            return

        for i in range(num_recipients):
            key_path = Path(
                input(
                    f"Enter public key path for recipient {i + 1}: "
                ).strip().strip('"')
            )

            public_key = bytes.fromhex(
                key_path.read_text(encoding="utf-8").strip()
            )
        # Validate compressed secp256k1 public key
            if (
                len(public_key) != 33
                or public_key[0] not in (0x02, 0x03)
            ):
                print(
                    "ERROR: Invalid recipient public key format. "
                    "Expected a 33-byte compressed secp256k1 key."
                )
                return
            
            if public_key in recipient_public_keys:
                print("ERROR: Duplicate recipient public key.")
                return

            recipient_public_keys.append(public_key)

    except (OSError, ValueError) as error:
        print(f"ERROR: Could not load recipient keys: {error}")
        return

    # Load sender's signing public key
    signing_public_key_path = Path(
        input("Enter your signing public key path: ").strip().strip('"')
    )

    try:
        signing_public_key = bytes.fromhex(
            signing_public_key_path.read_text(encoding="utf-8").strip()
        )

        if len(signing_public_key) != 32:
            print("ERROR: Invalid Ed25519 public key length.")
            return

    except (OSError, ValueError) as error:
        print(f"ERROR: Could not load signing public key: {error}")
        return

    # Unlock sender's Ed25519 private key
    signing_keystore_path = input(
        "Enter your signing keystore path: "
    ).strip().strip('"')

    try:
        signing_private_key = prompt_and_unlock_private_key(
            keystore_path=signing_keystore_path,
            expected_algorithm="Ed25519",
            expected_purpose="signing",
            expected_key_id=None
        )

    except (OSError, ValueError) as error:
        print(f"ERROR: Could not unlock signing key: {error}")
        return

    # Verify that signing public and private keys match
    try:
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
            signing_private_key
        )

        derived_public_key = private_key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        if derived_public_key != signing_public_key:
            print(
                "ERROR: Signing public key does not match "
                "the private key."
            )
            return

    except (ValueError, TypeError) as error:
        print(f"ERROR: Invalid signing key: {error}")
        return

    # Encrypt and sign document
    try:
        encrypt_file(
            file_path=str(file_path),
            output_path=str(output_path),
            recipient_public_keys=recipient_public_keys,
            signing_private_key=signing_private_key,
            signing_public_key=signing_public_key
        )

    except (OSError, ValueError, TypeError) as error:
        print(f"ERROR: Encryption failed: {error}")
        return

    print("\nDocument encrypted successfully!")

def decrypt_document():
    """
    Verify the digital signature and decrypt a document.
    """

    # Request encrypted file
    container_path = Path(
        input("Enter encrypted file path: ").strip().strip('"')
    )

    if not container_path.is_file():
        print("ERROR: Encrypted file not found.")
        return

    # Request output file
    output_path_input = input(
        "Enter output file path: "
    ).strip().strip('"')

    # Validate that the output path is not empty
    if not output_path_input:
        print("ERROR: Invalid output path or file already exists.")
        return

    output_path = Path(output_path_input)

    # Prevent overwriting existing files
    if output_path.exists():
        print("ERROR: Invalid output path or file already exists.")
        return

    # Request the recipient's encrypted private key
    keystore_path = input(
        "Enter your encrypted private key path: "
    ).strip().strip('"')

    # Request the trusted signer's public key
    signing_key_path = input(
        "Enter trusted signer public key path: "
    ).strip().strip('"')

    # Load trusted signing public key
    try:
        signing_public_key = bytes.fromhex(
            Path(signing_key_path)
            .read_text(encoding="utf-8")
            .strip()
        )

        # Validate Ed25519 public key length
        if len(signing_public_key) != 32:
            print("ERROR: Invalid Ed25519 public key length.")
            return

    except (OSError, ValueError) as error:
        print(f"ERROR: Could not load signing public key: {error}")
        return

    # Unlock recipient's ECIES private key
    try:
        private_key = prompt_and_unlock_private_key(
            keystore_path=keystore_path,
            expected_algorithm="secp256k1",
            expected_purpose="decryption",
            expected_key_id=None
        )

    except (OSError, ValueError) as error:
        print(f"ERROR: Could not unlock private key: {error}")
        return

    # Verify signature and decrypt document
    try:
        success = decrypt_file(
            container_path=str(container_path),
            private_key=private_key,
            output_path=str(output_path),
            trusted_signer_public_key=signing_public_key
        )

    except Exception as error:
        print(f"ERROR: Decryption failed: {error}")
        return

    if success:
        print("\nDocument verified and decrypted successfully!")
        print(f"Decrypted file: {output_path}")
    else:
        print("ERROR: Document could not be decrypted.")




def main():
    parser = argparse.ArgumentParser(
        description="Secure File Exchange - D6"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # Generate keys
    subparsers.add_parser(
        "generate-keys",
        help="Generate encryption and signing keys"
    )

    subparsers.add_parser(
        "export-public-keys",
        help="Export existing public keys"
    )

    # Encrypt file
    subparsers.add_parser(
        "encrypt",
        help="Encrypt and sign a file"
    )

    # Decrypt file
    subparsers.add_parser(
        "decrypt",
        help="Verify and decrypt a file"
    )

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys()

    elif args.command == "export-public-keys":
        export_public_keys()

    elif args.command == "encrypt":
        encrypt_document()

    elif args.command == "decrypt":
        decrypt_document()


if __name__ == "__main__":
    main()