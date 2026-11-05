
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ecies.keys import PrivateKey

from src.container import build_signature_payload

from src.digital_signature import (
    get_signer_fingerprint,
    verify_signature
)

from src.key_management import (
    get_key_fingerprint,
    decrypt_file_key
)

from src.container import (
    load_container,
    build_aad
)


def decrypt_file_legacy(container_path, private_key, output_path):
    """
    Decrypt a D3 vault file using an authorized recipient's
    ECIES private key.

    Args:
        container_path: Path to the encrypted .vault file.
        private_key: Recipient's ECIES private key (32 bytes).
        output_path: Path where the decrypted file will be saved.

    Returns:
        bool: True if decryption succeeds, False otherwise.
    """

    # 1. Load and validate the encrypted container
    try:
        container = load_container(container_path)
    except (OSError, ValueError, TypeError) as error:
        print(f"ERROR: Invalid container: {error}")
        return False
    
    if container["metadata"].get("version") != "3.0":
        print("ERROR: Legacy decryption only supports D3 containers.")
        return False




    # 2. Validate the private key
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        print("ERROR: Invalid private key format.")
        return False

    try:
        # 3. Derive the public key from the private key
        key_pair = PrivateKey("secp256k1", private_key)
        public_key = key_pair.public_key.to_bytes(True)

        # 4. Identify the recipient
        recipient_id = get_key_fingerprint(public_key)

        recipient = next(
            (
                item
                for item in container["recipients"]
                if item["id"] == recipient_id
            ),
            None
        )

        if recipient is None:
            print("ERROR: Recipient is not authorized.")
            return False

        # 5. Recover the AES file key using ECIES
        encrypted_key = bytes.fromhex(
            recipient["encrypted_key"]
        )

        aes_key = decrypt_file_key(
            private_key,
            encrypted_key
        )

        # 6. Reconstruct the authenticated data
        aad = build_aad(
            container["metadata"],
            container["recipients"]
        )

        # 7. Decrypt the document using AES-256-GCM
        nonce = bytes.fromhex(container["nonce"])
        ciphertext = bytes.fromhex(container["ciphertext"])

        plaintext = AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            aad
        )

    except (InvalidTag, ValueError, TypeError) as error:
        print(f"ERROR: Decryption failed: {error}")
        return False

    # 8. Save the decrypted document
    output_path = Path(output_path)

    try:
        with output_path.open("xb") as file:
            file.write(plaintext)
    except OSError as error:
        print(f"ERROR: Could not save decrypted file: {error}")
        return False

    print("File decrypted successfully!")
    return True

def decrypt_file(
    container_path,
    private_key,
    output_path,
    trusted_signer_public_key
):
    """
    Decrypt a D5 vault file after verifying its Ed25519 signature.

    Args:
        container_path: Path to the encrypted vault file.
        private_key: Recipient's ECIES private key (32 bytes).
        output_path: Path where the decrypted file will be saved.
        trusted_signer_public_key: Trusted Ed25519 public key (32 bytes).

    Returns:
        bool: True if decryption succeeds, False otherwise.
    """

    # 1. Load and validate the container
    try:
        container = load_container(container_path)
    except (OSError, ValueError, TypeError) as error:
        print(f"ERROR: Invalid container: {error}")
        return False

    # 2. Require a signed D5 container
    if container["metadata"].get("version") != "5.0":
        print("ERROR: D5 requires a signed version 5.0 container.")
        return False

    if container["metadata"].get("signature_algorithm") != "Ed25519":
        print("ERROR: Unsupported signature algorithm.")
        return False

    # 3. Validate the trusted public key
    if (
        not isinstance(trusted_signer_public_key, bytes)
        or len(trusted_signer_public_key) != 32
    ):
        print("ERROR: Invalid trusted signer public key.")
        return False

    # 4. Validate the recipient's private key
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        print("ERROR: Invalid recipient private key.")
        return False

    # 5. Verify the signer identity
    expected_signer_id = get_signer_fingerprint(
        trusted_signer_public_key
    )

    if container.get("signer_id") != expected_signer_id:
        print("ERROR: Signer identity does not match the trusted key.")
        return False

    # 6. Reconstruct the signed data
    try:
        signature_payload = build_signature_payload(container)
        signature = bytes.fromhex(container["signature"])
    except (KeyError, ValueError, TypeError) as error:
        print(f"ERROR: Invalid signature data: {error}")
        return False

    # 7. Verify the signature BEFORE decryption
    try:
        valid_signature = verify_signature(
            trusted_signer_public_key,
            signature_payload,
            signature
        )
    except (ValueError, TypeError) as error:
        print(f"ERROR: Signature verification failed: {error}")
        return False

    if not valid_signature:
        print("ERROR: Invalid digital signature.")
        return False

    # 8. Derive the recipient's public key
    try:
        key_pair = PrivateKey("secp256k1", private_key)
        public_key = key_pair.public_key.to_bytes(True)

        recipient_id = get_key_fingerprint(public_key)

        # 9. Find the authorized recipient
        recipient = next(
            (
                item
                for item in container["recipients"]
                if item["id"] == recipient_id
            ),
            None
        )

        if recipient is None:
            print("ERROR: Recipient is not authorized.")
            return False

        # 10. Recover the AES key using ECIES
        encrypted_key = bytes.fromhex(
            recipient["encrypted_key"]
        )

        aes_key = decrypt_file_key(
            private_key,
            encrypted_key
        )

        # 11. Reconstruct the AAD
        aad = build_aad(
            container["metadata"],
            container["recipients"]
        )

        # 12. Decrypt the document using AES-256-GCM
        nonce = bytes.fromhex(container["nonce"])
        ciphertext = bytes.fromhex(container["ciphertext"])

        plaintext = AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            aad
        )

    except (InvalidTag, ValueError, TypeError) as error:
        print(f"ERROR: Decryption failed: {error}")
        return False

    # 13. Save the decrypted document
    output_path = Path(output_path)

    try:
        with output_path.open("xb") as file:
            file.write(plaintext)
    except OSError as error:
        print(f"ERROR: Could not save decrypted file: {error}")
        return False

    print("File signature verified and decrypted successfully!")
    return True
