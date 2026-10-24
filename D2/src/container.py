import json
from pathlib import Path
import re

def canonical_json(data):
    """
    Convert data into a deterministic JSON byte representation.

    This ensures that the same information always produces
    the same byte sequence.

    Args:
        data (dict): Data to serialize.

    Returns:
        bytes: Canonical JSON encoded in UTF-8.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def build_aad(metadata, recipients):
    """
    Build authenticated additional data (AAD).

    The AAD includes the document metadata and the complete
    recipient list, including encrypted AES keys.

    Args:
        metadata (dict): Document metadata.
        recipients (list): Recipient information.

    Returns:
        bytes: Canonical AAD representation.
    """
    authenticated_data = {
        "metadata": metadata,
        "recipients": recipients
    }

    return canonical_json(authenticated_data)

def create_container(metadata, recipients, nonce, ciphertext):
    """
    Create a vault container for multiple recipients.

    Args:
        metadata (dict): Document metadata.
        recipients (list): List of recipients and encrypted AES keys.
        nonce (bytes): AES-GCM nonce.
        ciphertext (bytes): Encrypted document with authentication tag.

    Returns:
        dict: Vault container ready for JSON serialization.
    """

    # Validate metadata
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be a dictionary.")

    # Validate recipient list
    if not isinstance(recipients, list) or len(recipients) < 2:
        raise ValueError("At least two recipients are required.")

    recipient_ids = set()

    for recipient in recipients:

        # Validate recipient structure
        if not isinstance(recipient, dict):
            raise ValueError("Each recipient must be a dictionary.")

        if set(recipient.keys()) != {"id", "encrypted_key"}:
            raise ValueError("Invalid recipient structure.")

        recipient_id = recipient["id"]
        encrypted_key = recipient["encrypted_key"]

        # Validate SHA-256 fingerprint
        if not isinstance(recipient_id, str):
            raise ValueError("Recipient ID must be a string.")

        if not re.fullmatch(r"[0-9a-f]{64}", recipient_id):
            raise ValueError(
                "Recipient ID must be a 64-character SHA-256 fingerprint."
            )

        # Validate encrypted AES key
        if not isinstance(encrypted_key, str) or not encrypted_key:
            raise ValueError("Invalid encrypted key.")

        # Reject duplicate recipients
        if recipient_id in recipient_ids:
            raise ValueError("Duplicate recipient IDs are not allowed.")

        recipient_ids.add(recipient_id)

    # Validate AES-GCM nonce
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes.")

    # Validate ciphertext
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError("Invalid AES-GCM ciphertext.")

    # Build vault container
    container = {
        "metadata": metadata,
        "recipients": recipients,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    return container


def save_container(container, file_path):
    """
    Save a vault container as a JSON file.

    Args:
        container (dict): Vault container.
        file_path (str): Destination file path.
    """

    if not isinstance(container, dict):
        raise ValueError("Container must be a dictionary.")

    path = Path(file_path)

    if path.suffix.lower() != ".vault":
        raise ValueError("The file must have a .vault extension.")

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            container,
            file,
            indent=4,
            ensure_ascii=False
        )


def load_container(file_path):
    """
    Load and validate a vault container from a JSON file.

    Args:
        file_path (str): Path to the vault file.

    Returns:
        dict: Validated vault container.
    """

    path = Path(file_path)

    if path.suffix.lower() != ".vault":
        raise ValueError("The file must have a .vault extension.")

    with path.open("r", encoding="utf-8") as file:
        container = json.load(file)

    if not isinstance(container, dict):
        raise ValueError("Invalid vault container.")

    required_fields = {
        "metadata",
        "recipients",
        "nonce",
        "ciphertext"
    }

    if set(container.keys()) != required_fields:
        raise ValueError("Invalid vault container structure.")

    # Validate hexadecimal encoding
    try:
        nonce = bytes.fromhex(container["nonce"])
        ciphertext = bytes.fromhex(container["ciphertext"])
    except (TypeError, ValueError):
        raise ValueError("Invalid hexadecimal data in vault container.")

    # Reuse the validation rules from create_container
    validated_container = create_container(
        container["metadata"],
        container["recipients"],
        nonce,
        ciphertext
    )

    return validated_container