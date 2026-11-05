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

def _decode_hex_field(value, field_name):
    """
    Decode a hexadecimal field using strict validation.
    """

    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name} hexadecimal data.")

    if len(value) % 2 != 0 or not re.fullmatch(
        r"[0-9a-f]*", value
    ):
        raise ValueError(f"Invalid {field_name} hexadecimal data.")

    return bytes.fromhex(value)


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
    Validate and save a vault container as JSON.

    D5 containers must include a valid signer fingerprint
    and an Ed25519 signature.
    """

    if not isinstance(container, dict):
        raise ValueError("Container must be a dictionary.")

    path = Path(file_path)

    if path.suffix.lower() != ".vault":
        raise ValueError("The file must have a .vault extension.")

    metadata = container.get("metadata")

    if not isinstance(metadata, dict):
        raise ValueError("Invalid container metadata.")

    version = metadata.get("version")

    if version == "5.0":
        required_fields = {
            "metadata",
            "recipients",
            "nonce",
            "ciphertext",
            "signer_id",
            "signature"
        }

        if set(container.keys()) != required_fields:
            raise ValueError("Invalid D5 container structure.")

        signer_id = container["signer_id"]
        signature = container["signature"]

        if not isinstance(signer_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", signer_id
        ):
            raise ValueError("Invalid signer fingerprint.")

        if not isinstance(signature, str) or not re.fullmatch(
            r"[0-9a-f]{128}", signature
        ):
            raise ValueError("Invalid Ed25519 signature format.")

    elif version == "3.0":
        required_fields = {
            "metadata",
            "recipients",
            "nonce",
            "ciphertext"
        }

        if set(container.keys()) != required_fields:
            raise ValueError("Invalid D3 container structure.")

    else:
        raise ValueError("Unsupported container version.")

    # Validate the complete structure before writing
    nonce = _decode_hex_field(container.get("nonce"), "nonce")
    ciphertext = _decode_hex_field(
        container.get("ciphertext"), "ciphertext"
    )

    create_container(
        metadata,
        container.get("recipients"),
        nonce,
        ciphertext
    )

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            container,
            file,
            indent=4,
            ensure_ascii=False
        )


def load_container(file_path):
    """
    Load and validate a D3 or D5 vault container.

    D5 containers must include signer_id and signature.
    """

    path = Path(file_path)

    if path.suffix.lower() != ".vault":
        raise ValueError("The file must have a .vault extension.")

    with path.open("r", encoding="utf-8") as file:
        container = json.load(file)

    if not isinstance(container, dict):
        raise ValueError("Invalid vault container.")

    metadata = container.get("metadata")

    if not isinstance(metadata, dict):
        raise ValueError("Invalid container metadata.")

    version = metadata.get("version")

    base_fields = {
        "metadata",
        "recipients",
        "nonce",
        "ciphertext"
    }

    if version == "5.0":
        required_fields = base_fields | {
            "signer_id",
            "signature"
        }

        if set(container.keys()) != required_fields:
            raise ValueError("Invalid D5 container structure.")

        signer_id = container["signer_id"]
        signature = container["signature"]

        if not isinstance(signer_id, str) or not re.fullmatch(
            r"[0-9a-f]{64}", signer_id
        ):
            raise ValueError("Invalid signer fingerprint.")

        if not isinstance(signature, str) or not re.fullmatch(
            r"[0-9a-f]{128}", signature
        ):
            raise ValueError("Invalid Ed25519 signature format.")

    elif version == "3.0":
        if set(container.keys()) != base_fields:
            raise ValueError("Invalid D3 container structure.")

    else:
        raise ValueError("Unsupported container version.")

    nonce = _decode_hex_field(container["nonce"], "nonce")
    ciphertext = _decode_hex_field(
        container["ciphertext"], "ciphertext"
    )

    validated_container = create_container(
        metadata,
        container["recipients"],
        nonce,
        ciphertext
    )

    if version == "5.0":
        validated_container["signer_id"] = container["signer_id"]
        validated_container["signature"] = container["signature"]

    return validated_container

def build_signature_payload(container):
    """
    Build the canonical data that will be digitally signed.

    The signature protects metadata, recipients, nonce,
    ciphertext, and signer identification.

    Args:
        container (dict): Vault container.

    Returns:
        bytes: Canonical JSON data ready for signing.
    """

    if not isinstance(container, dict):
        raise ValueError("Container must be a dictionary.")

    required_fields = {
        "metadata",
        "recipients",
        "nonce",
        "ciphertext",
        "signer_id"
    }

    if not required_fields.issubset(container.keys()):
        raise ValueError("Missing fields required for digital signature.")

    signer_id = container["signer_id"]

    if not isinstance(signer_id, str) or not re.fullmatch(
        r"[0-9a-f]{64}", signer_id
    ):
        raise ValueError("Invalid signer fingerprint.")

    signed_data = {
        "metadata": container["metadata"],
        "recipients": container["recipients"],
        "nonce": container["nonce"],
        "ciphertext": container["ciphertext"],
        "signer_id": signer_id
    }

    return canonical_json(signed_data)