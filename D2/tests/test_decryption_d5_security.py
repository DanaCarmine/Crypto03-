
import json
from unittest.mock import patch

from tests.test_decryption_d5 import vault_data
from src.decryption import decrypt_file


def test_invalid_signature_blocks_key_recovery(vault_data):
    """
    An invalid signature must prevent ECIES key recovery.
    """

    container_path = vault_data["encrypted"]

    with container_path.open("r", encoding="utf-8") as file:
        container = json.load(file)

    # Modify the signature while keeping valid hexadecimal data
    signature = container["signature"]
    container["signature"] = (
        ("0" if signature[0] != "0" else "1")
        + signature[1:]
    )

    modified = vault_data["tmp_path"] / "invalid_signature.vault"

    with modified.open("w", encoding="utf-8") as file:
        json.dump(container, file)

    output = vault_data["tmp_path"] / "blocked_output.txt"

    with patch("src.decryption.decrypt_file_key") as mock_decrypt_key:
        result = decrypt_file(
            modified,
            vault_data["alice_private"],
            output,
            vault_data["signer_public"]
        )

    assert result is False
    mock_decrypt_key.assert_not_called()
    assert not output.exists()


def test_invalid_signature_blocks_aes_decryption(vault_data):
    """
    AES-GCM must not run when signature verification fails.
    """

    container_path = vault_data["encrypted"]

    with container_path.open("r", encoding="utf-8") as file:
        container = json.load(file)

    signature = container["signature"]
    container["signature"] = (
        ("0" if signature[0] != "0" else "1")
        + signature[1:]
    )

    modified = vault_data["tmp_path"] / "invalid_aes.vault"

    with modified.open("w", encoding="utf-8") as file:
        json.dump(container, file)

    output = vault_data["tmp_path"] / "blocked_aes.txt"

    with patch("src.decryption.AESGCM") as mock_aes:
        result = decrypt_file(
            modified,
            vault_data["alice_private"],
            output,
            vault_data["signer_public"]
        )

    assert result is False
    mock_aes.assert_not_called()
    assert not output.exists()


def test_wrong_signer_blocks_key_recovery(vault_data):
    """
    An untrusted signer must not trigger ECIES key recovery.
    """

    from src.digital_signature import generate_signing_key_pair

    _, wrong_public = generate_signing_key_pair()

    output = vault_data["tmp_path"] / "untrusted_output.txt"

    with patch("src.decryption.decrypt_file_key") as mock_decrypt_key:
        result = decrypt_file(
            vault_data["encrypted"],
            vault_data["alice_private"],
            output,
            wrong_public
        )

    assert result is False
    mock_decrypt_key.assert_not_called()
    assert not output.exists()
