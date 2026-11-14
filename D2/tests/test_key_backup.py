"""
D6 - Tests for Secure Key Backup and Recovery.

Tests use real encrypted ECIES private keys.
"""

import base64
import json

import pytest

from src.key_management import generate_key_pair

from src.secure_keystore import (
    encrypt_private_key,
    save_encrypted_key,
    load_encrypted_key,
    decrypt_private_key,
)

from src.key_backup import (
    create_key_backup,
    restore_key_backup,
)


TEST_PASSWORD = "TestPassword123!"


@pytest.fixture
def encrypted_keystore(tmp_path):
    """Generate a real encrypted private key for testing."""

    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key=private_key,
        password=TEST_PASSWORD,
        key_id="test-key-001",
        algorithm="secp256k1",
        purpose="decryption",
    )

    keystore_path = tmp_path / "keystore.json"

    save_encrypted_key(
        keystore,
        str(keystore_path),
    )

    return keystore_path


def test_create_backup(encrypted_keystore, tmp_path):
    """Verify that a backup file is created."""

    backup_path = tmp_path / "backup.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    assert backup_path.exists()


def test_restore_backup(encrypted_keystore, tmp_path):
    """Verify that a valid backup can be restored."""

    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    restore_key_backup(
        str(backup_path),
        str(restored_path),
        TEST_PASSWORD,
    )

    assert restored_path.exists()


def test_backup_preserves_data(encrypted_keystore, tmp_path):
    """Verify that the backup preserves encrypted data."""

    backup_path = tmp_path / "backup.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    original = json.loads(
        encrypted_keystore.read_text(encoding="utf-8")
    )

    backup = json.loads(
        backup_path.read_text(encoding="utf-8")
    )

    assert original == backup


def test_backup_missing_source(tmp_path):
    """Reject backup creation when the source is missing."""

    source = tmp_path / "missing.json"
    backup = tmp_path / "backup.json"

    with pytest.raises(FileNotFoundError):
        create_key_backup(
            str(source),
            str(backup),
        )


def test_restore_missing_backup(tmp_path):
    """Reject restoration when the backup is missing."""

    backup = tmp_path / "missing.json"
    restored = tmp_path / "restored.json"

    with pytest.raises(FileNotFoundError):
        restore_key_backup(
            str(backup),
            str(restored),
            TEST_PASSWORD,
        )


def test_prevent_backup_overwrite(encrypted_keystore, tmp_path):
    """Prevent overwriting an existing backup."""

    backup_path = tmp_path / "backup.json"

    backup_path.write_text(
        "existing backup",
        encoding="utf-8",
    )

    with pytest.raises(FileExistsError):
        create_key_backup(
            str(encrypted_keystore),
            str(backup_path),
        )


def test_prevent_restore_overwrite(encrypted_keystore, tmp_path):
    """Prevent overwriting an existing restored keystore."""

    restored_path = tmp_path / "restored.json"

    restored_path.write_text(
        "existing keystore",
        encoding="utf-8",
    )

    with pytest.raises(FileExistsError):
        restore_key_backup(
            str(encrypted_keystore),
            str(restored_path),
            TEST_PASSWORD,
        )


def test_reject_same_backup_path(encrypted_keystore):
    """Prevent using the same source and destination."""

    with pytest.raises(ValueError):
        create_key_backup(
            str(encrypted_keystore),
            str(encrypted_keystore),
        )


def test_reject_same_restore_path(encrypted_keystore):
    """Prevent restoring to the same file."""

    with pytest.raises(ValueError):
        restore_key_backup(
            str(encrypted_keystore),
            str(encrypted_keystore),
            TEST_PASSWORD,
        )


def test_restored_key_can_be_decrypted(tmp_path):
    """
    Verify that a restored private key can be
    decrypted with the original password.
    """

    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key=private_key,
        password=TEST_PASSWORD,
        key_id="recovery-test-key",
        algorithm="secp256k1",
        purpose="decryption",
    )

    original_path = tmp_path / "original.json"
    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    save_encrypted_key(
        keystore,
        str(original_path),
    )

    create_key_backup(
        str(original_path),
        str(backup_path),
    )

    restore_key_backup(
        str(backup_path),
        str(restored_path),
        TEST_PASSWORD,
    )

    restored_keystore = load_encrypted_key(
        str(restored_path)
    )

    recovered_private_key = decrypt_private_key(
        restored_keystore,
        TEST_PASSWORD,
    )

    assert recovered_private_key == private_key


def test_reject_backup_missing_fields(tmp_path):
    """Reject a backup with missing required fields."""

    backup_path = tmp_path / "corrupted_backup.json"
    restored_path = tmp_path / "restored.json"

    corrupted_data = {
        "key_id": "test-key-001",
        "ciphertext": "invalid-data",
    }

    backup_path.write_text(
        json.dumps(corrupted_data),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        restore_key_backup(
            str(backup_path),
            str(restored_path),
            TEST_PASSWORD,
        )

    assert not restored_path.exists()


def test_detect_tampered_backup(encrypted_keystore, tmp_path):
    """
    Reject a modified ciphertext before restoring
    the encrypted private key.
    """

    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    backup_data = json.loads(
        backup_path.read_text(encoding="utf-8")
    )

    ciphertext = bytearray(
        base64.b64decode(backup_data["ciphertext"])
    )

    # Modify one byte of the encrypted data.
    ciphertext[0] ^= 1

    backup_data["ciphertext"] = base64.b64encode(
        bytes(ciphertext)
    ).decode("utf-8")

    backup_path.write_text(
        json.dumps(backup_data),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Access denied",
    ):
        restore_key_backup(
            str(backup_path),
            str(restored_path),
            TEST_PASSWORD,
        )

    # A manipulated backup must not be restored.
    assert not restored_path.exists()


def test_reject_wrong_backup_password(encrypted_keystore, tmp_path):
    """
    Reject restoration when the password is incorrect.
    """

    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    with pytest.raises(
        ValueError,
        match="Access denied",
    ):
        restore_key_backup(
            str(backup_path),
            str(restored_path),
            "WrongPassword123!",
        )

    assert not restored_path.exists()


def test_reject_empty_backup_password(encrypted_keystore, tmp_path):
    """
    Reject restoration when the password is empty.
    """

    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    create_key_backup(
        str(encrypted_keystore),
        str(backup_path),
    )

    with pytest.raises(
        ValueError,
        match="A valid password is required",
    ):
        restore_key_backup(
            str(backup_path),
            str(restored_path),
            "",
        )

    assert not restored_path.exists()