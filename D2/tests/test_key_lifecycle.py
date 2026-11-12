"""
D6 - Automated tests for cryptographic key lifecycle management.
"""

import os

import pytest

from src.key_lifecycle import KeyLifecycleManager
from src.key_management import encrypt_file_key, decrypt_file_key
from src.secure_keystore import load_encrypted_key, decrypt_private_key


@pytest.fixture
def manager():
    return KeyLifecycleManager()


def test_register_key(manager):
    key = manager.register_key("alice-key-001")

    assert key["status"] == "ACTIVE"
    assert manager.is_active("alice-key-001") is True


def test_register_duplicate_key(manager):
    manager.register_key("alice-key-001")

    with pytest.raises(ValueError, match="already exists"):
        manager.register_key("alice-key-001")


def test_register_empty_key_id(manager):
    with pytest.raises(ValueError, match="cannot be empty"):
        manager.register_key("")


def test_get_unknown_key(manager):
    with pytest.raises(KeyError, match="Key not found"):
        manager.get_key("unknown-key")


def test_revoke_key(manager):
    manager.register_key("alice-key-001")

    revoked = manager.revoke_key("alice-key-001")

    assert revoked["status"] == "REVOKED"
    assert manager.is_active("alice-key-001") is False


def test_revoke_already_revoked_key(manager):
    manager.register_key("alice-key-001")
    manager.revoke_key("alice-key-001")

    with pytest.raises(ValueError, match="already revoked"):
        manager.revoke_key("alice-key-001")


def test_rotate_key(manager):
    manager.register_key("alice-key-001")

    result = manager.rotate_key(
        "alice-key-001",
        "alice-key-002",
    )

    assert result["old_key"]["status"] == "RETIRED"
    assert result["new_key"]["status"] == "ACTIVE"
    assert result["old_key"]["replaced_by"] == "alice-key-002"


def test_rotate_revoked_key(manager):
    manager.register_key("alice-key-001")
    manager.revoke_key("alice-key-001")

    with pytest.raises(ValueError, match="Only active"):
        manager.rotate_key(
            "alice-key-001",
            "alice-key-002",
        )


def test_rotate_retired_key(manager):
    manager.register_key("alice-key-001")

    manager.rotate_key(
        "alice-key-001",
        "alice-key-002",
    )

    with pytest.raises(ValueError, match="Only active"):
        manager.rotate_key(
            "alice-key-001",
            "alice-key-003",
        )


def test_rotate_duplicate_key_id(manager):
    manager.register_key("alice-key-001")
    manager.register_key("alice-key-002")

    with pytest.raises(ValueError, match="already exists"):
        manager.rotate_key(
            "alice-key-001",
            "alice-key-002",
        )


def test_rotate_encrypted_key(manager, tmp_path):
    manager.register_key("alice-key-001")

    result = manager.rotate_encrypted_key(
        "alice-key-001",
        "alice-key-002",
        "TestPassword123!",
        str(tmp_path),
    )

    assert result["old_key"]["status"] == "RETIRED"
    assert result["new_key"]["status"] == "ACTIVE"

    stored = load_encrypted_key(
        result["new_keystore_path"]
    )

    private_key = decrypt_private_key(
        stored,
        "TestPassword123!",
    )

    original_aes_key = os.urandom(32)

    encrypted_aes_key = encrypt_file_key(
        result["new_public_key"],
        original_aes_key,
    )

    recovered_aes_key = decrypt_file_key(
        private_key,
        encrypted_aes_key,
    )

    assert recovered_aes_key == original_aes_key


def test_rotate_encrypted_key_wrong_password(manager, tmp_path):
    manager.register_key("alice-key-001")

    result = manager.rotate_encrypted_key(
        "alice-key-001",
        "alice-key-002",
        "CorrectPassword123!",
        str(tmp_path),
    )

    stored = load_encrypted_key(
        result["new_keystore_path"]
    )

    with pytest.raises(ValueError, match="Access denied"):
        decrypt_private_key(
            stored,
            "WrongPassword!",
        )


def test_rotate_encrypted_key_invalid_password(manager, tmp_path):
    manager.register_key("alice-key-001")

    with pytest.raises(ValueError, match="Password cannot be empty"):
        manager.rotate_encrypted_key(
            "alice-key-001",
            "alice-key-002",
            "",
            str(tmp_path),
        )

    assert manager.is_active("alice-key-001") is True
    assert "alice-key-002" not in manager.keys