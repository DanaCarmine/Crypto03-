"""
D6 - Automated tests for cryptographic key lifecycle management.
"""

import os

import pytest
from src.key_registry import KeyRegistry
from src.key_lifecycle import KeyLifecycleManager
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
    
def test_key_lifecycle_persistence(tmp_path):
    """Verify that key metadata persists across manager instances."""

    registry_path = tmp_path / "registry.json"

    # First application session
    registry = KeyRegistry(str(registry_path))
    manager = KeyLifecycleManager(registry)

    manager.register_key("key-001")
    manager.rotate_key("key-001", "key-002")
    manager.revoke_key("key-002")

    # Simulate restarting the application
    new_registry = KeyRegistry(str(registry_path))
    new_manager = KeyLifecycleManager(new_registry)

    # Verify that both keys were recovered
    old_key = new_manager.get_key("key-001")
    new_key = new_manager.get_key("key-002")

    assert old_key["status"] == "RETIRED"
    assert old_key["replaced_by"] == "key-002"

    assert new_key["status"] == "REVOKED"
    assert new_key["replaced_by"] is None

    assert new_manager.is_active("key-001") is False
    assert new_manager.is_active("key-002") is False
    
def test_rotation_rollback_on_save_failure(tmp_path, monkeypatch):
    """Verify that a failed save does not leave a partial rotation."""

    registry_path = tmp_path / "registry.json"

    registry = KeyRegistry(str(registry_path))
    manager = KeyLifecycleManager(registry)

    # Register the original key successfully
    manager.register_key("key-001")

    original_key = manager.get_key("key-001")

    # Simulate a registry save failure
    def failing_save():
        raise RuntimeError("Simulated registry save failure")

    monkeypatch.setattr(registry, "save_registry", failing_save)

    # Rotation must fail
    with pytest.raises(RuntimeError, match="Simulated registry save failure"):
        manager.rotate_key("key-001", "key-002")

    # Original key must remain unchanged
    assert manager.get_key("key-001") == original_key

    # Replacement key must not remain registered
    with pytest.raises(KeyError):
        manager.get_key("key-002")

    # Verify the persisted registry was not modified
    recovered_registry = KeyRegistry(str(registry_path))
    recovered_manager = KeyLifecycleManager(recovered_registry)

    assert recovered_manager.get_key("key-001") == original_key

    with pytest.raises(KeyError):
        recovered_manager.get_key("key-002")