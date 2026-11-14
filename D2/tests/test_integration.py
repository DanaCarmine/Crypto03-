"""
D6 - Integration tests for secure key management.
"""
import os

from src.key_management import (
    generate_key_pair,
    encrypt_file_key,
)

from src.secure_keystore import (
    encrypt_private_key,
    save_encrypted_key,
)

from src.key_access import (
    unlock_private_key,
    decrypt_file_key_with_keystore,
)

from src.key_lifecycle import KeyLifecycleManager

from src.key_backup import (
    create_key_backup,
    restore_key_backup,
)


import pytest

from src.integration_demo import run_integration_demo


def test_complete_integration():
    """
    Verify the complete secure key management workflow.
    """
    assert run_integration_demo("TestPassword123!") is True


def test_reject_empty_password():
    """
    Verify that an empty password is rejected.
    """
    with pytest.raises(ValueError, match="A password is required"):
        run_integration_demo("")


def test_reject_invalid_password_type():
    """
    Verify that invalid password types are rejected.
    """
    with pytest.raises(ValueError, match="A password is required"):
        run_integration_demo(None)


def test_integration_with_different_password():
    """
    Verify that the workflow works with another valid password.
    """
    assert run_integration_demo("AnotherSecurePassword456!") is True


def test_restored_key_recovers_aes_key(tmp_path):
    """
    Verify that a restored keystore can recover
    an AES file key encrypted with ECIES.
    """

    password = "TestPassword123!"
    private_key, public_key = generate_key_pair()

    keystore = encrypt_private_key(
        private_key=private_key,
        password=password,
        key_id="integration-key-001",
        algorithm="secp256k1",
        purpose="decryption",
    )

    original_path = tmp_path / "original.json"
    backup_path = tmp_path / "backup.json"
    restored_path = tmp_path / "restored.json"

    save_encrypted_key(keystore, str(original_path))

    create_key_backup(
        str(original_path),
        str(backup_path),
    )

    restore_key_backup(
        str(backup_path),
        str(restored_path),
        password,
    )

    aes_key = os.urandom(32)

    encrypted_aes_key = encrypt_file_key(
        public_key,
        aes_key,
    )

    recovered_aes_key = decrypt_file_key_with_keystore(
        keystore_path=str(restored_path),
        password=password,
        expected_key_id="integration-key-001",
        encrypted_file_key=encrypted_aes_key,
    )

    assert recovered_aes_key == aes_key


def test_wrong_password_blocks_key_access(tmp_path):
    """
    Verify that an incorrect password cannot
    unlock an encrypted private key.
    """

    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key=private_key,
        password="CorrectPassword123!",
        key_id="integration-key-002",
        algorithm="secp256k1",
        purpose="decryption",
    )

    keystore_path = tmp_path / "keystore.json"

    save_encrypted_key(
        keystore,
        str(keystore_path),
    )

    with pytest.raises(ValueError, match="Access denied"):
        unlock_private_key(
            keystore_path=str(keystore_path),
            password="WrongPassword123!",
            expected_algorithm="secp256k1",
            expected_purpose="decryption",
            expected_key_id="integration-key-002",
        )


def test_rotated_key_recovers_aes_key(tmp_path):
    """
    Verify that a newly rotated key can
    recover an AES file key using ECIES.
    """

    password = "TestPassword123!"

    manager = KeyLifecycleManager()
    manager.register_key("old-key")

    rotation = manager.rotate_encrypted_key(
        old_key_id="old-key",
        new_key_id="new-key",
        password=password,
        keystore_directory=str(tmp_path),
    )

    assert manager.get_key("old-key")["status"] == "RETIRED"
    assert manager.get_key("new-key")["status"] == "ACTIVE"
    assert manager.get_key("old-key")["replaced_by"] == "new-key"

    aes_key = os.urandom(32)

    encrypted_aes_key = encrypt_file_key(
        rotation["new_public_key"],
        aes_key,
    )

    recovered_aes_key = decrypt_file_key_with_keystore(
        keystore_path=rotation["new_keystore_path"],
        password=password,
        expected_key_id="new-key",
        encrypted_file_key=encrypted_aes_key,
    )

    assert recovered_aes_key == aes_key


def test_revoked_key_is_not_active():
    """
    Verify that a revoked key is no longer
    considered active by the lifecycle manager.
    """

    manager = KeyLifecycleManager()

    manager.register_key("revocation-test-key")

    assert manager.is_active("revocation-test-key")

    manager.revoke_key("revocation-test-key")

    assert manager.get_key("revocation-test-key")["status"] == "REVOKED"
    assert not manager.is_active("revocation-test-key")