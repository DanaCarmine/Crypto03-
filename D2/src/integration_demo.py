"""
D6 - Secure Key Management Integration Demo.

Demonstrates secure storage, password-based access,
ECIES encryption, backup, recovery, key rotation,
and revocation.
"""

import os
import tempfile
from pathlib import Path

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


def run_integration_demo(password: str):
    """
    Execute the complete D6 key management workflow.

    Temporary files are automatically deleted
    when the demonstration finishes.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("A password is required.")

    print("\n=== D6 SECURE KEY MANAGEMENT DEMO ===")

    with tempfile.TemporaryDirectory() as temp_dir:

        directory = Path(temp_dir)

        keystore_path = directory / "original_keystore.json"
        backup_path = directory / "backup.json"
        restored_path = directory / "restored_keystore.json"

        manager = KeyLifecycleManager()

        # STEP 1: Generate ECIES key pair
        private_key, public_key = generate_key_pair()

        print("[1] ECIES key pair generated.")

        # STEP 2: Encrypt and store private key
        keystore = encrypt_private_key(
            private_key=private_key,
            password=password,
            key_id="demo-key-001",
            algorithm="secp256k1",
            purpose="decryption",
        )

        save_encrypted_key(
            keystore,
            str(keystore_path),
        )

        print("[2] Private key encrypted and stored.")

        # STEP 3: Register key
        manager.register_key("demo-key-001")

        assert manager.is_active("demo-key-001")

        print("[3] Key registered as ACTIVE.")

        # STEP 4: Unlock private key
        recovered_private_key = unlock_private_key(
            keystore_path=str(keystore_path),
            password=password,
            expected_algorithm="secp256k1",
            expected_purpose="decryption",
            expected_key_id="demo-key-001",
        )

        assert recovered_private_key == private_key

        print("[4] Private key successfully unlocked.")

        # STEP 5: Encrypt and recover AES file key
        file_key = os.urandom(32)

        encrypted_file_key = encrypt_file_key(
            public_key,
            file_key,
        )

        recovered_file_key = decrypt_file_key_with_keystore(
            keystore_path=str(keystore_path),
            password=password,
            expected_key_id="demo-key-001",
            encrypted_file_key=encrypted_file_key,
        )

        assert recovered_file_key == file_key

        print("[5] AES file key successfully recovered.")

        # STEP 6: Create encrypted backup
        create_key_backup(
            str(keystore_path),
            str(backup_path),
        )

        print("[6] Encrypted backup created.")

        # STEP 7: Restore encrypted backup
        restore_key_backup(
            str(backup_path),
            str(restored_path),
            password,
        )

        restored_private_key = unlock_private_key(
            keystore_path=str(restored_path),
            password=password,
            expected_algorithm="secp256k1",
            expected_purpose="decryption",
            expected_key_id="demo-key-001",
        )

        assert restored_private_key == private_key

        print("[7] Encrypted backup restored successfully.")

        # STEP 8: Rotate encrypted key
        rotation = manager.rotate_encrypted_key(
            old_key_id="demo-key-001",
            new_key_id="demo-key-002",
            password=password,
            keystore_directory=str(directory),
        )

        assert not manager.is_active("demo-key-001")
        assert manager.is_active("demo-key-002")

        # Verify that the rotated key can recover an AES file key
        new_file_key = os.urandom(32)

        new_encrypted_file_key = encrypt_file_key(
            rotation["new_public_key"],
            new_file_key,
        )

        new_recovered_file_key = decrypt_file_key_with_keystore(
            keystore_path=rotation["new_keystore_path"],
            password=password,
            expected_key_id="demo-key-002",
            encrypted_file_key=new_encrypted_file_key,
        )

        assert new_recovered_file_key == new_file_key

        print("[8] Key rotation completed.")
        print("    Old key: RETIRED")
        print("    New key: ACTIVE")

        print("    New key successfully verified with ECIES.")

        # STEP 9: Revoke new key
        manager.revoke_key("demo-key-002")

        assert not manager.is_active("demo-key-002")

        print("[9] New key revoked successfully.")

        print("\n=== DEMO COMPLETED SUCCESSFULLY ===")

        return True


if __name__ == "__main__":
    from getpass import getpass

    password = getpass("Enter a password for the demo: ")

    run_integration_demo(password)