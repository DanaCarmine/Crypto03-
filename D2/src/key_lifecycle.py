"""D6 - Cryptographic Key Lifecycle Management.

Manage key registration, revocation, rotation,
and encrypted private key storage.
"""

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import uuid

from src.key_management import generate_key_pair
from src.secure_keystore import (
    encrypt_private_key,
    save_encrypted_key,
)


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


def current_timestamp():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


class KeyLifecycleManager:
    """Manage cryptographic key lifecycle metadata."""

    def __init__(self):
        self.keys = {}

    def register_key(self, key_id: str):
        """Register a new active key."""

        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Key ID cannot be empty.")

        if key_id in self.keys:
            raise ValueError("Key ID already exists.")

        timestamp = current_timestamp()

        self.keys[key_id] = {
            "key_id": key_id,
            "status": KeyStatus.ACTIVE.value,
            "created_at": timestamp,
            "updated_at": timestamp,
            "replaced_by": None,
        }

        return self.get_key(key_id)

    def get_key(self, key_id: str):
        """Return a copy of the key metadata."""

        if key_id not in self.keys:
            raise KeyError("Key not found.")

        return self.keys[key_id].copy()

    def revoke_key(self, key_id: str):
        """Revoke a key."""

        key = self.get_key(key_id)

        if key["status"] == KeyStatus.REVOKED.value:
            raise ValueError("Key is already revoked.")

        self.keys[key_id]["status"] = KeyStatus.REVOKED.value
        self.keys[key_id]["updated_at"] = current_timestamp()

        return self.get_key(key_id)

    def is_active(self, key_id: str):
        """Check whether a key is active."""

        return (
            self.get_key(key_id)["status"]
            == KeyStatus.ACTIVE.value
        )

    def rotate_key(self, old_key_id: str, new_key_id: str):
        """
        Retire an active key and register its replacement.

        This operation updates lifecycle metadata only.
        """

        old_key = self.get_key(old_key_id)

        if old_key["status"] != KeyStatus.ACTIVE.value:
            raise ValueError("Only active keys can be rotated.")

        if not isinstance(new_key_id, str) or not new_key_id.strip():
            raise ValueError("New key ID cannot be empty.")

        if new_key_id in self.keys:
            raise ValueError("New key ID already exists.")

        # Register the replacement key
        new_key = self.register_key(new_key_id)

        # Retire the previous key
        self.keys[old_key_id]["status"] = KeyStatus.RETIRED.value
        self.keys[old_key_id]["updated_at"] = current_timestamp()
        self.keys[old_key_id]["replaced_by"] = new_key_id

        return {
            "old_key": self.get_key(old_key_id),
            "new_key": new_key,
        }

    def rotate_encrypted_key(
        self,
        old_key_id: str,
        new_key_id: str,
        password: str,
        keystore_directory: str,
    ):
        """
        Generate and securely store a new ECIES private key,
        then retire the previous key.
        """

        # Validate the current key
        old_key = self.get_key(old_key_id)

        if old_key["status"] != KeyStatus.ACTIVE.value:
            raise ValueError("Only active keys can be rotated.")

        if not isinstance(new_key_id, str) or not new_key_id.strip():
            raise ValueError("New key ID cannot be empty.")

        if new_key_id in self.keys:
            raise ValueError("New key ID already exists.")

        if not isinstance(password, str) or not password:
            raise ValueError("Password cannot be empty.")

        # Prepare the keystore directory
        directory = Path(keystore_directory)
        directory.mkdir(parents=True, exist_ok=True)

        # Generate a unique filename
        new_path = directory / f"{uuid.uuid4().hex}.json"

        # Generate a new ECIES key pair
        private_key, public_key = generate_key_pair()

        # Encrypt the private key
        encrypted_keystore = encrypt_private_key(
            private_key,
            password,
            new_key_id,
            algorithm="secp256k1",
            purpose="decryption",
        )

        # Save the encrypted private key
        save_encrypted_key(
            encrypted_keystore,
            str(new_path),
        )

        # Update lifecycle states after successful storage
        try:
            result = self.rotate_key(
                old_key_id,
                new_key_id,
            )
        except Exception:
            new_path.unlink(missing_ok=True)
            raise

        return {
            "old_key": result["old_key"],
            "new_key": result["new_key"],
            "new_public_key": public_key,
            "new_keystore_path": str(new_path),
        }