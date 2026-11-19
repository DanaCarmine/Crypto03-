"""
D6 - Persistent Cryptographic Key Registry.

Store and retrieve cryptographic key metadata
using a JSON file on disk.
"""

import json
import os
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path
from filelock import FileLock


class KeyRegistry:
    """Manage persistent storage of cryptographic key metadata."""

    def __init__(self, registry_path: str):
        """
        Initialize the key registry.

        Args:
            registry_path: Path to the JSON registry file.
        """

        self.registry_path = Path(registry_path)
        self.keys = {}
        self._loaded_hash = None
        self._file_lock = FileLock(
            str(self.registry_path) + ".lock",
            timeout=10,
        )

    def _get_file_hash(self):
        """
        Calculate the SHA-256 hash of the registry file.
        """

        if not self.registry_path.exists():
            return None

        content = self.registry_path.read_bytes()

        return hashlib.sha256(content).hexdigest()

    def load_registry(self):
        """
        Load and validate cryptographic key metadata
        from the persistent JSON registry.
        """

        # Create the directory if it does not exist
        self.registry_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Coordinate reading with other registry operations
        with self._file_lock:

            if not self.registry_path.exists():
                self.keys = {}
                self._loaded_hash = None
                return self.keys

            try:
                # Read the file once so the hash matches
                # the exact content being validated
                content = self.registry_path.read_bytes()

                data = json.loads(content.decode("utf-8"))

            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError(
                    "Invalid or corrupted registry JSON file."
                ) from error

            if not isinstance(data, dict):
                raise ValueError(
                    "Registry must be a JSON object."
                )

            if set(data.keys()) != {"version", "keys"}:
                raise ValueError(
                    "Invalid registry structure."
                )

            if data["version"] != "1.0":
                raise ValueError(
                    "Unsupported registry version."
                )

            if not isinstance(data["keys"], dict):
                raise ValueError(
                    "Registry keys must be a dictionary."
                )

            # Validate every key record
            for key_id, record in data["keys"].items():
                self.validate_key_record(
                    key_id,
                    record,
                )

            self.validate_registry_references(
                data["keys"]
            )

            # Update memory only after successful validation
            self.keys = data["keys"]

            # Store the hash of the validated content
            self._loaded_hash = hashlib.sha256(
                content
            ).hexdigest()

            return self.keys
        
    @staticmethod
    def validate_key_record(key_id: str, record: dict):
        """
        Validate the metadata structure of a cryptographic key.
        """

        # Verify the key identifier
        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("Invalid key ID.")

        # Verify that the record is a dictionary
        if not isinstance(record, dict):
            raise ValueError("Key record must be a dictionary.")

        # Define required metadata fields
        required_fields = {
            "key_id",
            "status",
            "created_at",
            "updated_at",
            "replaced_by",
        }

        # Verify that all required fields are present
        if set(record.keys()) != required_fields:
            raise ValueError("Invalid key record structure.")

        # Verify that the identifier matches
        if record["key_id"] != key_id:
            raise ValueError("Key ID mismatch.")

        # Verify the key status
        valid_statuses = {"ACTIVE", "RETIRED", "REVOKED"}

        if (
            not isinstance(record["status"], str)
            or record["status"] not in valid_statuses
        ):
            raise ValueError("Invalid key status.")

        # Verify timestamps
        for field in ("created_at", "updated_at"):
            timestamp = record[field]

            if not isinstance(timestamp, str):
                raise ValueError("Invalid key timestamp.")

            try:
                parsed_timestamp = datetime.fromisoformat(timestamp)
            except ValueError as error:
                raise ValueError("Invalid key timestamp.") from error

            if parsed_timestamp.tzinfo is None:
                raise ValueError("Key timestamp must include a timezone.")

        # Verify replacement reference
        replaced_by = record["replaced_by"]

        if replaced_by is not None:
            if not isinstance(replaced_by, str) or not replaced_by.strip():
                raise ValueError("Invalid replacement key ID.")
            
            if replaced_by == key_id:
                raise ValueError(
                    "A key cannot replace itself."
                )

        return True

    @classmethod
    def validate_registry_references(cls, keys: dict):
        """
        Validate replacement references and detect cycles.
        """

        for key_id, record in keys.items():

            replaced_by = record["replaced_by"]

            # Verify that the replacement key exists
            if replaced_by is not None:
                if replaced_by not in keys:
                    raise ValueError(
                        "Replacement key does not exist."
                    )

        # Detect circular replacement references
        for key_id in keys:

            visited = set()
            current_key = key_id

            while current_key is not None:

                if current_key in visited:
                    raise ValueError(
                        "Circular key replacement detected."
                    )

                visited.add(current_key)

                current_key = keys[current_key]["replaced_by"]

        return True

    def save_registry(self):
        """
        Save key metadata atomically and detect concurrent changes.
        """

        # Validate all key records before saving
        for key_id, record in self.keys.items():
            self.validate_key_record(key_id, record)

        # Validate references between keys
        self.validate_registry_references(self.keys)

        registry_data = {
            "version": "1.0",
            "keys": self.keys,
        }

        # Create the registry directory if necessary
        self.registry_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Allow only one writer at a time
        with self._file_lock:

            # Detect modifications made by another instance
            current_hash = self._get_file_hash()

            if current_hash != self._loaded_hash:
                raise RuntimeError(
                    "Registry was modified by another process."
                )

            temporary_path = None

            try:
                # Create a temporary file in the same directory
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=self.registry_path.parent,
                    prefix=".registry_",
                    suffix=".tmp",
                    delete=False,
                ) as temporary_file:

                    temporary_path = Path(
                        temporary_file.name
                    )

                    json.dump(
                        registry_data,
                        temporary_file,
                        indent=4,
                    )

                    temporary_file.flush()

                    os.fsync(
                        temporary_file.fileno()
                    )

                # Atomically replace the registry file
                os.replace(
                    temporary_path,
                    self.registry_path,
                )

                # Remember the newly saved version
                self._loaded_hash = self._get_file_hash()

            finally:
                if temporary_path is not None:
                    temporary_path.unlink(
                        missing_ok=True
                    )

        return self.registry_path