"""
Tests for persistent cryptographic key registry.
"""
import json
import pytest

from src.key_registry import KeyRegistry
from filelock import Timeout
from unittest.mock import patch


def test_load_registry_when_file_does_not_exist(tmp_path):
    """
    Verify that a missing registry initializes an empty dictionary.
    """

    # Create a temporary path for the registry
    registry_path = tmp_path / "registry.json"

    # Initialize the registry
    registry = KeyRegistry(str(registry_path))

    # Load the registry
    result = registry.load_registry()

    # Verify that the registry is empty
    assert result == {}
    assert registry.keys == {}

    # Verify that no file was created
    assert not registry_path.exists()

def test_load_registry_with_valid_json(tmp_path):
    """
    Verify that valid key metadata is loaded from a JSON file.
    """

    # Create a temporary registry file
    registry_path = tmp_path / "registry.json"

    # Define valid registry data
    registry_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "ACTIVE",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T20:00:00+00:00",
                "replaced_by": None
            }
        }
    }

    # Save the registry data as JSON
    registry_path.write_text(
        json.dumps(registry_data),
        encoding="utf-8"
    )

    # Initialize the registry
    registry = KeyRegistry(str(registry_path))

    # Load the registry from disk
    result = registry.load_registry()

    # Verify that the stored metadata was recovered
    assert result == registry_data["keys"]
    assert registry.keys["key_001"]["status"] == "ACTIVE"
    assert registry.keys["key_001"]["key_id"] == "key_001"

def test_load_registry_with_corrupted_json(tmp_path):
    """
    Verify that a corrupted JSON registry is rejected.
    """

    # Create a temporary registry file
    registry_path = tmp_path / "registry.json"

    # Write invalid JSON content
    invalid_json = '{"version": "1.0", "keys": {'

    registry_path.write_text(
        invalid_json,
        encoding="utf-8"
    )

    # Initialize the registry
    registry = KeyRegistry(str(registry_path))

    # Verify that loading the corrupted file raises an error
    with pytest.raises(
        ValueError,
        match="Invalid or corrupted registry JSON file."
    ):
        registry.load_registry()

    # Verify that the corrupted file was not modified
    assert registry_path.read_text(
        encoding="utf-8"
    ) == invalid_json

def test_load_registry_with_invalid_structure(tmp_path):
    """
    Verify that a registry with an invalid structure is rejected.
    """

    # Create a temporary registry file
    registry_path = tmp_path / "registry.json"

    # Define a JSON with an invalid structure
    invalid_data = {
        "version": "1.0",
        "keys": []
    }

    # Save the invalid JSON
    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8"
    )

    # Initialize the registry
    registry = KeyRegistry(str(registry_path))

    # Verify that the invalid structure is rejected
    with pytest.raises(
        ValueError,
        match="Registry keys must be a dictionary."
    ):
        registry.load_registry()

    # Verify that the original file was not modified
    assert json.loads(
        registry_path.read_text(encoding="utf-8")
    ) == invalid_data

def test_load_registry_with_invalid_key_status(tmp_path):
    """
    Verify that a registry containing an invalid key status is rejected.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "INVALID",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T20:00:00+00:00",
                "replaced_by": None,
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(ValueError, match="Invalid key status."):
        registry.load_registry()

    # Verify that invalid data was not accepted
    assert registry.keys == {}

    # Verify that the original file was not modified
    assert json.loads(
        registry_path.read_text(encoding="utf-8")
    ) == invalid_data

def test_save_registry_creates_json_file(tmp_path):
    """
    Verify that key metadata is saved to a JSON file.
    """

    registry_path = tmp_path / "registry.json"

    registry = KeyRegistry(str(registry_path))

    # Define a valid key record
    registry.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    # Save the registry
    registry.save_registry()

    # Verify that the JSON file was created
    assert registry_path.exists()

    # Read the saved file
    saved_data = json.loads(
        registry_path.read_text(encoding="utf-8")
    )

    # Verify the saved structure and metadata
    assert saved_data["version"] == "1.0"
    assert saved_data["keys"] == registry.keys
    assert saved_data["keys"]["key_001"]["status"] == "ACTIVE"

def test_registry_persistence_between_instances(tmp_path):
    """
    Verify that key metadata persists between registry instances.
    """

    registry_path = tmp_path / "registry.json"

    # First instance: create and save a registry
    registry1 = KeyRegistry(str(registry_path))

    registry1.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    registry1.save_registry()

    # Second instance: simulate restarting the application
    registry2 = KeyRegistry(str(registry_path))

    loaded_keys = registry2.load_registry()

    # Verify that the saved metadata was recovered
    assert loaded_keys == registry1.keys
    assert registry2.keys["key_001"]["status"] == "ACTIVE"
    assert registry2.keys["key_001"]["key_id"] == "key_001"

def test_registry_persists_key_revocation(tmp_path):
    """
    Verify that a revoked key remains revoked after reloading.
    """

    registry_path = tmp_path / "registry.json"

    # Create the first registry instance
    registry1 = KeyRegistry(str(registry_path))

    # Register an active key
    registry1.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    # Save the active key
    registry1.save_registry()

    # Simulate a key revocation
    registry1.keys["key_001"]["status"] = "REVOKED"
    registry1.keys["key_001"]["updated_at"] = (
        "2026-11-18T21:00:00+00:00"
    )

    # Save the updated registry
    registry1.save_registry()

    # Create a new instance to simulate restarting
    registry2 = KeyRegistry(str(registry_path))

    # Load the saved metadata
    loaded_keys = registry2.load_registry()

    # Verify that the key remains revoked
    assert loaded_keys["key_001"]["status"] == "REVOKED"

    # Verify that the update timestamp was preserved
    assert loaded_keys["key_001"]["updated_at"] == (
        "2026-11-18T21:00:00+00:00"
    )

def test_load_registry_with_missing_key_fields(tmp_path):
    """
    Verify that key records with missing fields are rejected.
    """

    registry_path = tmp_path / "registry.json"

    # Define a key record with missing metadata
    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "ACTIVE",
                "created_at": "2026-11-18T20:00:00+00:00",
            }
        },
    }

    # Save the invalid registry
    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    # Initialize the registry
    registry = KeyRegistry(str(registry_path))

    # Verify that the incomplete record is rejected
    with pytest.raises(
        ValueError,
        match="Invalid key record structure."
    ):
        registry.load_registry()

    # Verify that invalid metadata was not loaded
    assert registry.keys == {}

    # Verify that the original file was not modified
    assert json.loads(
        registry_path.read_text(encoding="utf-8")
    ) == invalid_data

def test_load_registry_with_invalid_timestamp(tmp_path):
    """
    Verify that invalid timestamps are rejected.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "ACTIVE",
                "created_at": "invalid-date",
                "updated_at": "2026-11-18T20:00:00+00:00",
                "replaced_by": None,
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="Invalid key timestamp."
    ):
        registry.load_registry()

    assert registry.keys == {}

def test_load_registry_with_key_id_mismatch(tmp_path):
    """
    Verify that mismatched key identifiers are rejected.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_999",
                "status": "ACTIVE",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T20:00:00+00:00",
                "replaced_by": None,
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="Key ID mismatch."
    ):
        registry.load_registry()

    assert registry.keys == {}

def test_load_registry_with_invalid_replacement(tmp_path):
    """
    Verify that invalid replacement references are rejected.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "RETIRED",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T21:00:00+00:00",
                "replaced_by": 12345,
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="Invalid replacement key ID."
    ):
        registry.load_registry()

    assert registry.keys == {}

def test_registry_detects_external_modifications(tmp_path):
    """
    Verify that stale registry data cannot overwrite newer changes.
    """

    registry_path = tmp_path / "registry.json"

    # Create and save the initial registry
    registry1 = KeyRegistry(str(registry_path))

    registry1.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    registry1.save_registry()

    # A second instance loads the same registry
    registry2 = KeyRegistry(str(registry_path))
    registry2.load_registry()

    # First instance revokes the key
    registry1.keys["key_001"]["status"] = "REVOKED"
    registry1.keys["key_001"]["updated_at"] = (
        "2026-11-18T21:00:00+00:00"
    )

    registry1.save_registry()

    # Second instance tries to save outdated information
    with pytest.raises(
        RuntimeError,
        match="Registry was modified by another process."
    ):
        registry2.save_registry()

    # Verify that the revocation was preserved
    registry3 = KeyRegistry(str(registry_path))
    registry3.load_registry()

    assert registry3.keys["key_001"]["status"] == "REVOKED"

def test_registry_file_lock_prevents_concurrent_writes(tmp_path):
    """
    Verify that a registry cannot be saved while
    another instance holds the file lock.
    """

    registry_path = tmp_path / "registry.json"

    # Create two independent registry instances
    registry1 = KeyRegistry(str(registry_path))
    registry2 = KeyRegistry(str(registry_path))

    # Prepare valid metadata
    registry2.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    # Reduce waiting time during the test
    registry2._file_lock.timeout = 0.1

    # First instance acquires the lock
    with registry1._file_lock:

        # Second instance attempts to save
        with pytest.raises(Timeout):
            registry2.save_registry()

        # Verify that no registry file was created
        assert not registry_path.exists()

    # After releasing the lock, saving should work
    registry2.save_registry()

    # Verify that the file was created successfully
    assert registry_path.exists()

def test_registry_file_lock_prevents_concurrent_reads(tmp_path):
    """
    Verify that registry loading respects the file lock.
    """

    registry_path = tmp_path / "registry.json"

    # Create two independent instances
    registry1 = KeyRegistry(str(registry_path))
    registry2 = KeyRegistry(str(registry_path))

    # Reduce timeout for faster testing
    registry2._file_lock.timeout = 0.1

    # First instance acquires the lock
    with registry1._file_lock:

        # Second instance attempts to read
        with pytest.raises(Timeout):
            registry2.load_registry()

    # After releasing the lock, reading should work
    loaded_keys = registry2.load_registry()

    # An empty registry is expected
    assert loaded_keys == {}

def test_registry_preserves_data_when_save_fails(tmp_path):
    """
    Verify that a failed save does not destroy
    the previously stored registry.
    """

    registry_path = tmp_path / "registry.json"

    # Create the initial registry
    registry = KeyRegistry(str(registry_path))

    registry.keys = {
        "key_001": {
            "key_id": "key_001",
            "status": "ACTIVE",
            "created_at": "2026-11-18T20:00:00+00:00",
            "updated_at": "2026-11-18T20:00:00+00:00",
            "replaced_by": None,
        }
    }

    # Save the original data
    registry.save_registry()

    # Keep a copy of the original file
    original_content = registry_path.read_bytes()

    # Modify the key status
    registry.keys["key_001"]["status"] = "REVOKED"
    registry.keys["key_001"]["updated_at"] = (
        "2026-11-18T21:00:00+00:00"
    )

    # Simulate a failure during file replacement
    with patch(
        "src.key_registry.os.replace",
        side_effect=OSError("Simulated disk error")
    ):
        with pytest.raises(
            OSError,
            match="Simulated disk error"
        ):
            registry.save_registry()

    # Verify that the original file was preserved
    assert registry_path.read_bytes() == original_content

    # Reload the registry from disk
    recovered_registry = KeyRegistry(str(registry_path))
    recovered_registry.load_registry()

    # The original ACTIVE status must remain unchanged
    assert recovered_registry.keys["key_001"]["status"] == "ACTIVE"

    # Verify that temporary files were cleaned up
    temporary_files = list(
        tmp_path.glob(".registry_*.tmp")
    )

    assert temporary_files == []

def test_registry_rejects_self_replacement(tmp_path):
    """
    Verify that a key cannot reference itself
    as its replacement.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "RETIRED",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T21:00:00+00:00",
                "replaced_by": "key_001",
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="A key cannot replace itself."
    ):
        registry.load_registry()

    assert registry.keys == {}

def test_registry_rejects_missing_replacement_key(tmp_path):
    """
    Verify that replacement references must point
    to existing registered keys.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "RETIRED",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T21:00:00+00:00",
                "replaced_by": "key_999",
            }
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="Replacement key does not exist."
    ):
        registry.load_registry()

    assert registry.keys == {}


def test_registry_rejects_circular_replacements(tmp_path):
    """
    Verify that circular key replacement chains are rejected.
    """

    registry_path = tmp_path / "registry.json"

    invalid_data = {
        "version": "1.0",
        "keys": {
            "key_001": {
                "key_id": "key_001",
                "status": "RETIRED",
                "created_at": "2026-11-18T20:00:00+00:00",
                "updated_at": "2026-11-18T21:00:00+00:00",
                "replaced_by": "key_002",
            },
            "key_002": {
                "key_id": "key_002",
                "status": "RETIRED",
                "created_at": "2026-11-18T21:00:00+00:00",
                "updated_at": "2026-11-18T22:00:00+00:00",
                "replaced_by": "key_003",
            },
            "key_003": {
                "key_id": "key_003",
                "status": "RETIRED",
                "created_at": "2026-11-18T22:00:00+00:00",
                "updated_at": "2026-11-18T23:00:00+00:00",
                "replaced_by": "key_001",
            },
        },
    }

    registry_path.write_text(
        json.dumps(invalid_data),
        encoding="utf-8",
    )

    registry = KeyRegistry(str(registry_path))

    with pytest.raises(
        ValueError,
        match="Circular key replacement detected."
    ):
        registry.load_registry()

    assert registry.keys == {}