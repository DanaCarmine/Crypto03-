"""Integration tests for KeyLifecycleManager and KeyRegistry."""

import json

from src.key_registry import KeyRegistry
from src.key_lifecycle import KeyLifecycleManager


def test_lifecycle_registry_integration(tmp_path):
    """Verify registration, persistence, rotation and revocation."""

    registry_path = tmp_path / "registry.json"

    # TEST 1: Register a new key
    registry = KeyRegistry(str(registry_path))
    manager = KeyLifecycleManager(registry)

    manager.register_key("daniela-key-001")

    assert manager.is_active("daniela-key-001")
    assert registry_path.exists()

    # TEST 2: Simulate an application restart
    new_registry = KeyRegistry(str(registry_path))
    manager = KeyLifecycleManager(new_registry)

    assert manager.is_active("daniela-key-001")

    # TEST 3: Rotate the key
    manager.rotate_key("daniela-key-001", "daniela-key-002")

    old_key = manager.get_key("daniela-key-001")
    new_key = manager.get_key("daniela-key-002")

    assert old_key["status"] == "RETIRED"
    assert old_key["replaced_by"] == "daniela-key-002"
    assert new_key["status"] == "ACTIVE"

    # TEST 4: Revoke the replacement key
    manager.revoke_key("daniela-key-002")

    assert manager.get_key("daniela-key-002")["status"] == "REVOKED"

    # TEST 5: Verify persistence after another restart
    final_registry = KeyRegistry(str(registry_path))
    final_manager = KeyLifecycleManager(final_registry)

    assert final_manager.get_key("daniela-key-001")["status"] == "RETIRED"
    assert final_manager.get_key("daniela-key-002")["status"] == "REVOKED"

    # TEST 6: Verify registry contains only expected metadata
    registry_data = json.loads(
        registry_path.read_text(encoding="utf-8")
    )

    assert registry_data["version"] == "1.0"

    expected_fields = {
        "key_id",
        "status",
        "created_at",
        "updated_at",
        "replaced_by",
    }

    for key_data in registry_data["keys"].values():
        assert set(key_data.keys()) == expected_fields