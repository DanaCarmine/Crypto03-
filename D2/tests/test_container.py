import copy

import pytest

from src.container import (
    canonical_json,
    build_aad,
    create_container,
    save_container,
    load_container,
)


@pytest.fixture
def vault_data():
    """Create sample data for container tests."""

    metadata = {
        "filename": "document.pdf",
        "algorithm": "AES-256-GCM",
        "key_encryption": "ECIES-secp256k1",
        "version": "3.0",
    }

    recipients = [
    {
        "id": "a" * 64,
        "encrypted_key": "encrypted_key_alice",
    },
    {
        "id": "b" * 64,
        "encrypted_key": "encrypted_key_bob",
    },
]

    nonce = b"123456789012"
    ciphertext = b"encrypted_document_data"

    return metadata, recipients, nonce, ciphertext


# TEST 1: Canonical JSON
def test_canonical_json():
    """Verify that dictionary key order does not affect serialization."""

    data1 = {"b": 2, "a": 1}
    data2 = {"a": 1, "b": 2}

    assert canonical_json(data1) == canonical_json(data2)


# TEST 2: AAD includes recipients
def test_build_aad(vault_data):
    """Verify that AAD includes metadata and all recipients."""

    metadata, recipients, _, _ = vault_data

    aad = build_aad(metadata, recipients)

    assert b"metadata" in aad
    assert b"recipients" in aad
    assert b"a" * 64 in aad
    assert b"b" * 64 in aad


# TEST 3: AAD changes when recipients are modified
def test_modified_recipients_change_aad(vault_data):
    """Verify that modifying recipients changes the AAD."""

    metadata, recipients, _, _ = vault_data

    original_aad = build_aad(metadata, recipients)

    modified_recipients = copy.deepcopy(recipients)
    modified_recipients[0]["encrypted_key"] = "modified_key"

    modified_aad = build_aad(metadata, modified_recipients)

    assert original_aad != modified_aad


# TEST 4: Create container
def test_create_container(vault_data):
    """Verify that a container contains the required fields."""

    metadata, recipients, nonce, ciphertext = vault_data

    container = create_container(
        metadata,
        recipients,
        nonce,
        ciphertext,
    )

    assert set(container.keys()) == {
        "metadata",
        "recipients",
        "nonce",
        "ciphertext",
    }

    assert len(container["recipients"]) == 2
    assert container["nonce"] == nonce.hex()
    assert container["ciphertext"] == ciphertext.hex()


# TEST 5: Reject fewer than two recipients
def test_insufficient_recipients(vault_data):
    """Verify that at least two recipients are required."""

    metadata, recipients, nonce, ciphertext = vault_data

    with pytest.raises(ValueError):
        create_container(
            metadata,
            recipients[:1],
            nonce,
            ciphertext,
        )


# TEST 6: Reject duplicate recipients
def test_duplicate_recipients(vault_data):
    """Verify that duplicate recipient IDs are rejected."""

    metadata, recipients, nonce, ciphertext = vault_data

    duplicate_recipients = [
        recipients[0],
        recipients[0],
    ]

    with pytest.raises(ValueError):
        create_container(
            metadata,
            duplicate_recipients,
            nonce,
            ciphertext,
        )


# TEST 7: Reject invalid nonce
def test_invalid_nonce(vault_data):
    """Verify that AES-GCM requires a 12-byte nonce."""

    metadata, recipients, _, ciphertext = vault_data

    with pytest.raises(ValueError):
        create_container(
            metadata,
            recipients,
            b"short",
            ciphertext,
        )


# TEST 8: Save and load container
def test_save_and_load_container(vault_data, tmp_path):
    """Verify that saving and loading preserves the container."""

    metadata, recipients, nonce, ciphertext = vault_data

    container = create_container(
        metadata,
        recipients,
        nonce,
        ciphertext
    )

    file_path = tmp_path / "document.vault"

    # Save the container
    save_container(container, file_path)

    # Load the container
    loaded_container = load_container(file_path)

    # Verify that the loaded data matches the original
    assert loaded_container == container

    # TEST 9: Reject invalid container structure
def test_invalid_container_structure(tmp_path):
    """Verify that containers with missing fields are rejected."""

    file_path = tmp_path / "invalid.vault"

    file_path.write_text(
        '{"metadata": {}, "nonce": "123"}',
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_container(file_path)

    # TEST 10: Reject invalid recipient fingerprint
def test_invalid_recipient_fingerprint(vault_data):
    """Verify that invalid recipient fingerprints are rejected."""

    metadata, recipients, nonce, ciphertext = vault_data

    recipients[0]["id"] = "invalid_fingerprint"

    with pytest.raises(ValueError):
        create_container(
            metadata,
            recipients,
            nonce,
            ciphertext,
        )

# TEST 11: Reject invalid nonce when loading a vault
def test_load_invalid_nonce(vault_data, tmp_path):
    """Verify that loading rejects an invalid AES-GCM nonce."""

    metadata, recipients, _, ciphertext = vault_data

    file_path = tmp_path / "invalid_nonce.vault"

    container = {
        "metadata": metadata,
        "recipients": recipients,
        "nonce": "1234",
        "ciphertext": ciphertext.hex()
    }

    save_container(container, file_path)

    with pytest.raises(ValueError):
        load_container(file_path)


# TEST 12: Reject invalid recipient fingerprint when loading
def test_load_invalid_recipient(vault_data, tmp_path):
    """Verify that loading rejects an invalid recipient fingerprint."""

    metadata, recipients, nonce, ciphertext = vault_data

    recipients[0]["id"] = "invalid_id"

    file_path = tmp_path / "invalid_recipient.vault"

    container = {
        "metadata": metadata,
        "recipients": recipients,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    save_container(container, file_path)

    with pytest.raises(ValueError):
        load_container(file_path)