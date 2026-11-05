import copy
import json
import pytest

from src.container import (
    build_signature_payload,
    create_container,
    load_container,
    save_container,
)


@pytest.fixture
def valid_d5_container():
    """Create a valid D5 container for testing."""

    metadata = {
        "filename": "document.txt",
        "algorithm": "AES-256-GCM",
        "key_encryption": "ECIES-secp256k1",
        "signature_algorithm": "Ed25519",
        "version": "5.0",
    }

    recipients = [
        {"id": "a" * 64, "encrypted_key": "abcd1234"},
        {"id": "b" * 64, "encrypted_key": "efgh5678"},
    ]

    container = create_container(
        metadata,
        recipients,
        b"\x01" * 12,
        b"\x02" * 32,
    )

    container["signer_id"] = "c" * 64
    container["signature"] = "d" * 128

    return container


def test_save_and_load_d5_container(valid_d5_container, tmp_path):
    """A complete D5 container can be saved and loaded."""

    path = tmp_path / "document.vault"

    save_container(valid_d5_container, path)
    loaded = load_container(path)

    assert loaded == valid_d5_container


def test_missing_signature_rejected(valid_d5_container, tmp_path):
    """D5 containers without signatures must be rejected."""

    container = copy.deepcopy(valid_d5_container)
    del container["signature"]

    with pytest.raises(ValueError):
        save_container(container, tmp_path / "document.vault")


def test_missing_signer_id_rejected(valid_d5_container, tmp_path):
    """D5 containers without signer IDs must be rejected."""

    container = copy.deepcopy(valid_d5_container)
    del container["signer_id"]

    with pytest.raises(ValueError):
        save_container(container, tmp_path / "document.vault")


@pytest.mark.parametrize(
    "invalid_signature",
    ["", "abc", "z" * 128, "a" * 126, None],
)
def test_invalid_signature_rejected(
    valid_d5_container, tmp_path, invalid_signature
):
    """Reject malformed Ed25519 signatures."""

    container = copy.deepcopy(valid_d5_container)
    container["signature"] = invalid_signature

    with pytest.raises(ValueError):
        save_container(container, tmp_path / "document.vault")


@pytest.mark.parametrize(
    "invalid_signer_id",
    ["", "abc", "z" * 64, "a" * 62, None],
)
def test_invalid_signer_id_rejected(
    valid_d5_container, tmp_path, invalid_signer_id
):
    """Reject malformed signer fingerprints."""

    container = copy.deepcopy(valid_d5_container)
    container["signer_id"] = invalid_signer_id

    with pytest.raises(ValueError):
        save_container(container, tmp_path / "document.vault")


def test_signature_payload_is_deterministic(valid_d5_container):
    """Dictionary key order must not affect the signed bytes."""

    container_a = copy.deepcopy(valid_d5_container)
    container_b = dict(reversed(list(container_a.items())))

    assert build_signature_payload(container_a) == (
        build_signature_payload(container_b)
    )


def test_signature_not_in_payload(valid_d5_container):
    """The signature itself must not be included in signed data."""

    payload = build_signature_payload(valid_d5_container)
    decoded = json.loads(payload.decode("utf-8"))

    assert "signature" not in decoded
    assert set(decoded) == {
        "metadata",
        "recipients",
        "nonce",
        "ciphertext",
        "signer_id",
    }


@pytest.mark.parametrize(
    "field",
    ["metadata", "recipients", "nonce", "ciphertext", "signer_id"],
)
def test_all_security_fields_are_signed(valid_d5_container, field):
    """Changing any protected field must change the signed payload."""

    modified = copy.deepcopy(valid_d5_container)

    if field == "metadata":
        modified["metadata"]["filename"] = "modified.txt"
    elif field == "recipients":
        modified["recipients"][0]["encrypted_key"] = "changed"
    elif field == "nonce":
        modified["nonce"] = "ff" * 12
    elif field == "ciphertext":
        modified["ciphertext"] = "ff" * 32
    else:
        modified["signer_id"] = "e" * 64

    assert build_signature_payload(modified) != (
        build_signature_payload(valid_d5_container)
    )


def test_load_rejects_missing_signature(valid_d5_container, tmp_path):
    """Loading an incomplete D5 container must fail."""

    container = copy.deepcopy(valid_d5_container)
    del container["signature"]

    path = tmp_path / "document.vault"
    path.write_text(json.dumps(container), encoding="utf-8")

    with pytest.raises(ValueError):
        load_container(path)


def test_load_rejects_invalid_signature(valid_d5_container, tmp_path):
    """Loading a malformed signature must fail."""

    container = copy.deepcopy(valid_d5_container)
    container["signature"] = "invalid"

    path = tmp_path / "document.vault"
    path.write_text(json.dumps(container), encoding="utf-8")

    with pytest.raises(ValueError):
        load_container(path)


def test_d3_backward_compatibility(tmp_path):
    """Existing D3 containers must remain readable."""

    metadata = {
        "filename": "legacy.txt",
        "version": "3.0",
        "algorithm": "AES-256-GCM",
    }

    recipients = [
        {"id": "a" * 64, "encrypted_key": "abcd"},
        {"id": "b" * 64, "encrypted_key": "efgh"},
    ]

    container = create_container(
        metadata,
        recipients,
        b"\x01" * 12,
        b"\x02" * 32,
    )

    path = tmp_path / "legacy.vault"

    save_container(container, path)

    assert load_container(path) == container


def test_unsupported_version_rejected(valid_d5_container, tmp_path):
    """Unsupported container versions must be rejected."""

    container = copy.deepcopy(valid_d5_container)
    container["metadata"]["version"] = "9.0"

    with pytest.raises(ValueError):
        save_container(container, tmp_path / "document.vault")