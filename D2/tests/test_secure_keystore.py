import copy

import pytest

from src.key_management import generate_key_pair
from src.digital_signature import generate_signing_key_pair

from src.secure_keystore import (
    encrypt_private_key,
    decrypt_private_key,
    save_encrypted_key,
    load_encrypted_key,
)


TEST_PASSWORD = "StrongPassword123!"


def test_ecies_private_key_encryption():
    """
    A secp256k1 private key can be encrypted and recovered.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
        "alice-ecies-001",
        "secp256k1",
        "decryption",
    )

    recovered = decrypt_private_key(
        keystore,
        TEST_PASSWORD,
    )

    assert recovered == private_key


def test_ed25519_private_key_encryption():
    """
    An Ed25519 private key can be encrypted and recovered.
    """
    private_key, _ = generate_signing_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
        "alice-signing-001",
        "Ed25519",
        "signing",
    )

    recovered = decrypt_private_key(
        keystore,
        TEST_PASSWORD,
    )

    assert recovered == private_key


def test_wrong_password():
    """
    An incorrect password must not unlock the private key.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    with pytest.raises(ValueError):
        decrypt_private_key(
            keystore,
            "WrongPassword123!",
        )


def test_modified_key_id():
    """
    Modified authenticated metadata must be rejected.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
        "alice-001",
    )

    modified = copy.deepcopy(keystore)
    modified["key_id"] = "eve-001"

    with pytest.raises(ValueError):
        decrypt_private_key(
            modified,
            TEST_PASSWORD,
        )


def test_modified_kdf_parameters():
    """
    Modified Argon2id parameters must be rejected.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    modified = copy.deepcopy(keystore)
    modified["kdf"]["iterations"] = 4

    with pytest.raises(ValueError):
        decrypt_private_key(
            modified,
            TEST_PASSWORD,
        )


def test_excessive_memory_cost():
    """
    Excessive KDF memory requirements must be rejected.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    modified = copy.deepcopy(keystore)
    modified["kdf"]["memory_cost"] = 999999999

    with pytest.raises(ValueError):
        decrypt_private_key(
            modified,
            TEST_PASSWORD,
        )


def test_modified_ciphertext():
    """
    Modified ciphertext must fail authentication.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    modified = copy.deepcopy(keystore)
    modified["ciphertext"] = "AAAA"

    with pytest.raises(ValueError):
        decrypt_private_key(
            modified,
            TEST_PASSWORD,
        )


def test_save_and_load_keystore(tmp_path):
    """
    An encrypted keystore can be saved and loaded.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    file_path = tmp_path / "alice.json"

    save_encrypted_key(
        keystore,
        str(file_path),
    )

    loaded = load_encrypted_key(
        str(file_path),
    )

    recovered = decrypt_private_key(
        loaded,
        TEST_PASSWORD,
    )

    assert recovered == private_key


def test_prevent_keystore_overwrite(tmp_path):
    """
    Existing keystore files must not be overwritten.
    """
    private_key, _ = generate_key_pair()

    keystore = encrypt_private_key(
        private_key,
        TEST_PASSWORD,
    )

    file_path = tmp_path / "alice.json"

    save_encrypted_key(
        keystore,
        str(file_path),
    )

    with pytest.raises(FileExistsError):
        save_encrypted_key(
            keystore,
            str(file_path),
        )


def test_invalid_private_key_length():
    """
    Invalid private key sizes must be rejected.
    """
    with pytest.raises(ValueError):
        encrypt_private_key(
            b"invalid-key",
            TEST_PASSWORD,
        )


def test_invalid_key_purpose():
    """
    Unsupported algorithm-purpose combinations are rejected.
    """
    private_key, _ = generate_key_pair()

    with pytest.raises(ValueError):
        encrypt_private_key(
            private_key,
            TEST_PASSWORD,
            algorithm="secp256k1",
            purpose="signing",
        )