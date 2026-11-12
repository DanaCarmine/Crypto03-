
import os

import pytest

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
    prompt_and_unlock_private_key,
    decrypt_file_key_with_keystore,
)


@pytest.fixture
def alice_keystore(tmp_path):
    private_key, public_key = generate_key_pair()

    password = "TestPassword123!"
    key_id = "alice-ecies-test"

    keystore = encrypt_private_key(
        private_key,
        password,
        key_id,
    )

    path = tmp_path / "alice.json"
    save_encrypted_key(keystore, str(path))

    return path, password, key_id, private_key, public_key


def test_unlock_correct_password(alice_keystore):
    path, password, key_id, private_key, _ = alice_keystore

    recovered = unlock_private_key(
        str(path),
        password,
        "secp256k1",
        "decryption",
        key_id,
    )

    assert recovered == private_key


def test_unlock_wrong_password(alice_keystore):
    path, _, key_id, _, _ = alice_keystore

    with pytest.raises(ValueError, match="Access denied"):
        unlock_private_key(
            str(path),
            "WrongPassword!",
            "secp256k1",
            "decryption",
            key_id,
        )


def test_unlock_wrong_key_id(alice_keystore):
    path, password, _, _, _ = alice_keystore

    with pytest.raises(ValueError, match="mismatch"):
        unlock_private_key(
            str(path),
            password,
            "secp256k1",
            "decryption",
            "bob-ecies-test",
        )


def test_unlock_wrong_purpose(alice_keystore):
    path, password, key_id, _, _ = alice_keystore

    with pytest.raises(ValueError, match="mismatch"):
        unlock_private_key(
            str(path),
            password,
            "secp256k1",
            "signing",
            key_id,
        )


def test_unlock_wrong_algorithm(alice_keystore):
    path, password, key_id, _, _ = alice_keystore

    with pytest.raises(ValueError, match="mismatch"):
        unlock_private_key(
            str(path),
            password,
            "Ed25519",
            "decryption",
            key_id,
        )


def test_prompt_unlock(alice_keystore, monkeypatch):
    path, password, key_id, private_key, _ = alice_keystore

    monkeypatch.setattr(
        "src.key_access.getpass",
        lambda _: password,
    )

    recovered = prompt_and_unlock_private_key(
        str(path),
        "secp256k1",
        "decryption",
        key_id,
    )

    assert recovered == private_key


def test_ecies_integration(alice_keystore):
    path, password, key_id, _, public_key = alice_keystore

    original_aes_key = os.urandom(32)

    encrypted_aes_key = encrypt_file_key(
        public_key,
        original_aes_key,
    )

    recovered_aes_key = decrypt_file_key_with_keystore(
        str(path),
        password,
        key_id,
        encrypted_aes_key,
    )

    assert recovered_aes_key == original_aes_key


def test_ecies_wrong_password(alice_keystore):
    path, _, key_id, _, public_key = alice_keystore

    encrypted_aes_key = encrypt_file_key(
        public_key,
        os.urandom(32),
    )

    with pytest.raises(ValueError, match="Access denied"):
        decrypt_file_key_with_keystore(
            str(path),
            "WrongPassword!",
            key_id,
            encrypted_aes_key,
        )


def test_ecies_wrong_private_key(alice_keystore):
    path, password, key_id, _, _ = alice_keystore

    _, bob_public_key = generate_key_pair()

    encrypted_aes_key = encrypt_file_key(
        bob_public_key,
        os.urandom(32),
    )

    with pytest.raises(ValueError):
        decrypt_file_key_with_keystore(
            str(path),
            password,
            key_id,
            encrypted_aes_key,
        )
