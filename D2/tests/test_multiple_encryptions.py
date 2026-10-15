import json

from src.encryption import encrypt_file


def test_multiple_encryptions(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("Same document content", encoding="utf-8")

    encrypted1 = tmp_path / "encrypted1.vault"
    encrypted2 = tmp_path / "encrypted2.vault"

    key1 = tmp_path / "secret1.key"
    key2 = tmp_path / "secret2.key"

    # Encrypt the same file twice
    encrypt_file(original, encrypted1, key1)
    encrypt_file(original, encrypted2, key2)

    # Read both encrypted containers
    with open(encrypted1, "r", encoding="utf-8") as file:
        container1 = json.load(file)

    with open(encrypted2, "r", encoding="utf-8") as file:
        container2 = json.load(file)

    # Compare the encryption results
    different_ciphertexts = (
        container1["ciphertext"] != container2["ciphertext"]
    )

    different_nonces = (
        container1["nonce"] != container2["nonce"]
    )

    different_keys = (
        key1.read_bytes() != key2.read_bytes()
    )

    print("Different ciphertexts:", different_ciphertexts)
    print("Different nonces:", different_nonces)
    print("Different keys:", different_keys)

    assert different_ciphertexts
    assert different_nonces
    assert different_keys