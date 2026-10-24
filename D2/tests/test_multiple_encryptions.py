from src.encryption import encrypt_file
from src.key_management import generate_key_pair
from src.container import load_container


def test_multiple_encryptions(tmp_path):
    """
    Verify that encrypting the same document twice
    produces different ciphertexts and nonces.
    """

    # 1. Create the original document
    original = tmp_path / "original.txt"
    original.write_text(
        "Same document content",
        encoding="utf-8"
    )

    # 2. Define output files
    encrypted1 = tmp_path / "encrypted1.vault"
    encrypted2 = tmp_path / "encrypted2.vault"

    # 3. Generate key pairs for two recipients
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    # 4. Encrypt the same document twice
    encrypt_file(
        original,
        encrypted1,
        [alice_public, bob_public]
    )

    encrypt_file(
        original,
        encrypted2,
        [alice_public, bob_public]
    )

    # 5. Load both encrypted containers
    container1 = load_container(encrypted1)
    container2 = load_container(encrypted2)

    # 6. Verify that both files were created
    assert encrypted1.exists()
    assert encrypted2.exists()

    # 7. Verify that the nonces are different
    assert container1["nonce"] != container2["nonce"]

    # 8. Verify that the ciphertexts are different
    assert container1["ciphertext"] != container2["ciphertext"]

    # 9. Verify that both containers have two recipients
    assert len(container1["recipients"]) == 2
    assert len(container2["recipients"]) == 2