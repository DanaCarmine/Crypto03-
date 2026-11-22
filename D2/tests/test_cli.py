"""
Automated tests for the Secure File Exchange CLI.
"""

from unittest.mock import patch

from main import encrypt_document


def test_encrypt_rejects_missing_file(capsys):
    """
    Verify that encryption rejects a nonexistent input file.
    """

    with patch(
        "builtins.input",
        return_value="files/nonexistent_document_12345.txt"
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: File not found." in captured.out


def test_encrypt_rejects_less_than_two_recipients(
    tmp_path, capsys
):
    """
    Verify that encryption requires at least two recipients.
    """

    # Create a temporary input file
    test_file = tmp_path / "test_document.txt"
    test_file.write_text(
        "Secure File Exchange test",
        encoding="utf-8"
    )

    # Simulate user input
    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "1"
        ]
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert (
        "ERROR: At least two recipients are required."
        in captured.out
    )

    # Verify that no encrypted file was created
    assert not test_file.with_suffix(".vault").exists()

def test_encrypt_rejects_duplicate_recipients(
    tmp_path, capsys
):
    """
    Verify that encryption rejects duplicate recipient keys.
    """

    # Create a temporary document
    test_file = tmp_path / "test_document.txt"
    test_file.write_text(
        "Testing duplicate recipients",
        encoding="utf-8"
    )

    # Create a valid compressed secp256k1 public key
    from src.key_management import generate_key_pair

    _, public_key = generate_key_pair()

    # Save the public key in a temporary file
    public_key_file = tmp_path / "recipient_public.hex"
    public_key_file.write_text(
        public_key.hex(),
        encoding="utf-8"
    )

    # Simulate two recipients using the same public key
    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "2",
            str(public_key_file),
            str(public_key_file)
        ]
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert (
        "ERROR: Duplicate recipient public key."
        in captured.out
    )

    # Verify that no encrypted file was created
    assert not test_file.with_suffix(".vault").exists()

def test_encrypt_rejects_invalid_recipient_key(
    tmp_path, capsys
):
    """
    Verify that encryption rejects an invalid recipient public key.
    """

    # Create a temporary document
    test_file = tmp_path / "test_document.txt"
    test_file.write_text(
        "Testing invalid recipient key",
        encoding="utf-8"
    )

    # Generate a valid recipient public key
    from src.key_management import generate_key_pair

    _, valid_public_key = generate_key_pair()

    valid_key_file = tmp_path / "valid_public.hex"
    valid_key_file.write_text(
        valid_public_key.hex(),
        encoding="utf-8"
    )

    # Create an invalid public key with incorrect length
    invalid_key_file = tmp_path / "invalid_public.hex"
    invalid_key_file.write_text(
        "1234567890ABCDEF",
        encoding="utf-8"
    )

    # Simulate user input
    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "2",
            str(valid_key_file),
            str(invalid_key_file)
        ]
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert (
        "ERROR: Invalid recipient public key format."
        in captured.out
    )

    # Verify that encryption was stopped
    assert not test_file.with_suffix(".vault").exists()

def test_encrypt_rejects_mismatched_signing_keys(
    tmp_path, capsys
):
    """
    Verify that encryption rejects mismatched Ed25519 keys.
    """

    from src.key_management import generate_key_pair
    from src.digital_signature import generate_signing_key_pair

    # Create a temporary document
    test_file = tmp_path / "test_document.txt"
    test_file.write_text(
        "Testing mismatched signing keys",
        encoding="utf-8"
    )

    # Generate two valid ECIES recipient public keys
    recipient_paths = []

    for i in range(2):
        _, public_key = generate_key_pair()

        key_file = tmp_path / f"recipient_{i}.hex"
        key_file.write_text(
            public_key.hex(),
            encoding="utf-8"
        )

        recipient_paths.append(key_file)

    # Generate two different Ed25519 key pairs
    signing_private_key, _ = generate_signing_key_pair()
    _, different_public_key = generate_signing_key_pair()

    # Save the incorrect signing public key
    signing_public_path = tmp_path / "wrong_signing_public.hex"
    signing_public_path.write_text(
        different_public_key.hex(),
        encoding="utf-8"
    )

    # Simulate CLI inputs and private key unlocking
    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "2",
            str(recipient_paths[0]),
            str(recipient_paths[1]),
            str(signing_public_path),
            str(tmp_path / "signing_key.json")
        ]
    ), patch(
        "main.prompt_and_unlock_private_key",
        return_value=signing_private_key
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert (
        "ERROR: Signing public key does not match "
        "the private key."
        in captured.out
    )

    # Verify that no encrypted file was created
    assert not test_file.with_suffix(".vault").exists()

def test_generate_keys_prevents_overwriting(
    tmp_path, monkeypatch, capsys
):
    """
    Verify that existing private keys cannot be overwritten.
    """

    from main import generate_keys

    monkeypatch.chdir(tmp_path)

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()

    existing_key = keys_dir / "encryption_key.json"
    existing_key.write_text("existing key", encoding="utf-8")

    with patch("main.getpass") as mock_password:
        generate_keys()

    captured = capsys.readouterr()

    assert "ERROR: Key files already exist." in captured.out
    assert "Existing keys will not be overwritten." in captured.out

    assert existing_key.read_text(encoding="utf-8") == "existing key"
    mock_password.assert_not_called()


def test_export_public_keys_rejects_missing_keystores(
    tmp_path, monkeypatch, capsys
):
    """
    Verify that public keys cannot be exported
    when encrypted private keys are missing.
    """

    from main import export_public_keys

    monkeypatch.chdir(tmp_path)

    export_public_keys()

    captured = capsys.readouterr()

    assert (
        "ERROR: Encrypted keystores were not found."
        in captured.out
    )

    assert not (tmp_path / "public_keys").exists()

def test_encrypt_prevents_overwriting(
    tmp_path, capsys
):
    """
    Verify that existing encrypted files are not overwritten.
    """

    test_file = tmp_path / "document.txt"
    test_file.write_text("Original document", encoding="utf-8")

    vault_file = tmp_path / "document.vault"
    vault_file.write_text("Existing vault", encoding="utf-8")

    with patch(
        "builtins.input",
        return_value=str(test_file)
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: Encrypted file already exists." in captured.out

    assert vault_file.read_text(encoding="utf-8") == "Existing vault"


def test_encrypt_rejects_invalid_signing_public_key(
    tmp_path, capsys
):
    """
    Verify that encryption rejects an Ed25519
    public key with an incorrect length.
    """

    from src.key_management import generate_key_pair

    test_file = tmp_path / "document.txt"
    test_file.write_text("Test document", encoding="utf-8")

    recipient_paths = []

    for i in range(2):
        _, public_key = generate_key_pair()

        key_path = tmp_path / f"recipient_{i}.hex"
        key_path.write_text(public_key.hex(), encoding="utf-8")

        recipient_paths.append(key_path)

    invalid_signing_key = tmp_path / "invalid_signing.hex"
    invalid_signing_key.write_text("1234567890", encoding="utf-8")

    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "2",
            str(recipient_paths[0]),
            str(recipient_paths[1]),
            str(invalid_signing_key)
        ]
    ):
        encrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: Invalid Ed25519 public key length." in captured.out

    assert not test_file.with_suffix(".vault").exists()


def test_encrypt_successful_execution(
    tmp_path, capsys
):
    """
    Verify that the CLI calls the encryption module
    when valid keys are provided.
    """

    from src.key_management import generate_key_pair
    from src.digital_signature import generate_signing_key_pair

    test_file = tmp_path / "document.txt"
    test_file.write_text("Secure document", encoding="utf-8")

    recipient_paths = []

    for i in range(2):
        _, public_key = generate_key_pair()

        key_path = tmp_path / f"recipient_{i}.hex"
        key_path.write_text(public_key.hex(), encoding="utf-8")

        recipient_paths.append(key_path)

    signing_private_key, signing_public_key = (
        generate_signing_key_pair()
    )

    signing_public_path = tmp_path / "signing_public.hex"
    signing_public_path.write_text(
        signing_public_key.hex(),
        encoding="utf-8"
    )

    with patch(
        "builtins.input",
        side_effect=[
            str(test_file),
            "2",
            str(recipient_paths[0]),
            str(recipient_paths[1]),
            str(signing_public_path),
            str(tmp_path / "signing_key.json")
        ]
    ), patch(
        "main.prompt_and_unlock_private_key",
        return_value=signing_private_key
    ), patch(
        "main.encrypt_file"
    ) as mock_encrypt:

        encrypt_document()

    captured = capsys.readouterr()

    assert "Document encrypted successfully!" in captured.out

    mock_encrypt.assert_called_once()

    assert mock_encrypt.call_args.kwargs["file_path"] == str(test_file)
    assert len(
        mock_encrypt.call_args.kwargs["recipient_public_keys"]
    ) == 2

def test_decrypt_rejects_missing_container(
    tmp_path, capsys
):
    """
    Verify that decryption rejects nonexistent containers.
    """

    from main import decrypt_document

    missing_file = tmp_path / "missing.vault"

    with patch(
        "builtins.input",
        return_value=str(missing_file)
    ):
        decrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: Encrypted file not found." in captured.out


def test_decrypt_prevents_overwriting(
    tmp_path, capsys
):
    """
    Verify that decryption cannot overwrite an existing file.
    """

    from main import decrypt_document

    container = tmp_path / "document.vault"
    container.write_text("Test container", encoding="utf-8")

    output = tmp_path / "document.txt"
    output.write_text("Original content", encoding="utf-8")

    with patch(
        "builtins.input",
        side_effect=[
            str(container),
            str(output)
        ]
    ):
        decrypt_document()

    captured = capsys.readouterr()

    assert (
        "ERROR: Invalid output path or file already exists."
        in captured.out
    )

    assert output.read_text(encoding="utf-8") == "Original content"


def test_decrypt_rejects_invalid_signing_public_key(
    tmp_path, capsys
):
    """
    Verify that decryption rejects malformed hexadecimal
    signing public keys.
    """

    from main import decrypt_document

    container = tmp_path / "document.vault"
    container.write_text("Test container", encoding="utf-8")

    output = tmp_path / "decrypted.txt"

    signing_key = tmp_path / "invalid_signing.hex"
    signing_key.write_text("INVALID_HEX", encoding="utf-8")

    with patch(
        "builtins.input",
        side_effect=[
            str(container),
            str(output),
            str(tmp_path / "encryption_key.json"),
            str(signing_key)
        ]
    ):
        decrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: Could not load signing public key:" in captured.out

    assert not output.exists()


def test_decrypt_successful_execution(
    tmp_path, capsys
):
    """
    Verify that the CLI invokes the decryption module
    with the expected parameters.
    """

    from main import decrypt_document
    from src.digital_signature import generate_signing_key_pair
    from src.key_management import generate_key_pair

    container = tmp_path / "document.vault"
    container.write_text("Mock container", encoding="utf-8")

    output = tmp_path / "decrypted.txt"

    private_key, _ = generate_key_pair()
    _, signing_public_key = generate_signing_key_pair()

    signing_key_path = tmp_path / "signing_public.hex"
    signing_key_path.write_text(
        signing_public_key.hex(),
        encoding="utf-8"
    )

    with patch(
        "builtins.input",
        side_effect=[
            str(container),
            str(output),
            str(tmp_path / "encryption_key.json"),
            str(signing_key_path)
        ]
    ), patch(
        "main.prompt_and_unlock_private_key",
        return_value=private_key
    ), patch(
        "main.decrypt_file",
        return_value=True
    ) as mock_decrypt:

        decrypt_document()

    captured = capsys.readouterr()

    assert (
        "Document verified and decrypted successfully!"
        in captured.out
    )

    mock_decrypt.assert_called_once()

    assert (
        mock_decrypt.call_args.kwargs["container_path"]
        == str(container)
    )

    assert (
        mock_decrypt.call_args.kwargs["output_path"]
        == str(output)
    )


def test_decrypt_handles_failed_verification(
    tmp_path, capsys
):
    """
    Verify that the CLI reports a failed decryption.
    """

    from main import decrypt_document
    from src.digital_signature import generate_signing_key_pair
    from src.key_management import generate_key_pair

    container = tmp_path / "document.vault"
    container.write_text("Mock container", encoding="utf-8")

    output = tmp_path / "decrypted.txt"

    private_key, _ = generate_key_pair()
    _, signing_public_key = generate_signing_key_pair()

    signing_key_path = tmp_path / "signing_public.hex"
    signing_key_path.write_text(
        signing_public_key.hex(),
        encoding="utf-8"
    )

    with patch(
        "builtins.input",
        side_effect=[
            str(container),
            str(output),
            str(tmp_path / "encryption_key.json"),
            str(signing_key_path)
        ]
    ), patch(
        "main.prompt_and_unlock_private_key",
        return_value=private_key
    ), patch(
        "main.decrypt_file",
        return_value=False
    ):

        decrypt_document()

    captured = capsys.readouterr()

    assert "ERROR: Document could not be decrypted." in captured.out

    assert not output.exists()