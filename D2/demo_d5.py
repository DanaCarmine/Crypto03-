"""
D5 - Secure Digital Document Vault
End-to-end demonstration.

This demo shows:
1. Key generation
2. Encryption and digital signing
3. Authorized decryption
4. Unauthorized recipient rejection
5. Tampered signature rejection
6. Untrusted signer rejection
7. Legacy D3 container rejection
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from src.key_management import generate_key_pair
from src.digital_signature import generate_signing_key_pair
from src.encryption import encrypt_file, encrypt_file_legacy
from src.decryption import decrypt_file


def show_step(number, description):
    print(f"\n[{number}] {description}")
    print("-" * 55)


def check_result(condition, description):
    if condition:
        print(f"[PASS] {description}")
    else:
        print(f"[FAIL] {description}")

    return condition


def run_demo():
    print("=" * 60)
    print("       SECURE DIGITAL DOCUMENT VAULT - D5 DEMO")
    print("=" * 60)

    results = []

    # Use a temporary directory to avoid leaving test files
    with TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)

        # STEP 1: Generate recipient keys
        show_step(1, "Generating recipient keys")

        alice_private, alice_public = generate_key_pair()
        bob_private, bob_public = generate_key_pair()
        eve_private, _ = generate_key_pair()

        print("[OK] Alice, Bob and Eve key pairs generated.")

        # STEP 2: Generate signing keys
        show_step(2, "Generating Ed25519 signing keys")

        signer_private, signer_public = generate_signing_key_pair()

        print("[OK] Sender signing key pair generated.")

        # STEP 3: Create the original document
        show_step(3, "Creating the original document")

        original = folder / "confidential_document.txt"

        original.write_text(
            "This is a confidential document protected by D5.",
            encoding="utf-8"
        )

        original_content = original.read_bytes()

        print("[OK] Original document created.")

        # STEP 4: Encrypt and sign
        show_step(4, "Encrypting and signing the document")

        encrypted = folder / "document.vault"

        encrypt_file(
            original,
            encrypted,
            [alice_public, bob_public],
            signer_private,
            signer_public
        )

        results.append(
            check_result(
                encrypted.exists(),
                "Signed D5 vault was created"
            )
        )

        # STEP 5: Alice decrypts
        show_step(5, "Alice decrypts the signed document")

        alice_output = folder / "alice_output.txt"

        alice_result = decrypt_file(
            encrypted,
            alice_private,
            alice_output,
            signer_public
        )

        results.append(
            check_result(
                alice_result is True
                and alice_output.exists()
                and alice_output.read_bytes() == original_content,
                "Alice successfully recovered the original document"
            )
        )

        # STEP 6: Bob decrypts
        show_step(6, "Bob decrypts the signed document")

        bob_output = folder / "bob_output.txt"

        bob_result = decrypt_file(
            encrypted,
            bob_private,
            bob_output,
            signer_public
        )

        results.append(
            check_result(
                bob_result is True
                and bob_output.exists()
                and bob_output.read_bytes() == original_content,
                "Bob successfully recovered the original document"
            )
        )

        # STEP 7: Unauthorized recipient
        show_step(7, "Unauthorized recipient attempt")

        eve_output = folder / "eve_output.txt"

        eve_result = decrypt_file(
            encrypted,
            eve_private,
            eve_output,
            signer_public
        )

        results.append(
            check_result(
                eve_result is False and not eve_output.exists(),
                "Unauthorized recipient was rejected"
            )
        )

        # STEP 8: Tamper with the digital signature
        show_step(8, "Testing a modified digital signature")

        with encrypted.open("r", encoding="utf-8") as file:
            container = json.load(file)

        signature = container["signature"]

        container["signature"] = (
            ("0" if signature[0] != "0" else "1")
            + signature[1:]
        )

        tampered = folder / "tampered.vault"

        with tampered.open("w", encoding="utf-8") as file:
            json.dump(container, file)

        tampered_output = folder / "tampered_output.txt"

        tampered_result = decrypt_file(
            tampered,
            alice_private,
            tampered_output,
            signer_public
        )

        results.append(
            check_result(
                tampered_result is False
                and not tampered_output.exists(),
                "Modified digital signature was rejected"
            )
        )

        # STEP 9: Untrusted signer
        show_step(9, "Testing an untrusted signer")

        _, wrong_signer_public = generate_signing_key_pair()

        untrusted_output = folder / "untrusted_output.txt"

        untrusted_result = decrypt_file(
            encrypted,
            alice_private,
            untrusted_output,
            wrong_signer_public
        )

        results.append(
            check_result(
                untrusted_result is False
                and not untrusted_output.exists(),
                "Untrusted signer was rejected"
            )
        )

        # STEP 10: Reject unsigned D3 container
        show_step(10, "Testing an unsigned legacy D3 container")

        legacy = folder / "legacy.vault"

        encrypt_file_legacy(
            original,
            legacy,
            [alice_public, bob_public]
        )

        legacy_output = folder / "legacy_output.txt"

        legacy_result = decrypt_file(
            legacy,
            alice_private,
            legacy_output,
            signer_public
        )

        results.append(
            check_result(
                legacy_result is False
                and not legacy_output.exists(),
                "Unsigned D3 container was rejected by D5"
            )
        )

    # FINAL SUMMARY
    print("\n" + "=" * 60)
    print("                  DEMO RESULTS")
    print("=" * 60)

    passed = sum(results)
    total = len(results)

    print(f"Passed: {passed}/{total}")

    if all(results):
        print("[SUCCESS] All D5 demonstration scenarios passed!")
    else:
        print("[WARNING] Some demonstration scenarios failed.")

    print("=" * 60)

    return all(results)


if __name__ == "__main__":
    success = run_demo()
    raise SystemExit(0 if success else 1)