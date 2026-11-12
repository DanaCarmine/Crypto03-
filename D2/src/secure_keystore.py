import os
import base64
import json
from pathlib import Path


from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


# Argon2id configuration
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

MEMORY_COST = 65536
ITERATIONS = 3
LANES = 4

SUPPORTED_ALGORITHMS = {
    "secp256k1",
    "Ed25519"
}

SUPPORTED_PURPOSES = {
    "decryption",
    "signing"
}

MAX_MEMORY_COST = 262144  # 256 MiB
MAX_ITERATIONS = 10
MAX_LANES = 8

def build_aad(metadata: dict) -> bytes:
    """
    Build canonical authenticated metadata.
    """
    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")

def validate_keystore(keystore: dict) -> None:
    """
    Validate the structure and cryptographic parameters
    of an encrypted keystore.
    """

    if not isinstance(keystore, dict):
        raise ValueError("Invalid keystore format.")

    required_fields = {
        "version",
        "key_id",
        "algorithm",
        "purpose",
        "kdf",
        "encryption",
        "salt",
        "nonce",
        "ciphertext"
    }

    if set(keystore.keys()) != required_fields:
        raise ValueError("Invalid keystore fields.")

    if keystore["version"] != "1.0":
        raise ValueError("Unsupported keystore version.")

    key_id = keystore["key_id"]

    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("Invalid key identifier.")

    if len(key_id) > 128:
        raise ValueError("Key identifier is too long.")

    valid_combinations = {
        ("secp256k1", "decryption"),
        ("Ed25519", "signing")
    }

    if (keystore["algorithm"], keystore["purpose"]) not in valid_combinations:
        raise ValueError("Unsupported algorithm or key purpose.")

    if keystore["encryption"] != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm.")

    kdf = keystore["kdf"]

    if not isinstance(kdf, dict):
        raise ValueError("Invalid KDF configuration.")

    if set(kdf.keys()) != {
        "name", "memory_cost", "iterations", "lanes", "length"
    }:
        raise ValueError("Invalid KDF parameters.")

    if kdf["name"] != "Argon2id" or kdf["length"] != KEY_SIZE:
        raise ValueError("Unsupported KDF.")

    for field in ("memory_cost", "iterations", "lanes", "length"):
        if type(kdf[field]) is not int:
            raise ValueError("Invalid KDF parameter type.")

    if not 65536 <= kdf["memory_cost"] <= MAX_MEMORY_COST:
        raise ValueError("Unsupported memory cost.")

    if not 1 <= kdf["iterations"] <= MAX_ITERATIONS:
        raise ValueError("Unsupported iteration count.")

    if not 1 <= kdf["lanes"] <= MAX_LANES:
        raise ValueError("Unsupported parallelism.")

    for field in ("salt", "nonce", "ciphertext"):
        if not isinstance(keystore[field], str):
            raise ValueError(f"Invalid {field} encoding.")

        try:
            base64.b64decode(keystore[field], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError(f"Invalid {field} encoding.") from exc

    salt = base64.b64decode(keystore["salt"])
    nonce = base64.b64decode(keystore["nonce"])
    ciphertext = base64.b64decode(keystore["ciphertext"])

    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt length.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Invalid nonce length.")

    if len(ciphertext) < 17:
        raise ValueError("Invalid ciphertext length.")

def validate_private_key_material(
    private_key: bytes,
    algorithm: str,
    purpose: str
) -> None:
    """
    Validate private key material and its intended purpose.
    """

    if not isinstance(private_key, bytes):
        raise ValueError("Private key must be bytes.")

    if len(private_key) != 32:
        raise ValueError("Private key must contain 32 bytes.")

    if algorithm == "secp256k1" and purpose == "decryption":
        private_value = int.from_bytes(private_key, "big")

        try:
            ec.derive_private_key(
                private_value,
                ec.SECP256K1()
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid secp256k1 private key."
            ) from exc

    elif algorithm == "Ed25519" and purpose == "signing":
        try:
            ed25519.Ed25519PrivateKey.from_private_bytes(
                private_key
            )
        except ValueError as exc:
            raise ValueError(
                "Invalid Ed25519 private key."
            ) from exc

    else:
        raise ValueError(
            "Unsupported algorithm and key purpose."
        )


def derive_key(
    password: str,
    salt: bytes,
    memory_cost: int = MEMORY_COST,
    iterations: int = ITERATIONS,
    lanes: int = LANES
) -> bytes:
    """
    Derive a 256-bit encryption key using Argon2id.
    """

    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required.")

    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError("Invalid salt.")

    if not isinstance(memory_cost, int) or isinstance(memory_cost, bool):
        raise ValueError("Invalid memory cost.")

    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise ValueError("Invalid iteration count.")

    if not isinstance(lanes, int) or isinstance(lanes, bool):
        raise ValueError("Invalid parallelism.")

    if not 65536 <= memory_cost <= MAX_MEMORY_COST:
        raise ValueError("Unsupported memory cost.")

    if not 1 <= iterations <= MAX_ITERATIONS:
        raise ValueError("Unsupported iteration count.")

    if not 1 <= lanes <= MAX_LANES:
        raise ValueError("Unsupported parallelism.")

    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost
    )

    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(
    private_key: bytes,
    password: str,
    key_id: str = "default-key",
    algorithm: str = "secp256k1",
    purpose: str = "decryption"
) -> dict:
    """
    Encrypt a private key and authenticate its metadata.
    """

    if not isinstance(private_key, bytes) or not private_key:
        raise ValueError("A valid private key is required.")

    # Validate the private key before encryption
    validate_private_key_material(
        private_key,
        algorithm,
        purpose
    )

    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError("A valid key identifier is required.")

    if len(key_id) > 128:
        raise ValueError("Key identifier is too long.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    metadata = {
        "version": "1.0",
        "key_id": key_id,
        "algorithm": algorithm,
        "purpose": purpose,
        "kdf": {
            "name": "Argon2id",
            "memory_cost": MEMORY_COST,
            "iterations": ITERATIONS,
            "lanes": LANES,
            "length": KEY_SIZE
        },
        "encryption": "AES-256-GCM"
    }

    aad = build_aad({
        **metadata,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8")
    })

    encryption_key = derive_key(password, salt)

    aesgcm = AESGCM(encryption_key)

    ciphertext = aesgcm.encrypt(
        nonce,
        private_key,
        aad
    )

    return {
        **metadata,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }

def decrypt_private_key(keystore: dict, password: str) -> bytes:
    """
    Decrypt a private key after validating and
    authenticating the keystore.
    """

    try:
        validate_keystore(keystore)

        metadata = {
            "version": keystore["version"],
            "key_id": keystore["key_id"],
            "algorithm": keystore["algorithm"],
            "purpose": keystore["purpose"],
            "kdf": keystore["kdf"],
            "encryption": keystore["encryption"],
            "salt": keystore["salt"],
            "nonce": keystore["nonce"]
        }

        aad = build_aad(metadata)

        salt = base64.b64decode(keystore["salt"], validate=True)
        nonce = base64.b64decode(keystore["nonce"], validate=True)
        ciphertext = base64.b64decode(
            keystore["ciphertext"],
            validate=True
        )

        kdf = keystore["kdf"]

        encryption_key = derive_key(
            password,
            salt,
            memory_cost=kdf["memory_cost"],
            iterations=kdf["iterations"],
            lanes=kdf["lanes"]
        )

        aesgcm = AESGCM(encryption_key)

        private_key = aesgcm.decrypt(
            nonce,
            ciphertext,
            aad
        )

        validate_private_key_material(
            private_key,
            keystore["algorithm"],
            keystore["purpose"]
        )

        return private_key

    except (InvalidTag, ValueError, KeyError, TypeError) as exc:
        raise ValueError(
            "Access denied: incorrect password or corrupted keystore."
        ) from exc

def save_encrypted_key(keystore: dict, file_path: str) -> None:
    """
    Save an encrypted private key to a JSON file.

    The file must contain only encrypted key material.
    """
    validate_keystore(keystore)

    path = Path(file_path)

    if path.exists():
        raise FileExistsError(
            "The keystore file already exists."
        )

    path.parent.mkdir(parents=True, exist_ok=True)

    # Create the file exclusively to avoid overwriting existing keys.
    with path.open("x", encoding="utf-8") as file:
        json.dump(keystore, file, indent=4)


def load_encrypted_key(file_path: str) -> dict:
    """
    Load an encrypted private key from a JSON file.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            "The keystore file does not exist."
        )

    with path.open("r", encoding="utf-8") as file:
        keystore = json.load(file)

    if not isinstance(keystore, dict):
        raise ValueError("Invalid keystore format.")

    required_fields = {
        "version",
        "key_id",
        "algorithm",
        "purpose",
        "kdf",
        "encryption",
        "salt",
        "nonce",
        "ciphertext"
    }

    if not required_fields.issubset(keystore.keys()):
        raise ValueError(
            "The keystore is missing required fields."
        )

    return keystore