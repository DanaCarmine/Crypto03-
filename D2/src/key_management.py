import hashlib
from ecies.keys import PrivateKey
from ecies import encrypt, decrypt

def generate_key_pair():
    """
    Generate an ECIES public/private key pair using secp256k1.

    Returns:
        tuple: (private_key, public_key) as bytes.
    """
    key_pair = PrivateKey("secp256k1")

    private_key = key_pair.secret
    public_key = key_pair.public_key.to_bytes(True)

    return private_key, public_key


def get_key_fingerprint(public_key):
    """
    Generate a SHA-256 fingerprint for a public key.

    Args:
        public_key (bytes): Compressed public key.

    Returns:
        str: SHA-256 fingerprint in hexadecimal format.
    """
    return hashlib.sha256(public_key).hexdigest()

def encrypt_file_key(public_key, file_key):
    """
    Encrypt an AES file key using the recipient's ECIES public key.

    Args:
        public_key (bytes): Recipient's compressed public key.
        file_key (bytes): 256-bit AES key to encrypt.

    Returns:
        bytes: Encrypted AES key.
    """
    if len(file_key) != 32:
        raise ValueError("The AES file key must be 32 bytes.")

    encrypted_key = encrypt(public_key, file_key)

    return encrypted_key


def decrypt_file_key(private_key, encrypted_key):
    """
    Recover an AES file key using the recipient's ECIES private key.

    Args:
        private_key (bytes): Recipient's private key.
        encrypted_key (bytes): ECIES-encrypted AES key.

    Returns:
        bytes: Recovered AES key.
    """
    file_key = decrypt(private_key, encrypted_key)

    if len(file_key) != 32:
        raise ValueError("Invalid recovered AES key length.")

    return file_key