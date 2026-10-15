import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def decrypt_file(container_path, key_path, output_path):
    with open(container_path, "r", encoding="utf-8") as file:
        container = json.load(file)

    with open(key_path, "rb") as file:
        key = file.read()

    metadata = container["metadata"]
    aad = json.dumps(metadata, sort_keys=True).encode("utf-8")

    nonce = bytes.fromhex(container["nonce"])
    ciphertext = bytes.fromhex(container["ciphertext"])

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    except InvalidTag:
        print("ERROR: Authentication failed!")
        print("The key is incorrect or the file was modified.")
        return False

    with open(output_path, "xb") as file:
        file.write(plaintext)

    print("File decrypted successfully!")
    return True