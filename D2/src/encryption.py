import os
import json

from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(file_path, output_path, key_path):

    # 1. Leer el archivo original
    file_path = Path(file_path)

    with open(file_path, "rb") as file:
        plaintext = file.read()

    # 2. Generar una nueva clave AES de 256 bits
    key = AESGCM.generate_key(bit_length=256)

    # 3. Generar un nonce aleatorio de 96 bits
    nonce = os.urandom(12)

    # 4. Definir los metadatos del archivo
    metadata = {
        "filename": file_path.name,
        "algorithm": "AES-256-GCM",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    # 5. Convertir los metadatos a bytes para usarlos como AAD
    aad = json.dumps(
        metadata,
        sort_keys=True
    ).encode("utf-8")

    # 6. Crear el objeto AES-GCM
    aesgcm = AESGCM(key)

    # 7. Cifrar el contenido del archivo
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 8. Crear el contenedor cifrado
    container = {
        "metadata": metadata,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

    # 9. Guardar el contenedor cifrado
    with open(output_path, "x", encoding="utf-8") as file:
        json.dump(container, file, indent=4)

    # 10. Guardar la clave en un archivo independiente
    with open(key_path, "xb") as file:
        file.write(key)

    print("File encrypted successfully!")
