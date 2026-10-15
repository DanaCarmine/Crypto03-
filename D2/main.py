from src.encryption import encrypt_file
from src.decryption import decrypt_file

# Encrypt the original document
encrypt_file(
    "files/documento.txt",
    "files/documento.vault",
    "files/documento.key"
)

# Decrypt the encrypted document
decrypt_file(
    "files/documento.vault",
    "files/documento.key",
    "files/documento_recuperado.txt"
)