import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag


class CryptoUtils:
    @staticmethod
    def encrypt(data: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key length. Must be 16, 24, or 32 bytes.")

        nonce = secrets.token_bytes(12)
        cipher = AESGCM(key)
        ct = cipher.encrypt(nonce, data, associated_data)
        return nonce + ct

    @staticmethod
    def decrypt(encrypted: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key length. Must be 16, 24, or 32 bytes.")

        if len(encrypted) < 12:
            raise ValueError("Ciphertext too short")

        nonce = encrypted[:12]
        ct = encrypted[12:]
        cipher = AESGCM(key)
        try:
            return cipher.decrypt(nonce, ct, associated_data)
        except InvalidTag:
            raise InvalidTag("Authentication failed")

    @staticmethod
    def derive_key(input_key: bytes, salt: bytes = None, info: bytes = b'session_key') -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(input_key)

    @staticmethod
    def generate_nonce(size=12):
        if size < 12:
            raise ValueError("Nonce size must be at least 12 bytes for AESGCM")
        return secrets.token_bytes(size)