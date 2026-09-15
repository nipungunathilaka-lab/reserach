import os
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from app.security.kms.base import KeyManagementProvider

logger = logging.getLogger(__name__)

class LocalDevProvider(KeyManagementProvider):
    """
    LOCAL DEVELOPMENT KEY PROVIDER
    NOT APPROVED FOR PRODUCTION
    
    This provider uses local static keys to simulate KMS operations.
    """

    def __init__(self):
        logger.warning("LOCAL DEVELOPMENT KEY PROVIDER INITIALIZED. NOT APPROVED FOR PRODUCTION.")
        # We simulate a static 32-byte key for encryption
        self.static_key = b"LOCAL_DEV_STATIC_KEY_01234567890" # 32 bytes
        # Simulate a static RSA keypair for signing
        self._private_key = None
        self._public_key = None
        self._init_keys()

    def _init_keys(self):
        # Deterministic but insecure for dev
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()

    def health_check(self) -> bool:
        return True

    def encrypt(self, plaintext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.static_key).encrypt(nonce, plaintext, None)
        # Prefix with nonce for easy decryption
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        nonce = ciphertext[:12]
        data = ciphertext[12:]
        return AESGCM(self.static_key).decrypt(nonce, data, None)

    def generate_data_key(self, key_identifier: str, context: Optional[dict] = None) -> tuple[bytes, bytes]:
        plaintext_key = os.urandom(32)
        encrypted_key = self.encrypt(plaintext_key, key_identifier, context)
        return plaintext_key, encrypted_key

    def sign(self, message: bytes, key_identifier: str) -> bytes:
        return self._private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def verify(self, message: bytes, signature: bytes, key_identifier: str) -> bool:
        try:
            self._public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
