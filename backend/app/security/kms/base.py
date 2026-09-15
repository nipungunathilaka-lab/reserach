import os
import base64
from typing import Optional

class KeyManagementProvider:
    """Base interface for Enterprise Key Management."""

    def health_check(self) -> bool:
        """Check if the provider is healthy and accessible."""
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        """Encrypts data using the specified server key."""
        raise NotImplementedError

    def decrypt(self, ciphertext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        """Decrypts data using the specified server key."""
        raise NotImplementedError

    def generate_data_key(self, key_identifier: str, context: Optional[dict] = None) -> tuple[bytes, bytes]:
        """
        Generates a data key for envelope encryption.
        Returns: (plaintext_key, encrypted_key)
        """
        raise NotImplementedError

    def sign(self, message: bytes, key_identifier: str) -> bytes:
        """Signs a message using the specified asymmetric server key."""
        raise NotImplementedError

    def verify(self, message: bytes, signature: bytes, key_identifier: str) -> bool:
        """Verifies a signature using the specified asymmetric server key."""
        raise NotImplementedError
