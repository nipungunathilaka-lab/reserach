import logging
import base64
from typing import Optional
import boto3
from botocore.exceptions import ClientError
from app.security.kms.base import KeyManagementProvider

logger = logging.getLogger(__name__)

class AWSKMSProvider(KeyManagementProvider):
    """AWS KMS provider for Enterprise Key Management."""

    def __init__(self, region_name: Optional[str] = None):
        self.region_name = region_name
        self._kms_client = None

    @property
    def kms(self):
        if self._kms_client is None:
            self._kms_client = boto3.client("kms", region_name=self.region_name)
        return self._kms_client

    def health_check(self) -> bool:
        try:
            # A simple describe on an existing alias/key or just checking if the client can be created
            # Usually we check if we can list aliases with a limit of 1 to verify credentials
            self.kms.list_aliases(Limit=1)
            return True
        except Exception as e:
            logger.error(f"KMS Health Check Failed: {e}")
            return False

    def encrypt(self, plaintext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        try:
            kwargs = {
                "KeyId": key_identifier,
                "Plaintext": plaintext,
            }
            if context:
                kwargs["EncryptionContext"] = {str(k): str(v) for k, v in context.items()}
                
            response = self.kms.encrypt(**kwargs)
            return response["CiphertextBlob"]
        except ClientError as e:
            logger.error(f"KMS Encrypt Error: {e}")
            raise RuntimeError(f"AWS KMS Encryption Failed: {e}")

    def decrypt(self, ciphertext: bytes, key_identifier: str, context: Optional[dict] = None) -> bytes:
        try:
            kwargs = {
                "KeyId": key_identifier,
                "CiphertextBlob": ciphertext,
            }
            if context:
                kwargs["EncryptionContext"] = {str(k): str(v) for k, v in context.items()}
                
            response = self.kms.decrypt(**kwargs)
            return response["Plaintext"]
        except ClientError as e:
            logger.error(f"KMS Decrypt Error: {e}")
            raise RuntimeError(f"AWS KMS Decryption Failed: {e}")

    def generate_data_key(self, key_identifier: str, context: Optional[dict] = None) -> tuple[bytes, bytes]:
        try:
            kwargs = {
                "KeyId": key_identifier,
                "KeySpec": "AES_256",
            }
            if context:
                kwargs["EncryptionContext"] = {str(k): str(v) for k, v in context.items()}
                
            response = self.kms.generate_data_key(**kwargs)
            return response["Plaintext"], response["CiphertextBlob"]
        except ClientError as e:
            logger.error(f"KMS GenerateDataKey Error: {e}")
            raise RuntimeError(f"AWS KMS GenerateDataKey Failed: {e}")

    def sign(self, message: bytes, key_identifier: str) -> bytes:
        try:
            # We assume message is already a digest or we let KMS hash it.
            # Usually for audit logs we sign the SHA-256 hash.
            response = self.kms.sign(
                KeyId=key_identifier,
                Message=message,
                MessageType="RAW", # Or DIGEST if message is pre-hashed
                SigningAlgorithm="RSASSA_PSS_SHA_256" # Or whatever we configure
            )
            return response["Signature"]
        except ClientError as e:
            logger.error(f"KMS Sign Error: {e}")
            raise RuntimeError(f"AWS KMS Sign Failed: {e}")

    def verify(self, message: bytes, signature: bytes, key_identifier: str) -> bool:
        try:
            response = self.kms.verify(
                KeyId=key_identifier,
                Message=message,
                Signature=signature,
                MessageType="RAW",
                SigningAlgorithm="RSASSA_PSS_SHA_256"
            )
            return response.get("SignatureValid", False)
        except ClientError as e:
            logger.error(f"KMS Verify Error: {e}")
            return False
