import os
import base64
import logging
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.core.config import settings
from app.database.db import SessionLocal
from app.database.models import PQCKey
from app.security.secure_memory import SecureBuffer

logger = logging.getLogger(__name__)

OQS_AVAILABLE = False
try:
    import oqs
    OQS_AVAILABLE = True
except (Exception, SystemExit) as e:
    logger.warning(f"Failed to import oqs: {e}")

class MLKEMService:
    @classmethod
    def _b64(cls, data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @classmethod
    def _unb64(cls, data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    @classmethod
    def get_master_key(cls) -> bytes:
        mk_b64 = settings.mlkem_private_key_master_key
        if not mk_b64:
            raise ValueError("MLKEM_PRIVATE_KEY_MASTER_KEY is not configured")
        
        try:
            mk = cls._unb64(mk_b64)
        except Exception as e:
            raise ValueError("MLKEM_PRIVATE_KEY_MASTER_KEY must be a valid Base64 encoded string") from e
            
        if len(mk) != 32:
            raise ValueError(f"MLKEM_PRIVATE_KEY_MASTER_KEY must decode to exactly 32 bytes (256-bit), got {len(mk)}")
        return mk

    @classmethod
    def startup_check(cls):
        if not settings.pqc_enabled:
            return
            
        if not OQS_AVAILABLE:
            msg = "PQC is enabled but liboqs-python could not be imported (OQS_AVAILABLE=False)."
            if settings.pqc_required:
                logger.error(msg)
                raise RuntimeError(msg)
            else:
                logger.warning(msg)
                return

        try:
            mechanisms = oqs.get_enabled_kem_mechanisms()
            if "ML-KEM-768" not in mechanisms:
                raise RuntimeError("ML-KEM-768 is not enabled in liboqs.")
            logger.info("PQC provider: Open Quantum Safe")
            logger.info("PQC KEM: ML-KEM-768")
            logger.info("PQC status: enabled")
            cls.get_master_key() # Check master key is valid
        except Exception as e:
            if settings.pqc_required:
                logger.error(f"PQC startup check failed: {e}")
                raise RuntimeError(f"PQC is required but unavailable: {e}")
            else:
                logger.warning(f"PQC startup check failed, continuing because PQC_REQUIRED is false: {e}")

    @classmethod
    def generate_keypair(cls, user_id: str):
        with SessionLocal() as db:
            active_key = db.query(PQCKey).filter(PQCKey.user_id == user_id, PQCKey.is_active == True).first()
            new_version = 1
            if active_key:
                new_version = active_key.key_version + 1
                active_key.is_active = False
                active_key.retired_at = datetime.utcnow()
                db.add(active_key)

            with oqs.KeyEncapsulation("ML-KEM-768") as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()

            master_key = cls.get_master_key()
            nonce = os.urandom(12)
            encrypted_secret_key = AESGCM(master_key).encrypt(nonce, secret_key, None)

            new_key = PQCKey(
                user_id=user_id,
                algorithm="ML-KEM-768",
                key_version=new_version,
                public_key=cls._b64(public_key),
                encrypted_private_key=cls._b64(encrypted_secret_key),
                private_key_nonce=cls._b64(nonce),
                is_active=True
            )
            db.add(new_key)
            db.commit()

    @classmethod
    def backfill_keys(cls):
        pass # User table no longer stored in SQLite; Node backend triggers keypair generation dynamically

    @classmethod
    def rotate_keypair(cls, user_id: str):
        cls.generate_keypair(user_id)

    @classmethod
    def get_active_public_key(cls, user_id: str) -> dict:
        with SessionLocal() as db:
            active_key = db.query(PQCKey).filter(PQCKey.user_id == user_id, PQCKey.is_active == True).first()
            if not active_key:
                raise ValueError(f"No active ML-KEM key found for user {user_id}")
            return {
                "public_key": cls._unb64(active_key.public_key),
                "key_version": active_key.key_version
            }

    @classmethod
    def _get_secret_key(cls, user_id: str, key_version: int) -> SecureBuffer:
        with SessionLocal() as db:
            pqc_key = db.query(PQCKey).filter(PQCKey.user_id == user_id, PQCKey.key_version == key_version).first()
            if not pqc_key:
                raise ValueError(f"No ML-KEM key found for user {user_id} with version {key_version}")
            
            encrypted_secret_key = cls._unb64(pqc_key.encrypted_private_key)
            nonce = cls._unb64(pqc_key.private_key_nonce)
            master_key = cls.get_master_key()
            
            try:
                secret_key_raw = AESGCM(master_key).decrypt(nonce, encrypted_secret_key, None)
                return SecureBuffer(secret_key_raw)
            except Exception as e:
                logger.error(f"Failed to decrypt ML-KEM private key for user {user_id}: {e}")
                raise

    @classmethod
    def encapsulate(cls, receiver_public_key: bytes) -> tuple[bytes, SecureBuffer]:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ciphertext, shared_secret_raw = kem.encap_secret(receiver_public_key)
            return ciphertext, SecureBuffer(shared_secret_raw)

    @classmethod
    def decapsulate(cls, ciphertext: bytes, receiver_id: str, key_version: int) -> SecureBuffer:
        secret_key_buf = cls._get_secret_key(receiver_id, key_version)
        try:
            with oqs.KeyEncapsulation("ML-KEM-768", secret_key_buf.bytes) as kem:
                shared_secret_raw = kem.decap_secret(ciphertext)
                return SecureBuffer(shared_secret_raw)
        finally:
            secret_key_buf.wipe()

    @classmethod
    def derive_key_encryption_key(cls, shared_secret: SecureBuffer, salt: bytes, context: bytes = b"UPCE-MLKEM-768-KEY-WRAP-v1") -> SecureBuffer:
        try:
            raw_kek = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=context,
            ).derive(shared_secret.bytes)
            return SecureBuffer(raw_kek)
        finally:
            if hasattr(shared_secret, "wipe"):
                shared_secret.wipe()
