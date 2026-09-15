import base64
import hashlib
import os
import time
import random
import json
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from app.database.db import ENCRYPTED_DIR, KEYS_DIR, ensure_storage_dirs, SessionLocal
from app.database.models import ECDHPrekey
from app.security.secure_memory import SecureBuffer


@dataclass
class EncryptionResult:
    encrypted_path: str
    encrypted_key: str
    nonce: str
    ecdh_public_key: str | None
    ecdh_wrapped_key: str | None
    ecdh_key_nonce: str | None
    cipher_algorithm: str
    pqc_wrapped_key: str | None
    pqc_wrap_nonce: str | None
    aes_time_ms: float
    rsa_key_wrap_time_ms: float
    ecdh_time_ms: float


class CryptoService:
    @staticmethod
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sha256_file(path: str | Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def _unb64(data: str) -> bytes:
        return base64.b64decode(data.encode("utf-8"))

    @staticmethod
    def key_paths(user_id: str | int) -> dict[str, Path]:
        return {
            "rsa_private": KEYS_DIR / f"user_{user_id}_rsa_private.pem",
            "rsa_public": KEYS_DIR / f"user_{user_id}_rsa_public.pem",
            "rsa_signing_private": KEYS_DIR / f"user_{user_id}_rsa_signing_private.pem",
            "rsa_signing_public": KEYS_DIR / f"user_{user_id}_rsa_signing_public.pem",
            "ecdh_private": KEYS_DIR / f"user_{user_id}_ecdh_private.pem",
            "ecdh_public": KEYS_DIR / f"user_{user_id}_ecdh_public.pem",
        }

    @classmethod
    def ensure_user_keypair(cls, user_id: str | int) -> None:
        ensure_storage_dirs()
        paths = cls.key_paths(user_id)
        if not paths["rsa_private"].exists():
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            paths["rsa_private"].write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            paths["rsa_public"].write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        if not paths["ecdh_private"].exists():
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            paths["ecdh_private"].write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            paths["ecdh_public"].write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        # Client-side signing key setup is handled by the frontend now.
        # We only generate server-side encryption/decryption keys here.

    @classmethod
    def _load_rsa_public(cls, user_id: str | int):
        cls.ensure_user_keypair(user_id)
        return serialization.load_pem_public_key(cls.key_paths(user_id)["rsa_public"].read_bytes())

    @classmethod
    def _load_rsa_private(cls, user_id: str | int):
        cls.ensure_user_keypair(user_id)
        return serialization.load_pem_private_key(cls.key_paths(user_id)["rsa_private"].read_bytes(), password=None)

    @classmethod
    def _load_ecdh_public(cls, user_id: str | int):
        cls.ensure_user_keypair(user_id)
        return serialization.load_pem_public_key(cls.key_paths(user_id)["ecdh_public"].read_bytes())

    @classmethod
    def _load_ecdh_private(cls, user_id: str | int):
        cls.ensure_user_keypair(user_id)
        return serialization.load_pem_private_key(cls.key_paths(user_id)["ecdh_private"].read_bytes(), password=None)

    # Signing methods removed. Client performs signatures.

    @classmethod
    def canonicalize_pfce_manifest(cls, manifest_dict: dict) -> bytes:
        # Prevent signature object from being recursively signed
        manifest_copy = dict(manifest_dict)
        if "signature" in manifest_copy:
            del manifest_copy["signature"]
        return json.dumps(
            manifest_copy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False
        ).encode("utf-8")

    @classmethod
    def get_spki_fingerprint(cls, spki_base64: str) -> str:
        try:
            spki_der = cls._unb64(spki_base64)
            return cls.sha256_bytes(spki_der)
        except Exception:
            return ""

    @classmethod
    def verify_client_signature(cls, canonical_payload: bytes, signature_b64: str, spki_base64: str) -> bool:
        try:
            public_key = serialization.load_der_public_key(cls._unb64(spki_base64))
            signature = cls._unb64(signature_b64)
            public_key.verify(
                signature,
                canonical_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    @classmethod
    def get_public_key(cls, user_id: str | int):
        return cls._load_rsa_public(user_id)

    @classmethod
    def get_public_key_size(cls, user_id: str | int) -> int:
        """Returns the size of the RSA public key in bits."""
        public_key = cls.get_public_key(user_id)
        if hasattr(public_key, 'key_size'):
            return public_key.key_size
        return 0

    @classmethod
    def verify_pfce_signature(cls, canonical_manifest: bytes, signature_b64: str, spki_base64: str) -> bool:
        return cls.verify_client_signature(canonical_manifest, signature_b64, spki_base64)

    @staticmethod
    def _derive_ecdh_wrap_key(shared_secret: bytes, transfer_context: bytes, info: bytes = b"secure-file-transfer-ecdh-aes-key-wrap") -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=transfer_context,
            info=info,
        ).derive(shared_secret)

    @classmethod
    def generate_prekeys_for_user(cls, user_id: int, count: int = 10):
        with SessionLocal() as db:
            for _ in range(count):
                private_key = ec.generate_private_key(ec.SECP256R1())
                public_key = private_key.public_key()
                
                priv_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")
                
                pub_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                
                prekey = ECDHPrekey(
                    user_id=user_id,
                    prekey_id=str(uuid.uuid4()),
                    public_key_pem=pub_pem,
                    private_key_pem=priv_pem,
                    expires_at=datetime.utcnow() + timedelta(days=30)
                )
                db.add(prekey)
            db.commit()

    @classmethod
    def claim_prekey(cls, receiver_id: int, transfer_id: str) -> str | None:
        with SessionLocal() as db:
            for attempt in range(3):
                prekey = db.query(ECDHPrekey).filter(
                    ECDHPrekey.user_id == receiver_id,
                    ECDHPrekey.consumed == False,
                    ECDHPrekey.expires_at > datetime.utcnow()
                ).first()
                
                if not prekey:
                    cls.generate_prekeys_for_user(receiver_id, 10)
                    continue
                
                # Try to claim it atomically
                updated = db.query(ECDHPrekey).filter(
                    ECDHPrekey.prekey_id == prekey.prekey_id,
                    ECDHPrekey.consumed == False
                ).update({
                    "consumed": True,
                    "consumed_at": datetime.utcnow(),
                    "transfer_id": transfer_id
                })
                
                if updated > 0:
                    db.commit()
                    return prekey.public_key_pem
                db.rollback()
            return None

    @classmethod
    def get_and_delete_prekey(cls, receiver_id: int, transfer_id: str) -> str | None:
        with SessionLocal() as db:
            prekey = db.query(ECDHPrekey).filter(
                ECDHPrekey.user_id == receiver_id,
                ECDHPrekey.transfer_id == transfer_id
            ).first()
            
            if not prekey:
                return None
                
            private_pem = prekey.private_key_pem
            # Forward secrecy: Delete the prekey so it can never be used again
            db.delete(prekey)
            db.commit()
            return private_pem

    @staticmethod
    def construct_pqc_aad(transfer_id: str, receiver_id: int | str, fragment_id: int, key_version: int) -> bytes:
        aad_dict = {
            "transfer_id": str(transfer_id),
            "receiver_id": str(receiver_id),
            "fragment_id": int(fragment_id),
            "algorithm": "ML-KEM-768",
            "key_version": int(key_version)
        }
        return json.dumps(aad_dict, sort_keys=True).encode("utf-8")

    @classmethod
    def encrypt_file_for_receiver(cls, src_path: str, receiver_id: str | int, stored_name: str, classification: str = "Sensitive", pqc_kek: bytes | None = None, pqc_aad: bytes | None = None, prekey_public_pem: str | None = None, transfer_id: str | None = None, sender_id: str | int | None = None) -> EncryptionResult:
        ensure_storage_dirs()
        
        # Always use 32-byte keys (256-bit) because ChaCha20Poly1305 strictly requires 32 bytes,
        # and polymorphic encryption may select it randomly regardless of classification.
        raw_aes_key = os.urandom(32)
        
        file_nonce = os.urandom(12)  # Recommended nonce size
        
        # Polymorphic cipher selection logic
        classification_lower = classification.lower() if classification else ""
        if "confidential" in classification_lower or "restricted" in classification_lower or "secret" in classification_lower or "sensitive" in classification_lower:
            selected_cipher = "ChaCha20-Poly1305"
        else:
            available_ciphers = ["AES-256-GCM", "ChaCha20-Poly1305"]
            selected_cipher = random.choice(available_ciphers)
        cipher_algorithm = selected_cipher

        t0 = time.perf_counter()
        
        encrypted_path = ENCRYPTED_DIR / f"{stored_name}.enc"
        
        chunk = Path(src_path).read_bytes()
        
        # --- POLYMORPHIC ENCRYPTION ---
        with SecureBuffer(raw_aes_key) as aes_key_buf:
            aes_key_mem = aes_key_buf.memory
            if selected_cipher == "AES-256-GCM":
                encrypted_chunk = AESGCM(aes_key_mem).encrypt(file_nonce, chunk, None)
                Path(encrypted_path).write_bytes(encrypted_chunk)
                
            else: # ChaCha20-Poly1305
                chacha = ChaCha20Poly1305(aes_key_mem)
                encrypted_chunk = chacha.encrypt(file_nonce, chunk, None)
                Path(encrypted_path).write_bytes(encrypted_chunk)

            aes_time_ms = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            receiver_rsa_public = cls._load_rsa_public(receiver_id)
            rsa_wrapped_key = receiver_rsa_public.encrypt(
                aes_key_buf.bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            rsa_time_ms = (time.perf_counter() - t0) * 1000

            ephemeral_public_pem_str = None
            ecdh_wrapped_key_b64 = None
            wrap_nonce_b64 = None
            ecdh_time_ms = 0.0

            if classification == "Sensitive":
                t0 = time.perf_counter()
                
                if prekey_public_pem:
                    receiver_ecdh_public = serialization.load_pem_public_key(prekey_public_pem.encode("utf-8"))
                else:
                    receiver_ecdh_public = cls._load_ecdh_public(receiver_id)
                    
                ephemeral_private = ec.generate_private_key(ec.SECP256R1())
                
                shared_secret_raw = ephemeral_private.exchange(ec.ECDH(), receiver_ecdh_public)
                with SecureBuffer(shared_secret_raw) as shared_secret_buf:
                    ephemeral_public_pem = ephemeral_private.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    wrap_nonce = os.urandom(12)
                    
                    # Context binding
                    if transfer_id and sender_id:
                        salt_input = f"UPCE-V1|{transfer_id}|{sender_id}|{receiver_id}|{hashlib.sha256(ephemeral_public_pem).hexdigest()}"
                        salt = hashlib.sha256(salt_input.encode("utf-8")).digest()
                        info = b"PFCE-FILE-KEK-v1"
                    else:
                        salt = stored_name.encode("utf-8")
                        info = b"secure-file-transfer-ecdh-aes-key-wrap"
                        
                    wrap_key_raw = cls._derive_ecdh_wrap_key(shared_secret_buf.bytes, salt, info=info)
                    with SecureBuffer(wrap_key_raw) as wrap_key_buf:
                        ecdh_wrapped_key = AESGCM(wrap_key_buf.memory).encrypt(wrap_nonce, aes_key_buf.bytes, None)
                
                # Deterministic wipe of ephemeral private scalar is done by Python's garbage collection / OpenSSL. 
                # We do not have direct access to `ephemeral_private` internal bytes, but we wiped our intermediate secrets.
                
                ecdh_time_ms = (time.perf_counter() - t0) * 1000
                
                ephemeral_public_pem_str = ephemeral_public_pem.decode("utf-8")
                ecdh_wrapped_key_b64 = cls._b64(ecdh_wrapped_key)
                wrap_nonce_b64 = cls._b64(wrap_nonce)

            pqc_wrapped_key_b64 = None
            pqc_wrap_nonce_b64 = None

            if pqc_kek:
                # Wrap the AES key using the PQC KEK generated at the transfer level
                pqc_wrap_nonce = os.urandom(12)
                pqc_wrapped_key = AESGCM(pqc_kek.memory if hasattr(pqc_kek, "memory") else pqc_kek).encrypt(pqc_wrap_nonce, aes_key_buf.bytes, pqc_aad)
                pqc_wrapped_key_b64 = cls._b64(pqc_wrapped_key)
                pqc_wrap_nonce_b64 = cls._b64(pqc_wrap_nonce)

            return EncryptionResult(
                encrypted_path=str(encrypted_path),
                encrypted_key=cls._b64(rsa_wrapped_key),
                nonce=cls._b64(file_nonce),
                ecdh_public_key=ephemeral_public_pem_str,
                ecdh_wrapped_key=ecdh_wrapped_key_b64,
                ecdh_key_nonce=wrap_nonce_b64,
            cipher_algorithm=cipher_algorithm,
            pqc_wrapped_key=pqc_wrapped_key_b64,
            pqc_wrap_nonce=pqc_wrap_nonce_b64,
            aes_time_ms=round(aes_time_ms, 3),
            rsa_key_wrap_time_ms=round(rsa_time_ms, 3),
            ecdh_time_ms=round(ecdh_time_ms, 3),
        )
    @classmethod
    def unwrap_key_with_ecdh(cls, receiver_id: str | int, ecdh_public_key_pem: str, ecdh_wrapped_key: str, ecdh_key_nonce: str, stored_name: str, prekey_private_pem: str | None = None, transfer_id: str | None = None, sender_id: str | int | None = None) -> SecureBuffer:
        if prekey_private_pem:
            receiver_private = serialization.load_pem_private_key(prekey_private_pem.encode("utf-8"), password=None)
        else:
            receiver_private = cls._load_ecdh_private(receiver_id)
            
        sender_ephemeral_public = serialization.load_pem_public_key(ecdh_public_key_pem.encode("utf-8"))
        shared_secret_raw = receiver_private.exchange(ec.ECDH(), sender_ephemeral_public)
        with SecureBuffer(shared_secret_raw) as shared_secret_buf:
            if transfer_id and sender_id:
                salt_input = f"UPCE-V1|{transfer_id}|{sender_id}|{receiver_id}|{hashlib.sha256(ecdh_public_key_pem.encode('utf-8')).hexdigest()}"
                salt = hashlib.sha256(salt_input.encode("utf-8")).digest()
                info = b"PFCE-FILE-KEK-v1"
            else:
                salt = stored_name.encode("utf-8")
                info = b"secure-file-transfer-ecdh-aes-key-wrap"
                
            wrap_key_raw = cls._derive_ecdh_wrap_key(shared_secret_buf.bytes, salt, info=info)
            with SecureBuffer(wrap_key_raw) as wrap_key_buf:
                aes_key_raw = AESGCM(wrap_key_buf.memory).decrypt(cls._unb64(ecdh_key_nonce), cls._unb64(ecdh_wrapped_key), None)
                return SecureBuffer(aes_key_raw)

    @classmethod
    def unwrap_pqc_key(cls, pqc_kek: SecureBuffer, pqc_wrapped_key_b64: str, pqc_wrap_nonce_b64: str, pqc_aad: bytes | None = None) -> SecureBuffer:
        pqc_wrapped_key = cls._unb64(pqc_wrapped_key_b64)
        pqc_wrap_nonce = cls._unb64(pqc_wrap_nonce_b64)
        aes_key_raw = AESGCM(pqc_kek.memory if hasattr(pqc_kek, 'memory') else pqc_kek).decrypt(pqc_wrap_nonce, pqc_wrapped_key, pqc_aad)
        return SecureBuffer(aes_key_raw)

    @classmethod
    def unwrap_key_with_rsa(cls, receiver_id: str | int, encrypted_key: str) -> SecureBuffer:
        receiver_private = cls._load_rsa_private(receiver_id)
        aes_key_raw = receiver_private.decrypt(
            cls._unb64(encrypted_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return SecureBuffer(aes_key_raw)

    @classmethod
    def decrypt_transfer_bytes(cls, transfer, receiver_id: str | int) -> bytes:
        aes_key_buf = None
        try:
            if transfer.ecdh_public_key and transfer.ecdh_wrapped_key and transfer.ecdh_key_nonce:
                aes_key_buf = cls.unwrap_key_with_ecdh(
                    receiver_id=receiver_id,
                    ecdh_public_key_pem=transfer.ecdh_public_key,
                    ecdh_wrapped_key=transfer.ecdh_wrapped_key,
                    ecdh_key_nonce=transfer.ecdh_key_nonce,
                    stored_name=transfer.stored_name,
                )
                if not aes_key_buf:
                    raise ValueError("ECDH unwrap returned None. Failing closed.")
            else:
                aes_key_buf = cls.unwrap_key_with_rsa(receiver_id=receiver_id, encrypted_key=transfer.encrypted_key)

            encrypted_bytes = Path(transfer.encrypted_path).read_bytes()
            cipher_algo = getattr(transfer, "cipher_algorithm", "AES-256-GCM")
            if cipher_algo == "ChaCha20-Poly1305":
                return ChaCha20Poly1305(aes_key_buf.memory).decrypt(cls._unb64(transfer.nonce), encrypted_bytes, None)
            else:
                return AESGCM(aes_key_buf.memory).decrypt(cls._unb64(transfer.nonce), encrypted_bytes, None)
        finally:
            if aes_key_buf:
                aes_key_buf.wipe()
