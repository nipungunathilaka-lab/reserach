import base64
import hashlib
import os
import time
import random
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from app.database.db import ENCRYPTED_DIR, KEYS_DIR, ensure_storage_dirs


@dataclass
class EncryptionResult:
    encrypted_path: str
    encrypted_key: str
    nonce: str
    ecdh_public_key: str | None
    ecdh_wrapped_key: str | None
    ecdh_key_nonce: str | None
    cipher_algorithm: str
    pqc_public_key: str | None
    pqc_ciphertext: str | None
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

    @staticmethod
    def _derive_ecdh_wrap_key(shared_secret: bytes, transfer_context: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=transfer_context,
            info=b"secure-file-transfer-ecdh-aes-key-wrap",
        ).derive(shared_secret)

    @classmethod
    def encrypt_file_for_receiver(cls, src_path: str, receiver_id: str | int, stored_name: str, classification: str = "Sensitive") -> EncryptionResult:
        ensure_storage_dirs()
        
        # Always use 32-byte keys (256-bit) because ChaCha20Poly1305 strictly requires 32 bytes,
        # and polymorphic encryption may select it randomly regardless of classification.
        aes_key = os.urandom(32)
        
        file_nonce = os.urandom(12)  # Recommended nonce size
        
        # Polymorphic cipher selection logic
        available_ciphers = ["AES-256-GCM", "ChaCha20-Poly1305"]
        cipher_algorithm = "Polymorphic (AES/ChaCha20)"

        t0 = time.perf_counter()
        
        encrypted_path = ENCRYPTED_DIR / f"{stored_name}.enc"
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        import random
        
        # We will write the file dynamically
        with open(src_path, 'rb') as f_in, open(encrypted_path, 'wb') as f_out:
            while True:
                # --- DYNAMIC FRAGMENTATION (Variable Chunk Sizes) ---
                # Randomize chunk size between 512KB and 2MB
                min_chunk_size = 512 * 1024     # 512 KB
                max_chunk_size = 2 * 1024 * 1024 # 2 MB
                dynamic_chunk_size = random.randint(min_chunk_size, max_chunk_size)
                
                chunk = f_in.read(dynamic_chunk_size)
                
                if not chunk or len(chunk) == 0:
                    break
                
                # --- POLYMORPHIC ENCRYPTION ---
                # Randomly pick an algorithm for this specific fragment
                selected_cipher = random.choice(available_ciphers)
                
                if selected_cipher == "AES-256-GCM":
                    encryptor = Cipher(
                        algorithms.AES(aes_key),
                        modes.GCM(file_nonce)
                    ).encryptor()
                    f_out.write(encryptor.update(chunk) + encryptor.finalize() + encryptor.tag)
                    
                else: # ChaCha20-Poly1305
                    chacha = ChaCha20Poly1305(aes_key)
                    encrypted_chunk = chacha.encrypt(file_nonce, chunk, None)
                    f_out.write(encrypted_chunk)

        aes_time_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        receiver_rsa_public = cls._load_rsa_public(receiver_id)
        rsa_wrapped_key = receiver_rsa_public.encrypt(
            aes_key,
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
            receiver_ecdh_public = cls._load_ecdh_public(receiver_id)
            ephemeral_private = ec.generate_private_key(ec.SECP256R1())
            shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_ecdh_public)
            ephemeral_public_pem = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            wrap_nonce = os.urandom(12)
            wrap_key = cls._derive_ecdh_wrap_key(shared_secret, stored_name.encode("utf-8"))
            ecdh_wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, aes_key, None)
            ecdh_time_ms = (time.perf_counter() - t0) * 1000
            
            ephemeral_public_pem_str = ephemeral_public_pem.decode("utf-8")
            ecdh_wrapped_key_b64 = cls._b64(ecdh_wrapped_key)
            wrap_nonce_b64 = cls._b64(wrap_nonce)

        # Hybrid PQC Mock
        pqc_public_key = "pqc_kyber_pub_key_mock"
        pqc_ciphertext = "pqc_kyber_ciphertext_mock"

        return EncryptionResult(
            encrypted_path=str(encrypted_path),
            encrypted_key=cls._b64(rsa_wrapped_key),
            nonce=cls._b64(file_nonce),
            ecdh_public_key=ephemeral_public_pem_str,
            ecdh_wrapped_key=ecdh_wrapped_key_b64,
            ecdh_key_nonce=wrap_nonce_b64,
            cipher_algorithm=cipher_algorithm,
            pqc_public_key=pqc_public_key,
            pqc_ciphertext=pqc_ciphertext,
            aes_time_ms=round(aes_time_ms, 3),
            rsa_key_wrap_time_ms=round(rsa_time_ms, 3),
            ecdh_time_ms=round(ecdh_time_ms, 3),
        )
    @classmethod
    def unwrap_key_with_ecdh(cls, receiver_id: str | int, ecdh_public_key_pem: str, ecdh_wrapped_key: str, ecdh_key_nonce: str, stored_name: str) -> bytes:
        receiver_private = cls._load_ecdh_private(receiver_id)
        sender_ephemeral_public = serialization.load_pem_public_key(ecdh_public_key_pem.encode("utf-8"))
        shared_secret = receiver_private.exchange(ec.ECDH(), sender_ephemeral_public)
        wrap_key = cls._derive_ecdh_wrap_key(shared_secret, stored_name.encode("utf-8"))
        return AESGCM(wrap_key).decrypt(cls._unb64(ecdh_key_nonce), cls._unb64(ecdh_wrapped_key), None)

    @classmethod
    def unwrap_key_with_rsa(cls, receiver_id: str | int, encrypted_key: str) -> bytes:
        receiver_private = cls._load_rsa_private(receiver_id)
        return receiver_private.decrypt(
            cls._unb64(encrypted_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @classmethod
    def decrypt_transfer_bytes(cls, transfer, receiver_id: str | int) -> bytes:
        if transfer.ecdh_public_key and transfer.ecdh_wrapped_key and transfer.ecdh_key_nonce:
            try:
                aes_key = cls.unwrap_key_with_ecdh(
                    receiver_id=receiver_id,
                    ecdh_public_key_pem=transfer.ecdh_public_key,
                    ecdh_wrapped_key=transfer.ecdh_wrapped_key,
                    ecdh_key_nonce=transfer.ecdh_key_nonce,
                    stored_name=transfer.stored_name,
                )
            except Exception:
                aes_key = cls.unwrap_key_with_rsa(receiver_id=receiver_id, encrypted_key=transfer.encrypted_key)
        else:
            aes_key = cls.unwrap_key_with_rsa(receiver_id=receiver_id, encrypted_key=transfer.encrypted_key)

        encrypted_bytes = Path(transfer.encrypted_path).read_bytes()
        return AESGCM(aes_key).decrypt(cls._unb64(transfer.nonce), encrypted_bytes, None)
