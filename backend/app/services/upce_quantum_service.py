import os
import sys
import logging
import base64
import random
from typing import Tuple, Dict, Any, Callable
import hashlib

# Keep existing imports if possible
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

from app.services.mlkem_service import MLKEMService
from app.security.secure_memory import SecureBuffer

logger = logging.getLogger(__name__)

# --- BLOCK 1: SECURE ENCLAVE ---
class SecureEnclaveManager:
    @staticmethod
    def execute_in_enclave(operation_name: str, func: Callable, *args, **kwargs):
        # Fake enclave messages removed per security audit.
        # Hardware TEE is currently unsupported on this environment.
        # This function executes in standard memory.
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            pass

# --- MOCKS FOR BACKWARD COMPATIBILITY ONLY ---
class AIContextAnalysisEngine:
    def __init__(self):
        logger.warning("[AI ENGINE] AIContextAnalysisEngine mock initialized. Use AIService instead for production.")
        self.epsilon = 0.5 

    def evaluate_threat_context(self, file_name: str, file_size_bytes: int) -> float:
        logger.warning("[AI ENGINE] Using mock evaluate_threat_context. This should not be called in production.")
        return 0.5

class ContextAwarePolicyGenerator:
    @staticmethod
    def generate_policy(context_vector_c: float) -> dict:
        logger.warning("[POLICY ENGINE] Using mock generate_policy. This should not be called in production.")
        return UniversalPolymorphicCryptoEngine.select_crypto_policy({"classification": "standard"}, {"anomaly_score": context_vector_c}, 0.0)

# --- NEW PRODUCTION SECURITY ORCHESTRATOR ---
class UniversalPolymorphicCryptoEngine:
    """
    UPCE: High-level security orchestration / key-management layer.
    """

    @staticmethod
    def select_crypto_policy(context: dict, ai_result: dict, malware_result: float) -> dict:
        """
        Determines the security policy based on AI context and threat scores.
        Replaces PFCEEngine's internal _get_adaptive_chunk_range and algorithmic choices.
        """
        threat_score = ai_result.get("anomaly_score", 0)
        level = ai_result.get("level", "low").lower()
        
        classification = context.get("classification", "standard").lower()
        
        # Adaptive chunk sizes and algorithms based on risk and classification
        if level in ["high", "critical"] or classification in ["sensitive", "confidential", "restricted", "secret"] or malware_result >= 0.90:
            policy = {
                "security_level": "Maximum",
                "min_chunk_bytes": 512 * 1024,
                "max_chunk_bytes": 2 * 1024 * 1024,
                "algorithm_candidates": ["ChaCha20-Poly1305"]
            }
        elif level == "medium" or classification in ["internal", "private"]:
            policy = {
                "security_level": "Elevated",
                "min_chunk_bytes": 2 * 1024 * 1024,
                "max_chunk_bytes": 5 * 1024 * 1024,
                "algorithm_candidates": ["AES-256-GCM", "ChaCha20-Poly1305"]
            }
        else:
            policy = {
                "security_level": "Standard",
                "min_chunk_bytes": 5 * 1024 * 1024,
                "max_chunk_bytes": 15 * 1024 * 1024,
                "algorithm_candidates": ["AES-256-GCM", "ChaCha20-Poly1305"]
            }
            
        print(f"[UPCE] Policy '{policy['security_level']}' applied based on Threat Score: {threat_score:.2f}", flush=True)
        return policy

    @staticmethod
    def generate_canonical_transcript(
        transfer_id: str, sender_id: str, receiver_id: str,
        ecdh_ephemeral_pub: bytes, ecdh_receiver_pub: bytes,
        mlkem_ciphertext: bytes, mlkem_pub: bytes
    ) -> bytes:
        transcript_dict = {
            "protocol_version": "UPCE-PFCE-HYBRID-KEX-V1",
            "transfer_id": str(transfer_id),
            "sender_id": str(sender_id),
            "receiver_id": str(receiver_id),
            "classical_algorithm": "ECDH-P256",
            "pq_algorithm": "ML-KEM-768",
            "kdf_algorithm": "HKDF-SHA256",
            "ecdh_ephemeral_pub_sha256": hashlib.sha256(ecdh_ephemeral_pub).hexdigest(),
            "ecdh_receiver_pub_sha256": hashlib.sha256(ecdh_receiver_pub).hexdigest(),
            "mlkem_ciphertext_sha256": hashlib.sha256(mlkem_ciphertext).hexdigest(),
            "mlkem_pub_sha256": hashlib.sha256(mlkem_pub).hexdigest()
        }
        import json
        canonical = json.dumps(transcript_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).digest()

    @staticmethod
    def derive_hybrid_kek(ecdh_secret: bytes, mlkem_secret: bytes, transcript_hash: bytes) -> SecureBuffer:
        import struct
        # Use length-prefixed encoding to prevent ambiguous boundary collisions
        ikm = struct.pack(">I", len(ecdh_secret)) + ecdh_secret + struct.pack(">I", len(mlkem_secret)) + mlkem_secret
        prk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"UPCE-PFCE-HYBRID-SALT-V1",
            info=None,
        ).derive(ikm)
        
        kek = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"UPCE-PFCE/KEK" + transcript_hash,
        ).derive(prk)
        return SecureBuffer(kek)

    @staticmethod
    def initialize_transfer_security(sender_id: str | int, receiver_id: str | int, policy: dict, prekey_public_pem: str | None = None, transfer_id: str = "") -> dict:
        """
        Establishes Hybrid (ECDH + ML-KEM) transfer-level keys for the receiver.
        """
        hybrid_metadata = {"enabled": False}
        hybrid_kek = None
        
        if not prekey_public_pem:
            logger.warning("[UPCE] No ECDH prekey provided. Falling back to classical/no-hybrid.")
            return {"hybrid_kek": None, "metadata": hybrid_metadata}
            
        try:
            # 1. ML-KEM Component
            receiver_pqc_info = MLKEMService.get_active_public_key(receiver_id)
            receiver_pub_key = receiver_pqc_info["public_key"]
            receiver_key_version = receiver_pqc_info["key_version"]
            kem_ciphertext, mlkem_secret_buf = MLKEMService.encapsulate(receiver_pub_key)
            
            # 2. ECDH Component
            from cryptography.hazmat.primitives.asymmetric import ec
            receiver_ecdh_public = serialization.load_pem_public_key(prekey_public_pem.encode("utf-8"))
            ephemeral_private = ec.generate_private_key(ec.SECP256R1())
            ephemeral_public_pem = ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            ecdh_secret_raw = ephemeral_private.exchange(ec.ECDH(), receiver_ecdh_public)
            
            # 3. Canonical Transcript
            transcript_hash = UniversalPolymorphicCryptoEngine.generate_canonical_transcript(
                transfer_id=transfer_id,
                sender_id=str(sender_id),
                receiver_id=str(receiver_id),
                ecdh_ephemeral_pub=ephemeral_public_pem,
                ecdh_receiver_pub=prekey_public_pem.encode("utf-8"),
                mlkem_ciphertext=kem_ciphertext,
                mlkem_pub=receiver_pub_key
            )
            
            # 4. KDF Combiner
            hybrid_kek = UniversalPolymorphicCryptoEngine.derive_hybrid_kek(
                ecdh_secret_raw, 
                mlkem_secret_buf.bytes, 
                transcript_hash
            )
            
            hybrid_metadata = {
                "enabled": True,
                "mode": "HYBRID",
                "classical_algorithm": "ECDH-P256",
                "pq_algorithm": "ML-KEM-768",
                "kdf": "HKDF-SHA256",
                "version": 1,
                "receiver_key_version": receiver_key_version,
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("utf-8"),
                "ecdh_ephemeral_public": ephemeral_public_pem.decode("utf-8")
            }
            print("[UPCE] Hybrid Transfer security initialized successfully.", flush=True)
            
            # Cleanup intermediate secrets
            mlkem_secret_buf.wipe()
            # ECDH ephemeral private is GC'd
            
        except Exception as e:
            logger.error(f"[UPCE] Failed to initialize hybrid transfer security: {e}")
            hybrid_metadata = {"enabled": False}
            
        return {
            "hybrid_kek": hybrid_kek,
            "metadata": hybrid_metadata
        }

    @staticmethod
    def recover_transfer_security(sender_id: str | int, receiver_id: str | int, transfer_id: str, metadata: dict, prekey_private_pem: str | None, prekey_public_pem: str | None) -> SecureBuffer | None:
        """
        Recovers the Hybrid transfer-level key from the metadata.
        """
        if not metadata.get("enabled") or metadata.get("mode") != "HYBRID":
            return None
            
        if not prekey_private_pem or not prekey_public_pem:
            logger.error("[UPCE] Missing receiver prekey material for hybrid decryption.")
            raise ValueError("Missing receiver prekey material. Cannot recover hybrid key.")
            
        try:
            # 1. ML-KEM Component
            kem_ciphertext = base64.b64decode(metadata["kem_ciphertext"])
            receiver_key_version = metadata["receiver_key_version"]
            mlkem_secret_buf = MLKEMService.decapsulate(kem_ciphertext, receiver_id, receiver_key_version)
            receiver_pqc_info = MLKEMService.get_active_public_key(receiver_id)
            receiver_pub_key = receiver_pqc_info["public_key"]
            
            # 2. ECDH Component
            from cryptography.hazmat.primitives.asymmetric import ec
            receiver_private = serialization.load_pem_private_key(prekey_private_pem.encode("utf-8"), password=None)
            ephemeral_public_pem = metadata["ecdh_ephemeral_public"].encode("utf-8")
            sender_ephemeral_public = serialization.load_pem_public_key(ephemeral_public_pem)
            ecdh_secret_raw = receiver_private.exchange(ec.ECDH(), sender_ephemeral_public)
            
            # 3. Canonical Transcript
            transcript_hash = UniversalPolymorphicCryptoEngine.generate_canonical_transcript(
                transfer_id=transfer_id,
                sender_id=str(sender_id),
                receiver_id=str(receiver_id),
                ecdh_ephemeral_pub=ephemeral_public_pem,
                ecdh_receiver_pub=prekey_public_pem.encode("utf-8"),
                mlkem_ciphertext=kem_ciphertext,
                mlkem_pub=receiver_pub_key
            )
            
            # 4. KDF Combiner
            hybrid_kek = UniversalPolymorphicCryptoEngine.derive_hybrid_kek(
                ecdh_secret_raw, 
                mlkem_secret_buf.bytes, 
                transcript_hash
            )
            
            print("[UPCE] Hybrid Transfer security recovered successfully.", flush=True)
            mlkem_secret_buf.wipe()
            return hybrid_kek
        except Exception as e:
            logger.error(f"[UPCE] Failed to recover hybrid transfer security: {e}")
            raise RuntimeError("KEY_ESTABLISHMENT_POLICY_MISMATCH") from e