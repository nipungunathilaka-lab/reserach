import os
import sys
import logging
import base64
import random
from typing import Tuple, Dict, Any, Callable

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
    def initialize_transfer_security(sender_id: str | int, receiver_id: str | int, policy: dict) -> dict:
        """
        Establishes Post-Quantum transfer-level keys for the receiver using MLKEMService.
        """
        pqc_metadata = {"enabled": False}
        pqc_kek = None
        
        try:
            receiver_pqc_info = MLKEMService.get_active_public_key(receiver_id)
            receiver_pub_key = receiver_pqc_info["public_key"]
            receiver_key_version = receiver_pqc_info["key_version"]
            
            kem_ciphertext, shared_secret_buf = MLKEMService.encapsulate(receiver_pub_key)
            
            kdf_salt = os.urandom(16)
            pqc_kek = MLKEMService.derive_key_encryption_key(shared_secret_buf, kdf_salt)
            
            pqc_metadata = {
                "enabled": True,
                "scheme": "ML-KEM-768",
                "receiver_key_version": receiver_key_version,
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode("utf-8"),
                "kdf": "HKDF-SHA256",
                "kdf_salt": base64.b64encode(kdf_salt).decode("utf-8"),
                "key_wrap_algorithm": "AES-256-GCM"
            }
            print("[UPCE] PQC Transfer security initialized successfully.", flush=True)
        except Exception as e:
            logger.error(f"[UPCE] Failed to perform PQC encapsulation for transfer: {e}")
            pqc_metadata = {"enabled": False}
            
        return {
            "pqc_kek": pqc_kek,
            "metadata": pqc_metadata
        }

    @staticmethod
    def recover_transfer_security(receiver_id: str | int, pqc_metadata: dict) -> bytes | None:
        """
        Recovers the Post-Quantum transfer-level key from the metadata using MLKEMService.
        """
        if not pqc_metadata.get("enabled"):
            return None
            
        try:
            kem_ciphertext = base64.b64decode(pqc_metadata["kem_ciphertext"])
            kdf_salt = base64.b64decode(pqc_metadata["kdf_salt"])
            receiver_key_version = pqc_metadata["receiver_key_version"]
            
            shared_secret_buf = MLKEMService.decapsulate(kem_ciphertext, receiver_id, receiver_key_version)
            pqc_kek = MLKEMService.derive_key_encryption_key(shared_secret_buf, kdf_salt)
            
            print("[UPCE] PQC Transfer security recovered successfully.", flush=True)
            return pqc_kek
        except Exception as e:
            logger.error(f"[UPCE] Failed to decapsulate and derive PQC KEK: {e}")
            raise RuntimeError("PQC required but decapsulation failed") from e