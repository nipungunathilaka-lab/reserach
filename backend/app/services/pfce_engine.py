import os
import io
import json
import hashlib
import random
import time
import zipfile
import shutil
import tempfile
import logging
from dataclasses import dataclass
from typing import Generator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from app.services.crypto_service import CryptoService
from app.services.mlkem_service import MLKEMService
import base64
from app.database.db import SessionLocal
from app.services.blockchain_service import BlockchainService
logger = logging.getLogger(__name__)

@dataclass
class PFCEUploadResult:
    pfce_package_path: str
    execution_time_seconds: float
    aes_time_ms: float
    rsa_key_wrap_time_ms: float
    ecdh_time_ms: float
    fragment_count: int         
    original_hash: str          
    cipher_algorithm: str
# ==========================================
# PFCE CORE ENGINE: DYNAMIC & ADAPTIVE FRAGMENTATION
# ==========================================

class PFCEEngine:
    def __init__(self):
        # We removed fixed chunk limits. Everything is dynamically generated now!
        pass




    def process_upload(self, file_stream: io.IOBase, sender_id: str | int, receiver_id: str | int, stored_name_prefix: str, classification: str, pfce_package_path: str, progress_callback=None, crypto_engine=None, security_policy=None, client_signature_metadata=None, transfer_monitor=None) -> PFCEUploadResult:
        """
        Reads dynamically from the stream, slices into polymorphic fragments,
        encrypts using CryptoService, and packages into a .pfce ZIP.
        Continuously evaluates AI risk using transfer_monitor.
        """
        if os.environ.get("UPCE_REQUIRE_TEE", "false").lower() == "true":
            logger.error("[SECURE ENCLAVE] TEE is required but unsupported on this host. Failing closed.")
            raise RuntimeError("503 TEE_UNAVAILABLE")

        start_time = time.time()

        
        metadata = {
            "package_version": "1.0",
            "crypto_profile": "UPCE-Hybrid",
            "sender_id": str(sender_id),
            "receiver_id": str(receiver_id),
            "pqc": {},
            "fragments": []
        }
        
        temp_dir = tempfile.mkdtemp(prefix="pfce_upload_")
        
        # PQC Transfer-Level Setup using UPCE
        pqc_kek = None
        if crypto_engine and security_policy:
            upce_result = crypto_engine.initialize_transfer_security(
                sender_id="system", receiver_id=receiver_id, policy=security_policy
            )
            pqc_kek = upce_result.get("pqc_kek")
            metadata["pqc"] = upce_result.get("metadata", {"enabled": False})
        else:
            metadata["pqc"] = {"enabled": False}
        
        total_aes_time_ms = 0.0
        total_rsa_wrap_time_ms = 0.0
        total_ecdh_time_ms = 0.0
        
        # Master Hash for Zero-Trust verification
        master_hash = hashlib.sha256()
        
        file_stream.seek(0, 2)
        total_size = file_stream.tell()
        file_stream.seek(0)
        total_mb = round(total_size / (1024 * 1024), 2)
        
        total_bytes_processed = 0
        last_logged_bytes = 0
        
        # --- BLOCK 4.1: Calculate adaptive bounds based on Context Policy ---
        min_bytes = security_policy.get("min_chunk_bytes", 5 * 1024 * 1024) if security_policy else 5 * 1024 * 1024
        max_bytes = security_policy.get("max_chunk_bytes", 15 * 1024 * 1024) if security_policy else 15 * 1024 * 1024
        
        # Forward Secrecy: Claim a One-Time Receiver Prekey for this transfer
        transfer_id_basename = os.path.basename(pfce_package_path)
        prekey_public_pem = CryptoService.claim_prekey(receiver_id, transfer_id_basename)
        
        try:
            fragment_id = 0
            
            while True:
                # DYNAMIC FRAGMENTATION: True random polymorphic sizing per chunk
                chunk_size = random.randint(min_bytes, max_bytes)
                
                frag_src_path = os.path.join(temp_dir, f"raw_frag_{fragment_id}")
                chunk_hash_obj = hashlib.sha256()
                bytes_read = 0
                
                with open(frag_src_path, "wb") as f_raw:
                    while bytes_read < chunk_size:
                        read_amount = min(1024 * 1024, chunk_size - bytes_read)
                        chunk_part = file_stream.read(read_amount)
                        if not chunk_part or len(chunk_part) == 0:
                            break
                        f_raw.write(chunk_part)
                        chunk_hash_obj.update(chunk_part)
                        master_hash.update(chunk_part)
                        bytes_read += len(chunk_part)
                        
                if bytes_read == 0:
                    os.remove(frag_src_path)
                    break
                    
                chunk_hash = chunk_hash_obj.hexdigest()
                
                # Generate Deterministic AAD
                pqc_aad = None
                if pqc_kek:
                    pqc_aad = CryptoService.construct_pqc_aad(
                        transfer_id=os.path.basename(pfce_package_path),
                        receiver_id=receiver_id,
                        fragment_id=fragment_id,
                        key_version=metadata["pqc"].get("receiver_key_version")
                    )

                # Encrypt the variable chunk
                frag_stored_name = f"{stored_name_prefix}_frag_{fragment_id}"
                frag_result = CryptoService.encrypt_file_for_receiver(
                    frag_src_path, 
                    receiver_id, 
                    frag_stored_name, 
                    classification, 
                    pqc_kek=pqc_kek, 
                    pqc_aad=pqc_aad,
                    prekey_public_pem=prekey_public_pem,
                    transfer_id=transfer_id_basename,
                    sender_id=sender_id
                )
                
                try:
                    with open(frag_result.encrypted_path, "rb") as f_enc:
                        ciphertext_sha256 = hashlib.sha256(f_enc.read()).hexdigest()
                except OSError:
                    ciphertext_sha256 = ""

                try:
                    os.remove(frag_src_path)
                except OSError:
                    pass
                
                fragment_filename = os.path.basename(frag_result.encrypted_path)
                
                # Metadata Generation
                fragment_info = {
                    "fragment_id": fragment_id,
                    "filename": fragment_filename,
                    "encrypted_key": frag_result.encrypted_key,
                    "nonce": frag_result.nonce,
                    "ecdh_public_key": frag_result.ecdh_public_key,
                    "ecdh_wrapped_key": frag_result.ecdh_wrapped_key,
                    "ecdh_key_nonce": frag_result.ecdh_key_nonce,
                    "cipher_algorithm": frag_result.cipher_algorithm,
                    "pqc_wrapped_key": frag_result.pqc_wrapped_key,
                    "pqc_wrap_nonce": frag_result.pqc_wrap_nonce,
                    "hash": chunk_hash,
                    "ciphertext_sha256": ciphertext_sha256,
                    "size": bytes_read
                }
                metadata["fragments"].append(fragment_info)
                
                total_aes_time_ms += frag_result.aes_time_ms
                total_rsa_wrap_time_ms += frag_result.rsa_key_wrap_time_ms
                total_ecdh_time_ms += frag_result.ecdh_time_ms
                
                total_bytes_processed += bytes_read
                
                # Continuous AI Behavioural Monitoring
                if transfer_monitor:
                    transfer_monitor.update_telemetry(chunk_size=bytes_read)
                    if transfer_monitor.should_reanalyse():
                        try:
                            ai_result = transfer_monitor.reanalyze_transfer()
                            # Print to console for proof of evaluation mid-transfer
                            logger.info(f"Mid-transfer AI evaluation: score={ai_result.get('anomaly_score')}, level={ai_result.get('level')}")
                        except Exception as e:
                            if type(e).__name__ == 'TransferBlockedError':
                                logger.warning(f"Transfer blocked mid-flight: {e}")
                                raise
                            logger.error(f"Failed to reanalyze transfer: {e}")
                
                if progress_callback and (total_bytes_processed - getattr(self, '_last_cb_bytes', 0) >= 5 * 1024 * 1024 or bytes_read == 0):
                    processed_mb = round(total_bytes_processed / (1024 * 1024), 2)
                    percentage = round((total_bytes_processed / total_size) * 100, 2) if total_size > 0 else 0
                    progress_callback(processed_mb, total_mb, percentage)
                    setattr(self, '_last_cb_bytes', total_bytes_processed)
                    
                if total_bytes_processed - last_logged_bytes >= 50 * 1024 * 1024:
                    processed_mb = round(total_bytes_processed / (1024 * 1024), 2)
                    logger.info(f"Encryption progress: {processed_mb} MB / {total_mb} MB completed.")
                    last_logged_bytes = total_bytes_processed
                
                fragment_id += 1
                
            if client_signature_metadata:
                metadata["signature"] = client_signature_metadata
            else:
                logger.warning("No client signature metadata provided to PFCE engine")
                metadata["signature"] = {}

            metadata_path = os.path.join(temp_dir, "metadata.json")
            with open(metadata_path, 'w', encoding='utf-8') as f_meta:
                json.dump(metadata, f_meta, indent=2)
                
                
            with zipfile.ZipFile(pfce_package_path, 'w', zipfile.ZIP_STORED, allowZip64=True) as zipf:
                zipf.write(metadata_path, arcname="metadata.json")
                for frag in metadata["fragments"]:
                    real_frag_path = os.path.join(os.path.dirname(pfce_package_path), frag["filename"]) 
                    
                    if not os.path.exists(real_frag_path):
                        from app.database.db import ENCRYPTED_DIR
                        real_frag_path = str(ENCRYPTED_DIR / frag["filename"])

                    zipf.write(real_frag_path, arcname=frag["filename"])
                    
                    try:
                        os.remove(real_frag_path)
                    except OSError:
                        pass
                        
        finally:
            if pqc_kek and hasattr(pqc_kek, "wipe"):
                pqc_kek.wipe()
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        execution_time = time.time() - start_time
        
        unique_ciphers = list(set([f.get("cipher_algorithm", "Unknown") for f in metadata["fragments"]]))
        cipher_algorithm_used = ", ".join(unique_ciphers) if unique_ciphers else "None"
        
        try:
            with SessionLocal() as db:
                BlockchainService.append_block(
                    db=db,
                    event_type="PFCE_SIGNATURE_CREATED",
                    details={
                        "transfer_id": os.path.basename(pfce_package_path),
                        "sender_id": sender_id,
                        "receiver_id": receiver_id,
                        "signature_algorithm": metadata["signature"]["algorithm"],
                        "key_fingerprint": metadata["signature"]["key_fingerprint"],
                        "verification_result": "CREATED"
                    }
                )
        except Exception as e:
            logger.error(f"Failed to log signature creation: {e}")
        
        return PFCEUploadResult(
            pfce_package_path=pfce_package_path,
            execution_time_seconds=execution_time,
            aes_time_ms=round(total_aes_time_ms, 3),
            rsa_key_wrap_time_ms=round(total_rsa_wrap_time_ms, 3),
            ecdh_time_ms=round(total_ecdh_time_ms, 3),
            fragment_count=fragment_id,
            original_hash=master_hash.hexdigest(),
            cipher_algorithm=cipher_algorithm_used
        )

    def process_download_stream(self, pfce_package_path: str, receiver_id: str | int, crypto_engine=None, sender_public_key_spki: str = "") -> Generator[bytes, None, None]:
        if not os.path.exists(pfce_package_path):
            raise FileNotFoundError(f"PFCE package not found: {pfce_package_path}")
            
        def _log_failure(reason: str):
            try:
                with SessionLocal() as db:
                    BlockchainService.append_block(
                        db=db,
                        event_type="PFCE_SIGNATURE_FAILED",
                        details={
                            "transfer_id": os.path.basename(pfce_package_path),
                            "receiver_id": receiver_id,
                            "failure_reason_category": reason,
                            "verification_result": "FAILED"
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to log signature failure: {e}")

        try:
            with zipfile.ZipFile(pfce_package_path, 'r', allowZip64=True) as zipf:
                # Instead of extracting all, read metadata directly
                metadata_bytes = zipf.read('metadata.json')
                metadata = json.loads(metadata_bytes.decode('utf-8'))
                
            if not metadata.get("signature"):
                _log_failure("SIGNATURE_MISSING")
                raise ValueError("Digital signature missing. Package rejected.")
            
            sig_obj = metadata["signature"]
            signer_id = sig_obj.get("signer_id")
            if not signer_id:
                _log_failure("SIGNER_ID_MISSING")
                raise ValueError("Missing signer_id in signature metadata.")
                
            if str(signer_id) != str(metadata.get("sender_id")):
                _log_failure("SIGNER_ID_MISMATCH")
                raise ValueError("Signer identity substitution attempt. Declared signer does not match signed sender.")
            
            if sig_obj.get("algorithm") != "RSA-PSS-SHA256":
                _log_failure("UNSUPPORTED_SIGNATURE_ALGORITHM")
                raise ValueError("Unsupported signature algorithm. Only RSA-PSS-SHA256 is accepted.")
                
            key_size = CryptoService.get_public_key_size(signer_id)
            if key_size < 2048:
                _log_failure("KEY_SIZE_TOO_SMALL")
                raise ValueError(f"Trusted public key size {key_size} is less than the required 2048 bits.")
            
            if sig_obj.get("key_fingerprint") != CryptoService.get_spki_fingerprint(sender_public_key_spki):
                _log_failure("KEY_FINGERPRINT_MISMATCH")
                raise ValueError("Signature key fingerprint mismatch. Sender public-key substitution attempt detected.")
            
            # Verify signature using transfer payload
            transfer_id = os.path.basename(pfce_package_path).split('_', 1)[0]
            file_size = sum(f.get("size", 0) for f in metadata.get("fragments", []))
            
            sig_transfer_id = sig_obj.get("transfer_id", "")
            sig_file_size = sig_obj.get("file_size", file_size)
            sig_issued_at = sig_obj.get("signed_at", "")
            sig_nonce = sig_obj.get("nonce", "")
            sig_original_sha256 = sig_obj.get("original_file_sha256", "")
            
            canonical_payload = (
                f"UPCE-TRANSFER-SIGNATURE-V1\n"
                f"transfer_id={sig_transfer_id}\n"
                f"sender_id={signer_id}\n"
                f"receiver_id={receiver_id}\n"
                f"file_sha256={sig_original_sha256}\n"
                f"file_size={sig_file_size}\n"
                f"issued_at={sig_issued_at}\n"
                f"nonce={sig_nonce}"
            ).encode("utf-8")
            
            # Verify signature
            is_valid = CryptoService.verify_pfce_signature(
                canonical_manifest=canonical_payload,
                signature_b64=sig_obj.get("signature", ""),
                spki_base64=sender_public_key_spki
            )
            if not is_valid:
                _log_failure("SIGNATURE_INVALID")
                raise ValueError("Invalid RSA-PSS signature. Package tampered or corrupted.")
                
            try:
                with SessionLocal() as db:
                    BlockchainService.append_block(
                        db=db,
                        event_type="PFCE_SIGNATURE_VERIFIED",
                        details={
                            "transfer_id": os.path.basename(pfce_package_path),
                            "sender_id": signer_id,
                            "receiver_id": receiver_id,
                            "signature_algorithm": sig_obj.get("algorithm"),
                            "key_fingerprint": sig_obj.get("key_fingerprint"),
                            "verification_result": "VALID"
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to log signature verification: {e}")
                
            fragments = sorted(metadata.get("fragments", []), key=lambda x: x["fragment_id"])
            
            # Forward Secrecy: Retrieve and delete the receiver's one-time private prekey
            # (Deleted immediately to prevent future decryption if long-term keys are compromised)
            transfer_id_basename = os.path.basename(pfce_package_path)
            prekey_private_pem = CryptoService.get_and_delete_prekey(receiver_id, transfer_id_basename)
            
            # Extract PQC Transfer-Level KEK using UPCE
            pqc_kek = None
            pqc_meta = metadata.get("pqc", {})
            if pqc_meta.get("enabled") and crypto_engine:
                pqc_kek = crypto_engine.recover_transfer_security(receiver_id, pqc_meta)
            elif pqc_meta.get("enabled"):
                logger.warning("PQC is enabled in metadata, but no crypto_engine was provided for decapsulation.")
            
            try:
                with zipfile.ZipFile(pfce_package_path, 'r', allowZip64=True) as zipf:
                    for fragment in fragments:
                        try:
                            # Read fragment directly from zip
                            with zipf.open(fragment["filename"]) as f_frag:
                                encrypted_chunk = f_frag.read()
                        except KeyError:
                            raise ValueError(f"Missing fragment file: {fragment['filename']}")
                        
                    actual_ciphertext_hash = hashlib.sha256(encrypted_chunk).hexdigest()
                    if "ciphertext_sha256" in fragment and actual_ciphertext_hash != fragment["ciphertext_sha256"]:
                        _log_failure("CIPHERTEXT_HASH_MISMATCH")
                        raise ValueError(f"Ciphertext digest mismatch for fragment {fragment['fragment_id']}")
                        
                    expected_hash = fragment["hash"]
                    stored_name_approx = fragment["filename"].replace(".enc", "")
                    
                    aes_key = None
                    
                    try:
                        # 1. Attempt Post-Quantum Decapsulation (ML-KEM-768) using Transfer KEK
                        if pqc_kek and fragment.get("pqc_wrapped_key") and fragment.get("pqc_wrap_nonce"):
                            try:
                                pqc_aad = None
                                if "pqc" in metadata and "receiver_key_version" in metadata["pqc"]:
                                    pqc_aad = CryptoService.construct_pqc_aad(
                                        transfer_id=os.path.basename(pfce_package_path),
                                        receiver_id=receiver_id,
                                        fragment_id=fragment["fragment_id"],
                                        key_version=metadata["pqc"]["receiver_key_version"]
                                    )
                                    
                                aes_key = CryptoService.unwrap_pqc_key(
                                    pqc_kek=pqc_kek,
                                    pqc_wrapped_key_b64=fragment["pqc_wrapped_key"],
                                    pqc_wrap_nonce_b64=fragment["pqc_wrap_nonce"],
                                    pqc_aad=pqc_aad
                                )
                            except Exception as e:
                                logger.error(f"PQC unwrap failed: {e}")
                                _log_failure("PQC_UNWRAP_FAILED")
                                raise ValueError(f"PQC unwrap failed for fragment {fragment['fragment_id']}") from e
                        
                        # 2. Modern: ECDH with Prekey
                        if aes_key is None and fragment.get("ecdh_public_key") and fragment.get("ecdh_wrapped_key") and fragment.get("ecdh_key_nonce"):
                            try:
                                aes_key = CryptoService.unwrap_key_with_ecdh(
                                    receiver_id=receiver_id,
                                    ecdh_public_key_pem=fragment["ecdh_public_key"],
                                    ecdh_wrapped_key=fragment["ecdh_wrapped_key"],
                                    ecdh_key_nonce=fragment["ecdh_key_nonce"],
                                    stored_name=stored_name_approx,
                                    prekey_private_pem=prekey_private_pem,
                                    transfer_id=transfer_id_basename,
                                    sender_id=metadata.get("sender_id")
                                )
                            except Exception as e:
                                logger.error(f"ECDH unwrap failed for Modern transfer: {e}")
                                _log_failure("ECDH_UNWRAP_FAILED")
                                raise ValueError("ECDH unwrap failed. Forward secrecy prekey missing or invalid. Failing closed.") from e
                            
                            if aes_key is None:
                                _log_failure("ECDH_UNWRAP_RETURNED_NONE")
                                raise ValueError("ECDH unwrap returned None. Failing closed.")
                        
                        # 3. Legacy Fallback: RSA (Only if not a modern transfer)
                        if aes_key is None and not fragment.get("ecdh_public_key"):
                            aes_key = CryptoService.unwrap_key_with_rsa(
                                receiver_id=receiver_id, 
                                encrypted_key=fragment["encrypted_key"]
                            )
                        
                        cipher_algorithm = fragment.get("cipher_algorithm", "AES-256-GCM")
                        if cipher_algorithm == "ChaCha20-Poly1305":
                            decrypted_chunk = ChaCha20Poly1305(aes_key.memory).decrypt(
                                CryptoService._unb64(fragment["nonce"]), 
                                encrypted_chunk, 
                                None
                            )
                        else:
                            decrypted_chunk = AESGCM(aes_key.memory).decrypt(
                                CryptoService._unb64(fragment["nonce"]), 
                                encrypted_chunk, 
                                None
                            )
                        
                        actual_hash = hashlib.sha256(decrypted_chunk).hexdigest()
                        if actual_hash != expected_hash:
                            _log_failure("INTEGRITY_CHECK_FAILED")
                            raise ValueError(f"Integrity check failed for fragment {fragment['fragment_id']}. Hash mismatch.")
                            
                        yield decrypted_chunk
                        
                    finally:
                        if aes_key and hasattr(aes_key, "wipe"):
                            aes_key.wipe()
            finally:
                if pqc_kek and hasattr(pqc_kek, "wipe"):
                    pqc_kek.wipe()
        finally:
            pass