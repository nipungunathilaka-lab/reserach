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

    def _get_adaptive_chunk_range(self, classification):
        c = (classification or "").strip().lower()

        if c in ["sensitive", "confidential", "restricted", "secret"]:
            return 512 * 1024, 2 * 1024 * 1024

        elif c in ["internal", "private"]:
            return 2 * 1024 * 1024, 5 * 1024 * 1024

        else:
            return 5 * 1024 * 1024, 15 * 1024 * 1024


    def process_upload(self, file_stream: io.IOBase, receiver_id: str | int, stored_name_prefix: str, classification: str, pfce_package_path: str, progress_callback=None) -> PFCEUploadResult:
        """
        Reads dynamically from the stream, slices into polymorphic fragments,
        encrypts using CryptoService, and packages into a .pfce ZIP.
        """
        start_time = time.time()
        
        metadata = {
            "fragments": []
        }
        
        temp_dir = tempfile.mkdtemp(prefix="pfce_upload_")
        
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
        min_bytes, max_bytes = self._get_adaptive_chunk_range(classification)
        
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
                
                # Encrypt the variable chunk
                frag_stored_name = f"{stored_name_prefix}_frag_{fragment_id}"
                frag_result = CryptoService.encrypt_file_for_receiver(
                    frag_src_path, receiver_id, frag_stored_name, classification
                )
                
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
                    "pqc_public_key": frag_result.pqc_public_key,
                    "pqc_ciphertext": frag_result.pqc_ciphertext,
                    "hash": chunk_hash,
                    "size": bytes_read
                }
                metadata["fragments"].append(fragment_info)
                
                total_aes_time_ms += frag_result.aes_time_ms
                total_rsa_wrap_time_ms += frag_result.rsa_key_wrap_time_ms
                total_ecdh_time_ms += frag_result.ecdh_time_ms
                
                total_bytes_processed += bytes_read
                
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
                
            metadata_path = os.path.join(temp_dir, "metadata.json")
            with open(metadata_path, 'w', encoding='utf-8') as f_meta:
                json.dump(metadata, f_meta, indent=2)
                
            with zipfile.ZipFile(pfce_package_path, 'w', zipfile.ZIP_STORED) as zipf:
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
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        execution_time = time.time() - start_time
        
        unique_ciphers = list(set([f.get("cipher_algorithm", "Unknown") for f in metadata["fragments"]]))
        cipher_algorithm_used = ", ".join(unique_ciphers) if unique_ciphers else "None"
        
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

    def process_download_stream(self, pfce_package_path: str, receiver_id: str | int) -> Generator[bytes, None, None]:
        if not os.path.exists(pfce_package_path):
            raise FileNotFoundError(f"PFCE package not found: {pfce_package_path}")
            
        temp_dir = tempfile.mkdtemp(prefix="pfce_download_")
        
        try:
            with zipfile.ZipFile(pfce_package_path, 'r') as zipf:
                zipf.extractall(temp_dir)
                
            metadata_path = os.path.join(temp_dir, "metadata.json")
            if not os.path.exists(metadata_path):
                raise ValueError("Invalid PFCE package: missing metadata.json")
                
            with open(metadata_path, 'r', encoding='utf-8') as f_meta:
                metadata = json.load(f_meta)
                
            fragments = sorted(metadata.get("fragments", []), key=lambda x: x["fragment_id"])
            
            for fragment in fragments:
                frag_path = os.path.join(temp_dir, fragment["filename"])
                if not os.path.exists(frag_path):
                    raise ValueError(f"Missing fragment file: {fragment['filename']}")
                    
                with open(frag_path, 'rb') as f_frag:
                    encrypted_chunk = f_frag.read()
                    
                expected_hash = fragment["hash"]
                stored_name_approx = fragment["filename"].replace(".enc", "")
                
                aes_key = None
                
                # 1. Attempt Post-Quantum Decapsulation (ML-KEM-768)
                if fragment.get("pqc_ciphertext") and fragment.get("pqc_public_key") and fragment.get("pqc_ciphertext") != "pqc_kyber_ciphertext_mock":
                    try:
                        aes_key = CryptoService.unwrap_key_with_pqc(
                            receiver_id=receiver_id,
                            pqc_ciphertext_b64=fragment["pqc_ciphertext"],
                            pqc_public_key_combined=fragment["pqc_public_key"],
                            stored_name=stored_name_approx
                        )
                    except Exception as e:
                        logger.error(f"PQC unwrap failed: {e}")
                
                # 2. Fallback to ECDH
                if aes_key is None and fragment.get("ecdh_public_key") and fragment.get("ecdh_wrapped_key") and fragment.get("ecdh_key_nonce"):
                    try:
                        aes_key = CryptoService.unwrap_key_with_ecdh(
                            receiver_id=receiver_id,
                            ecdh_public_key_pem=fragment["ecdh_public_key"],
                            ecdh_wrapped_key=fragment["ecdh_wrapped_key"],
                            ecdh_key_nonce=fragment["ecdh_key_nonce"],
                            stored_name=stored_name_approx
                        )
                    except Exception as e:
                        logger.error(f"ECDH unwrap failed: {e}")
                
                # 3. Fallback to RSA
                if aes_key is None:
                    aes_key = CryptoService.unwrap_key_with_rsa(
                        receiver_id=receiver_id, 
                        encrypted_key=fragment["encrypted_key"]
                    )
                
                cipher_algorithm = fragment.get("cipher_algorithm", "AES-256-GCM")
                if cipher_algorithm == "ChaCha20-Poly1305":
                    decrypted_chunk = ChaCha20Poly1305(aes_key).decrypt(
                        CryptoService._unb64(fragment["nonce"]), 
                        encrypted_chunk, 
                        None
                    )
                else:
                    decrypted_chunk = AESGCM(aes_key).decrypt(
                        CryptoService._unb64(fragment["nonce"]), 
                        encrypted_chunk, 
                        None
                    )
                
                actual_hash = hashlib.sha256(decrypted_chunk).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError(f"Integrity check failed for fragment {fragment['fragment_id']}. Hash mismatch.")
                    
                yield decrypted_chunk
                
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)