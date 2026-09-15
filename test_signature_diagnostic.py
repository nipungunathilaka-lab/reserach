import sys
import os
import time
import base64
import json
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.crypto_service import CryptoService

def run_test():
    print("=== SIGNATURE DIAGNOSTIC TEST ===")
    
    # 1. Generate RSA-PSS test key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Export public key SPKI
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_base64 = base64.b64encode(spki_der).decode('utf-8')
    
    # 2. Generate known transfer context
    transfer_id = "test-transfer-id"
    sender_id = "test-sender"
    receiver_id = "test-receiver"
    file_sha256 = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
    file_size = 12345
    issued_at = "2026-09-11T16:30:20.123Z"
    nonce = "test-nonce-123456"
    
    # 3. Frontend-style canonicalization
    frontend_payload_str = (
        f"UPCE-TRANSFER-SIGNATURE-V1\n"
        f"transfer_id={transfer_id}\n"
        f"sender_id={sender_id}\n"
        f"receiver_id={receiver_id}\n"
        f"file_sha256={file_sha256}\n"
        f"file_size={file_size}\n"
        f"issued_at={issued_at}\n"
        f"nonce={nonce}"
    )
    frontend_payload_bytes = frontend_payload_str.encode('utf-8')
    frontend_payload_sha256 = hashlib.sha256(frontend_payload_bytes).hexdigest()
    
    # 4. Sign
    signature = private_key.sign(
        frontend_payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # 5. Backend-style canonicalization
    backend_payload_bytes = (
        f"UPCE-TRANSFER-SIGNATURE-V1\n"
        f"transfer_id={transfer_id}\n"
        f"sender_id={sender_id}\n"
        f"receiver_id={receiver_id}\n"
        f"file_sha256={file_sha256}\n"
        f"file_size={file_size}\n"
        f"issued_at={issued_at}\n"
        f"nonce={nonce}"
    ).encode("utf-8")
    backend_payload_sha256 = hashlib.sha256(backend_payload_bytes).hexdigest()
    
    # 6. Verify
    print(f"Frontend SHA256: {frontend_payload_sha256}")
    print(f"Backend SHA256:  {backend_payload_sha256}")
    
    is_valid = CryptoService.verify_client_signature(
        canonical_payload=backend_payload_bytes,
        signature_b64=signature_b64,
        spki_base64=spki_base64
    )
    
    print(f"Signature Valid: {is_valid}")
    if is_valid:
        print("Test passed successfully.")
    else:
        print("Test failed: Signature validation mismatch.")
        
if __name__ == "__main__":
    run_test()
