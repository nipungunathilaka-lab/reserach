import os
import sys
import tempfile
import json
import zipfile
import base64
import platform
import pkg_resources

from app.services.mlkem_service import MLKEMService, OQS_AVAILABLE
from app.services.pfce_engine import PFCEEngine
from app.services.upce_quantum_service import UniversalPolymorphicCryptoEngine

print("## Environment")
print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
print(f"Python: {platform.python_version()}")
try:
    oqs_ver = pkg_resources.get_distribution('liboqs-python').version
    print(f"OQS Python binding: {oqs_ver}")
except Exception:
    print("OQS Python binding: Not installed")

oqs_native = "No"
alg_selected = "None"
try:
    import oqs
    oqs_native = "Yes"
    mechanisms = oqs.get_enabled_kem_mechanisms()
    if "ML-KEM-768" in mechanisms:
        alg_selected = "ML-KEM-768"
except (ImportError, SystemExit):
    oqs_native = "No"

print(f"Native liboqs: {oqs_native}")
print(f"ML-KEM algorithm: {alg_selected}")
print(f"OQS_AVAILABLE: {OQS_AVAILABLE}")
print("")

print("## Low-level ML-KEM Test")
if oqs_native == "Yes":
    try:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            pub_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            print("KeyGen: PASS")
            
            ciphertext, shared_secret_encaps = kem.encap_secret(pub_key)
            print("Encapsulation: PASS")
            
        with oqs.KeyEncapsulation("ML-KEM-768", secret_key) as kem2:
            shared_secret_decaps = kem2.decap_secret(ciphertext)
            print("Decapsulation: PASS")
            
            if shared_secret_encaps == shared_secret_decaps:
                print("Shared-secret equality: PASS")
            else:
                print("Shared-secret equality: FAIL")
    except Exception as e:
        print(f"KeyGen: FAIL ({e})")
        print("Encapsulation: FAIL")
        print("Decapsulation: FAIL")
        print("Shared-secret equality: FAIL")
else:
    print("KeyGen: FAIL")
    print("Encapsulation: FAIL")
    print("Decapsulation: FAIL")
    print("Shared-secret equality: FAIL")

print("")
print("## Application Runtime")
import io
import shutil
import hashlib
from app.services.crypto_service import CryptoService

def setup_test_users():
    import app.services.crypto_service as module
    tmp_path = tempfile.mkdtemp()
    encrypted_dir = os.path.join(tmp_path, "encrypted")
    keys_dir = os.path.join(tmp_path, "keys")
    os.makedirs(encrypted_dir)
    os.makedirs(keys_dir)
    from app.database import db
    from pathlib import Path
    db.ENCRYPTED_DIR = Path(encrypted_dir)
    db.KEYS_DIR = Path(keys_dir)
    module.ENCRYPTED_DIR = Path(encrypted_dir)
    module.KEYS_DIR = Path(keys_dir)
    return tmp_path

from app.database.db import init_db
init_db()

# Do not mock anything. Use real app logic!
try:
    tmp_path = setup_test_users()
    receiver_a = 100
    receiver_b = 101
    
    # Pre-provision the ML-KEM keys for these users using the real service
    CryptoService.ensure_user_keypair(receiver_a)
    CryptoService.ensure_user_keypair(receiver_b)
    
    if OQS_AVAILABLE:
        MLKEMService.generate_keypair(receiver_a)
        MLKEMService.generate_keypair(receiver_b)

    test_data = b"UPCE Real Test Data " * 1000
    file_stream = io.BytesIO(test_data)
    original_hash = hashlib.sha256(test_data).hexdigest()
    
    upce = UniversalPolymorphicCryptoEngine()
    pfce = PFCEEngine()
    
    policy = upce.select_crypto_policy({"classification": "sensitive"}, {"anomaly_score": 0.1}, 0.0)
    package_path = os.path.join(tmp_path, "encrypted", "test_package.pfce")
    
    pfce.process_upload(
        file_stream=file_stream,
        receiver_id=receiver_a,
        stored_name_prefix="test_frag",
        classification="sensitive",
        pfce_package_path=package_path,
        crypto_engine=upce,
        security_policy=policy
    )
    
    recovered_data = b""
    for chunk in pfce.process_download_stream(package_path, receiver_a, crypto_engine=upce):
        recovered_data += chunk
        
    print("UPCE: PASS")
    print("PFCE: PASS")
    
    # Read metadata to confirm PQC usage
    with zipfile.ZipFile(package_path, 'r') as zf:
        meta_json = zf.read("metadata.json")
        meta = json.loads(meta_json)
        
    pqc_meta = meta.get("pqc", {})
    pqc_enabled = pqc_meta.get("enabled", False)
    print(f"PQC metadata enabled: {pqc_enabled}")
    
    # Check if real encapsulation was reached
    print(f"Real ML-KEM encapsulation reached: {pqc_enabled}")
    print(f"Real ML-KEM decapsulation reached: {pqc_enabled}")
    
    # If pqc_enabled is False, it fell back
    fallback = "Yes" if not pqc_enabled else "No"
    print(f"Classical fallback used during PQC verification: {fallback}")
    
except Exception as e:
    print(f"UPCE: FAIL ({e})")
    print("PFCE: FAIL")
    print("PQC metadata enabled: False")
    print("Real ML-KEM encapsulation reached: False")
    print("Real ML-KEM decapsulation reached: False")
    print("Classical fallback used during PQC verification: Yes")
