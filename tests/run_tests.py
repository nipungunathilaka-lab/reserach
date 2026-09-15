import os
import sys

# Add backend to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from fastapi.testclient import TestClient
from app.main import app
from app.database.db import SessionLocal
from app.database.models import ECDHPrekey
import tempfile

client = TestClient(app)

def test_prekey_upload():
    payload = {
        "user_id": "1",
        "prekeys": [
            {
                "prekey_id": "test_prekey_1",
                "public_key_pem": "dummy_public_key_pem"
            }
        ]
    }
    response = client.post("/internal/crypto/prekeys/upload", json=payload)
    assert response.status_code == 200
    
    with SessionLocal() as db:
        prekey = db.query(ECDHPrekey).filter(ECDHPrekey.prekey_id == "test_prekey_1").first()
        assert prekey is not None
        assert prekey.private_key_pem is None
        db.delete(prekey)
        db.commit()
    print("test_prekey_upload passed")

def test_claim_prekey():
    response = client.get("/internal/crypto/prekeys/claim/99999")
    assert response.status_code == 404
    print("test_claim_prekey passed")

def test_strict_e2ee_encrypt():
    files = {'file': ('dummy.txt', b'dummy_ciphertext_data')}
    data = {
        "sender_id": "1",
        "receiver_id": "2",
        "is_strict_e2ee": "true",
        "wrapped_key": "dummy_wrapped",
        "wrap_nonce": "dummy_nonce",
        "ephemeral_public": "dummy_ephemeral"
    }
    
    response = client.post("/internal/crypto/encrypt", files=files, data=data)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["malware_scan_status"] == "SKIPPED_E2EE"
    assert res_data["cipher_algorithm"] == "Strict E2EE (AES-256-GCM + ECDH-P256)"
    assert res_data["ecdh_wrapped_key"] == "dummy_wrapped"
    print("test_strict_e2ee_encrypt passed")

def test_strict_e2ee_decrypt():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"dummy_ciphertext_data")
        tmp_path = tmp.name
        
    try:
        payload = {
            "encrypted_path": tmp_path,
            "receiver_id": "2",
            "is_strict_e2ee": True
        }
        response = client.post("/internal/crypto/decrypt", json=payload)
        assert response.status_code == 200
        assert response.content == b"dummy_ciphertext_data"
        print("test_strict_e2ee_decrypt passed")
    finally:
        os.remove(tmp_path)

if __name__ == "__main__":
    test_prekey_upload()
    test_claim_prekey()
    test_strict_e2ee_encrypt()
    test_strict_e2ee_decrypt()
    print("All tests passed.")
