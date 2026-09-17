import pytest
import os
from fastapi.testclient import TestClient
from app.main import app
from app.database.db import SessionLocal
from app.database.models import ECDHPrekey
from sqlalchemy import text

client = TestClient(app)

def test_prekey_upload_allows_null_private_key():
    """Test that prekeys can be uploaded with null private keys (Simulated Server-Bypass)."""
    # We will hit the /internal/crypto/prekeys/upload endpoint
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
    
    # Verify in DB
    with SessionLocal() as db:
        prekey = db.query(ECDHPrekey).filter(ECDHPrekey.prekey_id == "test_prekey_1").first()
        assert prekey is not None
        assert prekey.private_key_pem is None
        
        # Cleanup
        db.delete(prekey)
        db.commit()

def test_claim_prekey_returns_404_when_none_available():
    """Ensure server does not auto-generate server-side keys when claiming fails."""
    response = client.get("/internal/crypto/prekeys/claim/99999")
    assert response.status_code == 404
    assert "No unconsumed prekeys available" in response.text

def test_simulated_bypass_encrypt():
    """Test that simulated server bypass disables PFCE encryption and malware scanning."""
    # We'll upload a dummy file to /internal/crypto/encrypt
    # and pass is_simulated_bypass = "true"
    
    files = {'file': ('dummy.txt', b'dummy_ciphertext_data')}
    data = {
        "sender_id": "1",
        "receiver_id": "2",
        "is_simulated_bypass": "true",
        "wrapped_key": "dummy_wrapped",
        "wrap_nonce": "dummy_nonce",
        "ephemeral_public": "dummy_ephemeral"
    }
    
    response = client.post("/internal/crypto/encrypt", files=files, data=data)
    assert response.status_code == 200
    res_data = response.json()
    
    # Check that malware scan was skipped
    assert res_data["malware_scan_status"] == "SKIPPED_BYPASS"
    assert res_data["scanner"] == "Simulated Server-Bypass"
    assert res_data["malware_verdict"] == "CLEAN"
    
    # Check that PFCE encryption was bypassed
    assert res_data["cipher_algorithm"] == "Simulated Server-Bypass (AES-256-GCM + ECDH-P256)"
    assert res_data["encrypted_key"] == ""
    assert res_data["ecdh_wrapped_key"] == "dummy_wrapped"
    assert res_data["nonce"] == "dummy_nonce"
    assert res_data["ecdh_public_key"] == "dummy_ephemeral"

def test_simulated_bypass_decrypt():
    """Test that is_simulated_bypass=true bypasses PFCE decryption."""
    # First we need a dummy file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"dummy_ciphertext_data")
        tmp_path = tmp.name
        
    try:
        payload = {
            "encrypted_path": tmp_path,
            "receiver_id": "2",
            "is_simulated_bypass": True
        }
        response = client.post("/internal/crypto/decrypt", json=payload)
        assert response.status_code == 200
        assert response.content == b"dummy_ciphertext_data"
    finally:
        os.remove(tmp_path)
