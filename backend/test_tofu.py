import pytest
pytestmark = [pytest.mark.unit]
import pytest
import uuid
import jwt
import os
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
import sys
sys.modules['web3'] = MagicMock()
sys.modules['web3.middleware'] = MagicMock()
sys.modules['eth_account'] = MagicMock()

from app.main import app
from app.security.internal_auth import INTERNAL_API_SECRET
from app.services.crypto_service import CryptoService

client = TestClient(app)

# Helper to generate a valid internal service token
def get_token(method="POST", path="/internal/crypto/encrypt"):
    return jwt.encode({
        "service": "node-api", 
        "iss": "node-api", 
        "aud": "fastapi-engine", 
        "jti": str(uuid.uuid4()),
        "req_method": method,
        "req_path": path
    }, INTERNAL_API_SECRET, algorithm="HS256")

@patch("app.security.internal_auth.get_redis")
def test_jwt_context_binding(mock_get_redis):
    # Mock redis to always return True for SETNX (no replay)
    mock_redis = MagicMock()
    mock_redis.set.return_value = True
    mock_get_redis.return_value = mock_redis
    
    # 1. Valid Context
    token = get_token("POST", "/internal/crypto/ensure_keys")
    res = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    
    # 2. Invalid Method Context
    token2 = get_token("GET", "/internal/crypto/ensure_keys")
    res2 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token2}"})
    assert res2.status_code == 403
    assert "HTTP Method context mismatch" in res2.text
    
    # 3. Invalid Path Context
    token3 = get_token("POST", "/internal/crypto/wrong_path")
    res3 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token3}"})
    assert res3.status_code == 403
    assert "HTTP Path context mismatch" in res3.text

@patch("app.security.internal_auth.get_redis")
def test_jwt_replay_protection(mock_get_redis):
    mock_redis = MagicMock()
    
    # First time SETNX succeeds (returns True)
    mock_redis.set.return_value = True
    mock_get_redis.return_value = mock_redis
    
    token = get_token("POST", "/internal/crypto/ensure_keys")
    res1 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200
    
    # Second time SETNX fails (returns False - key already exists)
    mock_redis.set.return_value = False
    res2 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401
    assert "Replayed JTI detected" in res2.text

@patch("app.routes.internal_engine_routes.CryptoService.verify_client_signature")
@patch("app.routes.internal_engine_routes.key_integrity_monitor.verify_public_key")
@patch("app.security.internal_auth.get_redis")
def test_tofu_logic(mock_get_redis, mock_verify_public_key, mock_verify_signature):
    mock_redis = MagicMock()
    mock_redis.set.return_value = True
    mock_get_redis.return_value = mock_redis
    
    token = get_token("POST", "/internal/crypto/encrypt")
    
    # Dummy file upload data
    files = {"file": ("test.txt", b"hello world")}
    data = {
        "sender_id": "100",
        "receiver_id": "200",
        "client_signature": "dummy_sig",
        "sender_public_key_spki": "dummy_spki",
        "original_file_sha256": CryptoService.sha256_bytes(b"hello world")
    }
    
    # 1. same trusted key + valid signature -> PASS (200 OK or 406 AI Blocked, but not 403 Substitution)
    mock_verify_public_key.return_value = (True, "trusted_fp")
    mock_verify_signature.return_value = True
    res1 = client.post("/internal/crypto/encrypt", data=data, files=files, headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code != 403 # Might be 406 due to AI or 200 OK, but not 403 Forbidden Key
    
    # 2. same trusted key + different legitimate signature -> PASS
    data["client_signature"] = "another_legit_sig"
    mock_verify_public_key.return_value = (True, "trusted_fp")
    mock_verify_signature.return_value = True
    res2 = client.post("/internal/crypto/encrypt", data=data, files=files, headers={"Authorization": f"Bearer {get_token()}"})
    assert res2.status_code != 403
    
    # 3. same trusted key + incorrect signature -> FAIL
    mock_verify_public_key.return_value = (True, "trusted_fp")
    mock_verify_signature.return_value = False
    res3 = client.post("/internal/crypto/encrypt", data=data, files=files, headers={"Authorization": f"Bearer {get_token()}"})
    assert res3.status_code == 403
    assert "Invalid digital signature" in res3.text
    
    # 4. substituted public key -> FAIL
    mock_verify_public_key.return_value = (False, "trusted_fp")
    # Even if signature is mathematically valid for the rogue key, it should fail before verifying
    mock_verify_signature.return_value = True 
    res4 = client.post("/internal/crypto/encrypt", data=data, files=files, headers={"Authorization": f"Bearer {get_token()}"})
    assert res4.status_code == 403
    assert "Public key substitution attempt detected" in res4.text
