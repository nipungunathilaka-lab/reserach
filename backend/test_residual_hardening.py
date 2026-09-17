import pytest
pytestmark = [pytest.mark.integration, pytest.mark.redis]
import pytest
from fastapi.testclient import TestClient
import jwt
import os
import uuid
import time

from app.main import app
from app.security.internal_auth import INTERNAL_API_SECRET
from app.security.internal_auth import get_redis

client = TestClient(app)

def test_internal_auth_missing_token():
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"})
    assert response.status_code == 401
    assert "Missing or invalid internal service token" in response.text

def test_internal_auth_invalid_signature():
    token = jwt.encode({"service": "node-api", "iss": "node-api", "aud": "fastapi-engine", "jti": str(uuid.uuid4())}, "wrong-secret", algorithm="HS256")
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "SERVICE_AUTH_FAILURE: Invalid internal service token" in response.text

def test_internal_auth_wrong_issuer():
    token = jwt.encode({"service": "node-api", "iss": "wrong-issuer", "aud": "fastapi-engine", "jti": str(uuid.uuid4())}, INTERNAL_API_SECRET, algorithm="HS256")
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "SERVICE_AUTH_FAILURE: Invalid token issuer" in response.text

def test_internal_auth_wrong_audience():
    token = jwt.encode({"service": "node-api", "iss": "node-api", "aud": "wrong-audience", "jti": str(uuid.uuid4())}, INTERNAL_API_SECRET, algorithm="HS256")
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "SERVICE_AUTH_FAILURE: Invalid token audience" in response.text

def test_internal_auth_expired():
    token = jwt.encode({"service": "node-api", "iss": "node-api", "aud": "fastapi-engine", "jti": str(uuid.uuid4()), "exp": time.time() - 10}, INTERNAL_API_SECRET, algorithm="HS256")
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "SERVICE_AUTH_FAILURE: Internal service token expired" in response.text

def test_internal_auth_replayed_jti():
    jti = str(uuid.uuid4())
    token = jwt.encode({"service": "node-api", "iss": "node-api", "aud": "fastapi-engine", "jti": jti}, INTERNAL_API_SECRET, algorithm="HS256")
    
    # First request should pass auth (though might fail business logic if DB not setup, but we expect 200 for ensure_keys)
    response1 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response1.status_code == 200
    
    # Second request with same token should fail due to replay
    response2 = client.post("/internal/crypto/ensure_keys", data={"user_id": "123"}, headers={"Authorization": f"Bearer {token}"})
    assert response2.status_code == 401
    assert "SERVICE_AUTH_FAILURE: Replayed JTI detected" in response2.text

def test_internal_auth_valid():
    jti = str(uuid.uuid4())
    token = jwt.encode({"service": "node-api", "iss": "node-api", "aud": "fastapi-engine", "jti": jti}, INTERNAL_API_SECRET, algorithm="HS256")
    response = client.post("/internal/crypto/ensure_keys", data={"user_id": "999"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

if __name__ == "__main__":
    print("Running test_internal_auth_missing_token...")
    test_internal_auth_missing_token()
    print("Running test_internal_auth_invalid_signature...")
    test_internal_auth_invalid_signature()
    print("Running test_internal_auth_wrong_issuer...")
    test_internal_auth_wrong_issuer()
    print("Running test_internal_auth_wrong_audience...")
    test_internal_auth_wrong_audience()
    print("Running test_internal_auth_expired...")
    test_internal_auth_expired()
    print("Running test_internal_auth_replayed_jti...")
    test_internal_auth_replayed_jti()
    print("Running test_internal_auth_valid...")
    test_internal_auth_valid()
    print("All tests passed!")
