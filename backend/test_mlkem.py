import pytest
pytestmark = [pytest.mark.integration, pytest.mark.pqc]
import os
import io
import pytest
import oqs
from unittest.mock import patch, MagicMock

# Environment setup for tests
os.environ["MLKEM_PRIVATE_KEY_MASTER_KEY"] = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=" # exactly 32 'a's encoded
os.environ["PQC_ENABLED"] = "true"
import tempfile
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db")
os.close(temp_db_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{temp_db_path}"

from app.core.config import settings
from app.database.db import Base, engine, SessionLocal
from app.database.models import PQCKey
from app.services.mlkem_service import MLKEMService
from app.services.pfce_engine import PFCEEngine
from app.services.upce_quantum_service import UniversalPolymorphicCryptoEngine

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def test_user(db_session):
    return "test_user_id_1"

@pytest.fixture
def test_receiver(db_session):
    return "test_receiver_id"

def test_oqs_availability():
    """Test 1 - ML-KEM library availability"""
    mechanisms = oqs.get_enabled_kem_mechanisms()
    assert "ML-KEM-768" in mechanisms

def test_real_key_generation(test_user, db_session):
    """Test 2 - Real key generation"""
    MLKEMService.generate_keypair(test_user)
    pqc_key = db_session.query(PQCKey).filter_by(user_id=test_user, is_active=True).first()
    assert pqc_key is not None
    assert pqc_key.algorithm == "ML-KEM-768"
    assert pqc_key.key_version == 1
    assert len(pqc_key.public_key) > 0
    assert len(pqc_key.encrypted_private_key) > 0
    
    # Generate again to test rotation and different keys
    MLKEMService.generate_keypair(test_user)
    pqc_key_v2 = db_session.query(PQCKey).filter_by(user_id=test_user, is_active=True).first()
    assert pqc_key_v2.key_version == 2
    assert pqc_key_v2.public_key != pqc_key.public_key

def test_encapsulation_roundtrip(test_receiver):
    """Test 3 - Encapsulation/decapsulation round trip"""
    MLKEMService.generate_keypair(test_receiver)
    receiver_pqc_info = MLKEMService.get_active_public_key(test_receiver)
    receiver_pub_key = receiver_pqc_info["public_key"]
    receiver_key_version = receiver_pqc_info["key_version"]

    kem_ciphertext, sender_shared_secret = MLKEMService.encapsulate(receiver_pub_key)
    
    # Decapsulate
    receiver_shared_secret = MLKEMService.decapsulate(kem_ciphertext, test_receiver, receiver_key_version)
    
    assert sender_shared_secret.bytes == receiver_shared_secret.bytes
    assert len(sender_shared_secret.bytes) == 32
    
    sender_shared_secret.wipe()
    receiver_shared_secret.wipe()

def test_receiver_isolation(test_user, test_receiver):
    """Test 4 - Receiver isolation"""
    MLKEMService.generate_keypair(test_user)
    MLKEMService.generate_keypair(test_receiver)
    
    receiver_pqc_info = MLKEMService.get_active_public_key(test_receiver)
    
    # Encapsulate for Receiver
    kem_ciphertext, shared_secret = MLKEMService.encapsulate(receiver_pqc_info["public_key"])
    
    # Attempt to decapsulate with User A's key (wrong receiver)
    user_pqc_info = MLKEMService.get_active_public_key(test_user)
    
    wrong_shared_secret = MLKEMService.decapsulate(kem_ciphertext, test_user, user_pqc_info["key_version"])
    
    # ML-KEM returns a pseudo-random string on failure instead of exception
    assert wrong_shared_secret.bytes != shared_secret.bytes

def test_database_persistence(test_user, db_session):
    """Test 5 - Database persistence"""
    MLKEMService.generate_keypair(test_user)
    info = MLKEMService.get_active_public_key(test_user)
    
    # Simulate a new process decrypting
    secret_key_buf = MLKEMService._get_secret_key(test_user, info["key_version"])
    assert len(secret_key_buf.bytes) > 0
    secret_key_buf.wipe()
    
    pqc_info = MLKEMService.get_active_public_key(test_user.id)
    kem_ciphertext, sender_shared_secret = MLKEMService.encapsulate(pqc_info["public_key"])
    
    # This proves we load from DB
    receiver_shared_secret = MLKEMService.decapsulate(kem_ciphertext, test_user.id, pqc_info["key_version"])
    assert sender_shared_secret.bytes == receiver_shared_secret.bytes

def test_end_to_end_pfce(test_user, test_receiver):
    """Test 6 - End-to-end PFCE test"""
    # 1. Receiver must have PQC key
    MLKEMService.generate_keypair(test_receiver.id)
    
    # 2. Original file data
    original_data = os.urandom(5 * 1024 * 1024) # 5 MB file
    file_stream = io.BytesIO(original_data)
    
    # 3. Encrypt
    engine = PFCEEngine()
    package_path = "test_end_to_end.pfce"
    try:
        upce = UniversalPolymorphicCryptoEngine()
        policy = upce.select_crypto_policy({"classification": "sensitive"}, {"anomaly_score": 0.0}, 0.0)
        result = engine.process_upload(file_stream, 1, test_receiver.id, "e2e_test", "Sensitive", package_path, crypto_engine=upce, security_policy=policy)
        assert os.path.exists(package_path)
        
        # 4. Decrypt
        decrypted_chunks = []
        for chunk in engine.process_download_stream(package_path, test_receiver.id, crypto_engine=upce):
            decrypted_chunks.append(chunk)
            
        decrypted_data = b"".join(decrypted_chunks)
        
        # 5. Assert identity
        assert original_data == decrypted_data
    finally:
        if os.path.exists(package_path):
            os.remove(package_path)

def test_corrupted_kem_ciphertext(test_receiver):
    """Test 7 - Corrupted KEM ciphertext"""
    MLKEMService.generate_keypair(test_receiver.id)
    receiver_pqc_info = MLKEMService.get_active_public_key(test_receiver.id)
    kem_ciphertext, sender_shared_secret = MLKEMService.encapsulate(receiver_pqc_info["public_key"])
    
    # Corrupt ciphertext
    corrupted_ciphertext = bytearray(kem_ciphertext)
    corrupted_ciphertext[0] ^= 0xFF
    corrupted_ciphertext = bytes(corrupted_ciphertext)
    
    wrong_shared_secret = MLKEMService.decapsulate(corrupted_ciphertext, test_receiver.id, receiver_pqc_info["key_version"])
    
    assert wrong_shared_secret != sender_shared_secret

def test_corrupted_wrapped_key(test_user, test_receiver):
    """Test 8 - Corrupted wrapped key"""
    MLKEMService.generate_keypair(test_receiver.id)
    original_data = os.urandom(1024 * 1024)
    file_stream = io.BytesIO(original_data)
    engine = PFCEEngine()
    package_path = "test_corrupt.pfce"
    try:
        upce = UniversalPolymorphicCryptoEngine()
        policy = upce.select_crypto_policy({"classification": "sensitive"}, {"anomaly_score": 0.0}, 0.0)
        engine.process_upload(file_stream, 1, test_receiver.id, "corrupt_test", "Sensitive", package_path, crypto_engine=upce, security_policy=policy)
        
        # Modify the package to corrupt the wrapped key
        import zipfile
        import json
        with zipfile.ZipFile(package_path, 'r') as zipr:
            metadata = json.loads(zipr.read('metadata.json'))
            frag_name = metadata['fragments'][0]['filename']
            frag_data = zipr.read(frag_name)
            
        metadata['fragments'][0]['pqc_wrapped_key'] = "AAAA" + metadata['fragments'][0]['pqc_wrapped_key'][4:]
        
        with zipfile.ZipFile(package_path, 'w') as zipw:
            zipw.writestr('metadata.json', json.dumps(metadata))
            zipw.writestr(frag_name, frag_data)
            
        with pytest.raises(Exception):
            list(engine.process_download_stream(package_path, test_receiver.id, crypto_engine=upce))
    finally:
        if os.path.exists(package_path):
            os.remove(package_path)

def test_aad_modification_fails(test_receiver):
    """Test 8b - Corrupted AAD"""
    MLKEMService.generate_keypair(test_receiver.id)
    original_data = os.urandom(1024)
    file_stream = io.BytesIO(original_data)
    engine = PFCEEngine()
    package_path = "test_aad_corrupt.pfce"
    try:
        upce = UniversalPolymorphicCryptoEngine()
        policy = upce.select_crypto_policy({"classification": "sensitive"}, {"anomaly_score": 0.0}, 0.0)
        engine.process_upload(file_stream, 1, test_receiver.id, "aad_test", "Sensitive", package_path, crypto_engine=upce, security_policy=policy)
        
        # Modify the receiver_id in metadata (corrupting AAD conceptually)
        import zipfile
        import json
        with zipfile.ZipFile(package_path, 'r') as zipr:
            metadata = json.loads(zipr.read('metadata.json'))
            frag_name = metadata['fragments'][0]['filename']
            frag_data = zipr.read(frag_name)
            
        metadata['pqc']['receiver_key_version'] = 999  # Corrupting AAD logic
        
        with zipfile.ZipFile(package_path, 'w') as zipw:
            zipw.writestr('metadata.json', json.dumps(metadata))
            zipw.writestr(frag_name, frag_data)
            
        with pytest.raises(Exception):
            list(engine.process_download_stream(package_path, test_receiver.id, crypto_engine=upce))
    finally:
        if os.path.exists(package_path):
            os.remove(package_path)

def test_missing_oqs(monkeypatch):
    """Test 9 - Missing OQS / PQC Disabled Behavior"""
    monkeypatch.setattr("app.core.config.settings.pqc_required", True)
    
    with patch("app.services.mlkem_service.OQS_AVAILABLE", False):
        with pytest.raises(RuntimeError) as exc_info:
            MLKEMService.startup_check()
        assert "PQC is enabled but liboqs-python could not be imported" in str(exc_info.value)

def test_key_rotation(test_user, test_receiver):
    """Test 10 - Key rotation"""
    # Version 1
    MLKEMService.generate_keypair(test_receiver.id)
    v1_info = MLKEMService.get_active_public_key(test_receiver.id)
    assert v1_info["key_version"] == 1
    
    data1 = b"File A Content"
    engine = PFCEEngine()
    upce = UniversalPolymorphicCryptoEngine()
    policy = upce.select_crypto_policy({"classification": "sensitive"}, {"anomaly_score": 0.0}, 0.0)
    engine.process_upload(io.BytesIO(data1), 1, test_receiver.id, "file_a", "Sensitive", "file_a.pfce", crypto_engine=upce, security_policy=policy)
    
    # Rotate to Version 2
    MLKEMService.rotate_keypair(test_receiver.id)
    v2_info = MLKEMService.get_active_public_key(test_receiver.id)
    assert v2_info["key_version"] == 2
    
    data2 = b"File B Content"
    engine.process_upload(io.BytesIO(data2), 1, test_receiver.id, "file_b", "Sensitive", "file_b.pfce", crypto_engine=upce, security_policy=policy)
    
    try:
        # File A decrypts using key version 1
        decrypted_a = b"".join(list(engine.process_download_stream("file_a.pfce", test_receiver.id, crypto_engine=upce)))
        assert decrypted_a == data1
        
        # File B decrypts using key version 2
        decrypted_b = b"".join(list(engine.process_download_stream("file_b.pfce", test_receiver.id, crypto_engine=upce)))
        assert decrypted_b == data2
    finally:
        for f in ["file_a.pfce", "file_b.pfce"]:
            if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    pytest.main(["-v", "test_mlkem.py"])
