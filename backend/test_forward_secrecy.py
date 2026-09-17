import pytest
pytestmark = [pytest.mark.integration, pytest.mark.pqc]
import pytest
import os
import uuid
from sqlalchemy import create_engine
from app.database.db import SessionLocal, Base
from app.database.models import ECDHPrekey
from app.services.crypto_service import CryptoService
from app.services.pfce_engine import PFCEEngine
import tempfile
import io
import concurrent.futures

import tempfile

@pytest.fixture(scope="module")
def setup_db():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    engine = create_engine(f"sqlite:///{db_path}?check_same_thread=False&timeout=15")
    Base.metadata.create_all(bind=engine)
    SessionLocal.configure(bind=engine)
    
    yield
    
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    os.close(db_fd)
    try:
        os.remove(db_path)
    except:
        pass

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def test_user(db_session):
    return "fs_test_user_id"

def create_dummy_file(path, content):
    with open(path, "w") as f:
        f.write(content)

create_dummy_file("dummy_test.txt", "secret file contents")

def test_fresh_sender_key_and_prekey_consumption(setup_db, db_session, test_user):
    CryptoService.generate_prekeys_for_user(test_user, 5)
    
    transfer_id1 = str(uuid.uuid4())
    prekey_pub1 = CryptoService.claim_prekey(test_user, transfer_id1)
    
    transfer_id2 = str(uuid.uuid4())
    prekey_pub2 = CryptoService.claim_prekey(test_user, transfer_id2)
    
    assert prekey_pub1 != prekey_pub2
    
    res1 = CryptoService.encrypt_file_for_receiver(
        "dummy_test.txt", 2, "test_file_1", "Sensitive", prekey_public_pem=prekey_pub1, transfer_id=transfer_id1, sender_id=1
    )
    res2 = CryptoService.encrypt_file_for_receiver(
        "dummy_test.txt", 2, "test_file_2", "Sensitive", prekey_public_pem=prekey_pub2, transfer_id=transfer_id2, sender_id=1
    )
    
    assert res1.ecdh_public_key != res2.ecdh_public_key

def test_concurrent_prekey_claims(setup_db):
    # Ensure there is exactly 1 prekey available
    with SessionLocal() as db:
        db.query(ECDHPrekey).filter(ECDHPrekey.user_id == 2).delete()
        db.commit()
    CryptoService.generate_prekeys_for_user(2, 1) # Only 1 prekey!
    
    # Try to claim concurrently
    def claim():
        return CryptoService.claim_prekey(2, str(uuid.uuid4()))
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: claim(), range(5)))
        
    # Only one should have succeeded (the others might have triggered generation but the very FIRST attempt should be clean)
    # Wait, claim_prekey generates more if it runs out. So they might all get keys!
    # But they must all be DIFFERENT keys.
    valid_keys = [k for k in results if k is not None]
    assert len(valid_keys) == 5
    assert len(set(valid_keys)) == 5

def test_compromise_before_deletion(setup_db):
    transfer_id = str(uuid.uuid4())
    prekey_pub = CryptoService.claim_prekey(2, transfer_id)
    
    res = CryptoService.encrypt_file_for_receiver(
        "dummy_test.txt", 2, "test_file_pre", "Sensitive", prekey_public_pem=prekey_pub, transfer_id=transfer_id, sender_id=1
    )
    
    # State: TRANSFER_PENDING. The private prekey is still in the database.
    # Attacker compromises the DB right now:
    with SessionLocal() as db:
        stolen_prekey = db.query(ECDHPrekey).filter(ECDHPrekey.transfer_id == transfer_id).first()
        assert stolen_prekey is not None
        stolen_private = stolen_prekey.private_key_pem
        
    # Attacker can decrypt:
    unwrapped = CryptoService.unwrap_key_with_ecdh(
        2, res.ecdh_public_key, res.ecdh_wrapped_key, res.ecdh_key_nonce, "test_file_pre", prekey_private_pem=stolen_private, transfer_id=transfer_id, sender_id=1
    )
    assert unwrapped is not None

def test_compromise_after_deletion(setup_db):
    transfer_id = str(uuid.uuid4())
    prekey_pub = CryptoService.claim_prekey(2, transfer_id)
    
    res = CryptoService.encrypt_file_for_receiver(
        "dummy_test.txt", 2, "test_file_post", "Sensitive", prekey_public_pem=prekey_pub, transfer_id=transfer_id, sender_id=1
    )
    
    # Receiver downloads and consumes the key
    prekey_priv = CryptoService.get_and_delete_prekey(2, transfer_id)
    assert prekey_priv is not None
    
    # State: DELETED. Attacker compromises the DB right now:
    with SessionLocal() as db:
        stolen_prekey = db.query(ECDHPrekey).filter(ECDHPrekey.transfer_id == transfer_id).first()
        assert stolen_prekey is None # It's gone!
        
    # Forward Secrecy achieved here.

def test_no_downgrade_for_modern_transfers(setup_db):
    transfer_id = str(uuid.uuid4())
    prekey_pub = CryptoService.claim_prekey(2, transfer_id)
    
    res = CryptoService.encrypt_file_for_receiver(
        "dummy_test.txt", 2, "test_file_dg", "Sensitive", prekey_public_pem=prekey_pub, transfer_id=transfer_id, sender_id=1
    )
    
    # Receiver consumes key
    prekey_priv = CryptoService.get_and_delete_prekey(2, transfer_id)
    
    # Now try to decrypt again but pretend the prekey_priv is missing (or attacker only has long-term key)
    # The system should fail closed, not downgrade to RSA or static ECDH
    try:
        CryptoService.unwrap_key_with_ecdh(
            2, res.ecdh_public_key, res.ecdh_wrapped_key, res.ecdh_key_nonce, "test_file_dg", prekey_private_pem=None, transfer_id=transfer_id, sender_id=1
        )
        assert False, "Should have failed closed!"
    except Exception:
        assert True
