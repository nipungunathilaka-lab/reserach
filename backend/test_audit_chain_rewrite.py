import pytest
pytestmark = [pytest.mark.integration, pytest.mark.besu]
import pytest
import os
import json
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.database.models import AuditBlock, Base
from app.services.blockchain_service import BlockchainService
from datetime import datetime

os.environ["BLOCKCHAIN_ENABLED"] = "false"
TEST_DB_URL = "sqlite:///:memory:"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_full_chain_rewrite(db):
    """
    Phase 9: TEST FULL CHAIN REWRITE LIMITATION
    Demonstrates that if an attacker controls the database, they can rewrite 
    history and recompute the chain, making it appear VALID to local verification.
    """
    # 1. Create a chain of 3 blocks
    b1 = BlockchainService.append_block(db, event_type="LOGIN", details={"user": "admin"})
    b2 = BlockchainService.append_block(db, event_type="FILE_UPLOAD", details={"file": "secret.txt"})
    b3 = BlockchainService.append_block(db, event_type="LOGOUT", details={"user": "admin"})
    
    # Verify it is initially valid
    verification = BlockchainService.verify_chain(db)
    assert verification["valid"] is True
    
    # 2. Attacker modifies block 1 bypassing ORM protections (using raw SQL)
    fake_details = json.dumps({"user": "hacker"}, sort_keys=True)
    new_b1_hash = BlockchainService._calculate_hash(
        event_type="LOGIN",
        details_json=fake_details,
        previous_hash="0" * 64,
        timestamp=b1.created_at.isoformat()
    )
    
    db.execute(text(
        "UPDATE audit_blocks SET details_json = :det, block_hash = :bhash WHERE id = :id"
    ), {"det": fake_details, "bhash": new_b1_hash, "id": b1.id})
    
    # 3. Attacker recalculates Block 2
    new_b2_hash = BlockchainService._calculate_hash(
        event_type="FILE_UPLOAD",
        details_json=b2.details_json,
        previous_hash=new_b1_hash,
        timestamp=b2.created_at.isoformat()
    )
    db.execute(text(
        "UPDATE audit_blocks SET previous_hash = :phash, block_hash = :bhash WHERE id = :id"
    ), {"phash": new_b1_hash, "bhash": new_b2_hash, "id": b2.id})
    
    # 4. Attacker recalculates Block 3
    new_b3_hash = BlockchainService._calculate_hash(
        event_type="LOGOUT",
        details_json=b3.details_json,
        previous_hash=new_b2_hash,
        timestamp=b3.created_at.isoformat()
    )
    db.execute(text(
        "UPDATE audit_blocks SET previous_hash = :phash, block_hash = :bhash WHERE id = :id"
    ), {"phash": new_b2_hash, "bhash": new_b3_hash, "id": b3.id})
    
    db.commit()
    
    # 5. Run the verifier again
    # Due to the nature of a database-only hash chain, if all subsequent hashes are 
    # perfectly recalculated, the verifier will see it as a VALID chain.
    # Note: If BLOCKCHAIN_ENABLED=true, the ONCHAIN_HASH_MISMATCH would catch this!
    rewrite_verification = BlockchainService.verify_chain(db)
    assert rewrite_verification["valid"] is True
    assert rewrite_verification["status"] == "VALID"
