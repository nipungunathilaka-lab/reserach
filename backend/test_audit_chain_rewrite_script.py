import os
import json
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.database.models import AuditBlock, Base
from app.services.blockchain_service import BlockchainService

# Setup an isolated test database
os.environ["BLOCKCHAIN_ENABLED"] = "false"
TEST_DB_URL = "sqlite:///:memory:"

engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def run_tests():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    print("--- Running test_full_chain_rewrite ---")
    b1 = BlockchainService.append_block(db, event_type="LOGIN", details={"user": "admin"})
    b2 = BlockchainService.append_block(db, event_type="FILE_UPLOAD", details={"file": "secret.txt"})
    b3 = BlockchainService.append_block(db, event_type="LOGOUT", details={"user": "admin"})
    
    verification = BlockchainService.verify_chain(db)
    print(f"Initial chain valid: {verification['valid']}")
    
    fake_details = json.dumps({"user": "hacker"}, sort_keys=True)
    new_b1_hash = BlockchainService._calculate_hash(
        event_type="LOGIN",
        details_json=fake_details,
        previous_hash="0" * 64,
        timestamp=b1.created_at.isoformat()
    )
    
    db.execute(text("UPDATE audit_blocks SET details_json = :det, block_hash = :bhash WHERE id = :id"), {"det": fake_details, "bhash": new_b1_hash, "id": b1.id})
    
    new_b2_hash = BlockchainService._calculate_hash(
        event_type="FILE_UPLOAD",
        details_json=b2.details_json,
        previous_hash=new_b1_hash,
        timestamp=b2.created_at.isoformat()
    )
    db.execute(text("UPDATE audit_blocks SET previous_hash = :phash, block_hash = :bhash WHERE id = :id"), {"phash": new_b1_hash, "bhash": new_b2_hash, "id": b2.id})
    
    new_b3_hash = BlockchainService._calculate_hash(
        event_type="LOGOUT",
        details_json=b3.details_json,
        previous_hash=new_b2_hash,
        timestamp=b3.created_at.isoformat()
    )
    db.execute(text("UPDATE audit_blocks SET previous_hash = :phash, block_hash = :bhash WHERE id = :id"), {"phash": new_b2_hash, "bhash": new_b3_hash, "id": b3.id})
    
    db.commit()
    
    rewrite_verification = BlockchainService.verify_chain(db)
    print(f"Post-rewrite chain valid: {rewrite_verification['valid']}, status: {rewrite_verification['status']}")
    
    db.close()
    Base.metadata.drop_all(bind=engine)

if __name__ == "__main__":
    run_tests()
