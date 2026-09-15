import os
import json
from sqlalchemy import create_engine
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
    
    print("--- Running test_audit_record_append_is_allowed ---")
    block = BlockchainService.append_block(
        db,
        event_type="TEST_EVENT",
        details={"info": "Append test"}
    )
    if block.id is not None:
        print("PASS: Append allowed")
    
    print("--- Running test_audit_record_update_is_blocked ---")
    try:
        block.details_json = json.dumps({"info": "Malicious update"})
        db.commit()
        print("FAIL: Update was allowed!")
    except Exception as e:
        print(f"PASS: Update rejected with: {e}")
        db.rollback()
    
    print("--- Running test_audit_record_delete_is_blocked ---")
    try:
        db.delete(block)
        db.commit()
        print("FAIL: Delete was allowed!")
    except Exception as e:
        print(f"PASS: Delete rejected with: {e}")
        db.rollback()
        
    db.close()
    Base.metadata.drop_all(bind=engine)

if __name__ == "__main__":
    run_tests()
