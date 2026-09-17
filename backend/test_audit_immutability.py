import pytest
pytestmark = [pytest.mark.integration, pytest.mark.besu]
import pytest
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

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(bind=engine)

def test_audit_record_append_is_allowed(db):
    """Phase 7: Attempt to append a new block. Expected: SUCCESS"""
    block = BlockchainService.append_block(
        db,
        event_type="TEST_EVENT",
        details={"info": "Append test"}
    )
    assert block.id is not None
    assert block.event_type == "TEST_EVENT"

def test_audit_record_update_is_blocked(db):
    """Phase 7: Attempt to modify an existing audit block. Expected: REJECTED"""
    block = BlockchainService.append_block(
        db,
        event_type="TEST_EVENT",
        details={"info": "Update test"}
    )
    
    with pytest.raises(Exception) as excinfo:
        block.details_json = json.dumps({"info": "Malicious update"})
        db.commit()
    
    assert "SECURITY VIOLATION: AuditBlock records are append-only and cannot be updated" in str(excinfo.value)

def test_audit_record_delete_is_blocked(db):
    """Phase 7: Attempt to delete an existing audit block. Expected: REJECTED"""
    block = BlockchainService.append_block(
        db,
        event_type="TEST_EVENT",
        details={"info": "Delete test"}
    )
    
    with pytest.raises(Exception) as excinfo:
        db.delete(block)
        db.commit()
    
    assert "SECURITY VIOLATION: AuditBlock records are append-only and cannot be deleted" in str(excinfo.value)
