import pytest
import os
import json
import time
import subprocess
from unittest.mock import patch, MagicMock
from app.services.blockchain_service import BlockchainService
from app.database.models import AuditBlock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.database.db import Base

# Setup temporary test database
engine = create_engine("sqlite:///./test_blockchain.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def check_docker_available():
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

DOCKER_AVAILABLE = check_docker_available()

def require_docker():
    if not DOCKER_AVAILABLE:
        pytest.fail("Docker is not available. Cannot connect to Besu network. Failing honestly as per Phase 12 requirements.", pytrace=False)

@pytest.fixture(scope="module")
def db_session():
    db = TestingSessionLocal()
    yield db
    db.close()
    
@pytest.fixture(autouse=True)
def clear_db(db_session: Session):
    db_session.query(AuditBlock).delete()
    db_session.commit()

# Ensure blockchain is enabled for tests
os.environ["BLOCKCHAIN_ENABLED"] = "true"
os.environ["BLOCKCHAIN_REQUIRED"] = "true"

def test_bc01_network_connectivity():
    require_docker()
    w3 = BlockchainService._get_web3()
    assert w3 is not None
    assert w3.is_connected()
    assert w3.eth.block_number >= 0

def test_bc02_smart_contract_deployment():
    require_docker()
    contract = BlockchainService.get_contract()
    assert contract is not None
    assert BlockchainService._contract_address is not None
    assert len(BlockchainService._contract_address) == 42 # 0x + 40 hex chars

def test_bc03_04_05_audit_transaction_submission_and_receipt(db_session: Session):
    require_docker()
    event_details = {"user_id": 1, "action": "FILE_UPLOAD", "filename": "test.txt"}
    
    # 1. Append a block (this should trigger blockchain anchoring)
    block = BlockchainService.append_block(
        db_session,
        event_type="FILE_UPLOAD",
        details=event_details
    )
    
    assert block.id is not None
    assert block.blockchain_status == "CONFIRMED"
    assert block.blockchain_transaction_hash is not None
    assert block.blockchain_block_number is not None
    assert block.blockchain_network_id == "1337"
    
    # Verify BC-05 Correct event hash stored on-chain
    contract = BlockchainService.get_contract()
    anchor = contract.functions.anchors(block.id).call()
    assert anchor[2] == block.block_hash # eventHash match
    
def test_bc06_normal_verification_passes(db_session: Session):
    require_docker()
    event_details = {"user_id": 1, "action": "TEST", "filename": "test.txt"}
    BlockchainService.append_block(
        db_session,
        event_type="TEST",
        details=event_details
    )
    
    valid, errors = BlockchainService.verify_chain(db_session)
    assert valid is True
    assert len(errors) == 0

def test_bc07_database_tampering_detected(db_session: Session):
    require_docker()
    event_details = {"user_id": 1, "action": "TAMPER_ME"}
    block = BlockchainService.append_block(db_session, event_type="TEST", details=event_details)
    
    # Directly tamper with DB
    block.event_type = "TAMPERED_EVENT"
    db_session.commit()
    
    valid, errors = BlockchainService.verify_chain(db_session)
    assert valid is False
    assert any("block hash mismatch in local DB" in e for e in errors)
    assert any("Blockchain event_hash mismatch (Tampering detected!)" in e for e in errors)

def test_bc08_recalculated_local_hash_chain_attack(db_session: Session):
    require_docker()
    # Wipe chain for this specific test
    db_session.query(AuditBlock).delete()
    db_session.commit()
    
    block1 = BlockchainService.append_block(db_session, event_type="TEST", details={"action": "1"})
    block2 = BlockchainService.append_block(db_session, event_type="TEST", details={"action": "2"})
    
    # Tamper block 1 and recalculate hashes to make local DB perfectly consistent
    block1.details_json = json.dumps({"action": "hacked"})
    new_hash_1 = BlockchainService._calculate_hash(
        event_type=block1.event_type,
        details_json=block1.details_json,
        previous_hash=block1.previous_hash,
        timestamp=block1.created_at.isoformat()
    )
    block1.block_hash = new_hash_1
    
    # Fix block 2 to match
    block2.previous_hash = new_hash_1
    new_hash_2 = BlockchainService._calculate_hash(
        event_type=block2.event_type,
        details_json=block2.details_json,
        previous_hash=block2.previous_hash,
        timestamp=block2.created_at.isoformat()
    )
    block2.block_hash = new_hash_2
    
    db_session.commit()
    
    valid, errors = BlockchainService.verify_chain(db_session)
    # The local DB hash mismatch error should NOT appear for block 1 because we forged it perfectly
    assert not any("mismatch in local DB" in e for e in errors)
    # BUT the blockchain verification MUST fail and detect tampering
    assert valid is False
    assert any("Blockchain event_hash mismatch (Tampering detected!)" in e for e in errors)

def test_bc09_multi_node_consensus_check():
    require_docker()
    w3 = BlockchainService._get_web3()
    block_num_1 = w3.eth.block_number
    time.sleep(3) # Wait for 2 blocks (block period is 2s)
    block_num_2 = w3.eth.block_number
    assert block_num_2 > block_num_1

def test_bc10_validator_restart_sync():
    """Test validator fault/recovery behaviour."""
    require_docker()
    # Stop one validator
    subprocess.run(["docker", "compose", "stop", "besu-validator-4"], check=True)
    
    # Ensure consensus continues
    w3 = BlockchainService._get_web3()
    block_num_1 = w3.eth.block_number
    time.sleep(3)
    block_num_2 = w3.eth.block_number
    assert block_num_2 > block_num_1
    
    # Restart the validator
    subprocess.run(["docker", "compose", "start", "besu-validator-4"], check=True)
    time.sleep(5)
    
    # Consensus should still be advancing
    block_num_3 = w3.eth.block_number
    assert block_num_3 > block_num_2

def test_bc11_persistence_after_docker_restart(db_session: Session):
    require_docker()
    block = BlockchainService.append_block(db_session, event_type="PERSIST_TEST", details={"action": "test"})
    tx_hash = block.blockchain_transaction_hash
    assert tx_hash is not None
    
    subprocess.run(["docker", "compose", "restart"], check=True)
    time.sleep(15) # Wait for network to come back up
    
    w3 = BlockchainService._get_web3()
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    assert receipt is not None
    assert receipt.status == 1

def test_bc12_invalid_missing_transaction_cannot_be_confirmed(db_session: Session):
    # If BLOCKCHAIN_REQUIRED=true and we can't connect, it MUST raise an exception.
    os.environ["BLOCKCHAIN_RPC_URL"] = "http://localhost:9999" # Fake port
    BlockchainService._web3 = None # Force reconnect
    
    with pytest.raises(RuntimeError, match="Blockchain anchoring required but node/keys not available"):
        BlockchainService.append_block(db_session, event_type="TEST", details={"action": "test"})
        
    # Restore correct URL for other tests
    os.environ["BLOCKCHAIN_RPC_URL"] = "http://localhost:8545"
    BlockchainService._web3 = None

def test_bc13_duplicate_audit_anchoring_protection(db_session: Session):
    require_docker()
    block = BlockchainService.append_block(db_session, event_type="IDEMPOTENCY_TEST", details={"action": "test"})
    assert block.blockchain_status == "CONFIRMED"
    
    # Force retry by directly calling contract with same block ID
    w3 = BlockchainService._get_web3()
    contract = BlockchainService.get_contract()
    
    # Attempting to re-anchor the same block.id should fail at contract level because of require()
    account = w3.eth.account.from_key(os.environ["BLOCKCHAIN_SIGNER_PRIVATE_KEY"])
    nonce = w3.eth.get_transaction_count(account.address)
    
    tx = contract.functions.appendAuditAnchor(
        block.id,
        "dummy", "dummy", "dummy", "dummy",
        int(block.created_at.timestamp())
    ).build_transaction({
        "chainId": 1337,
        "gas": 500000,
        "gasPrice": w3.eth.gas_price,
        "nonce": nonce,
    })
    
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=os.environ["BLOCKCHAIN_SIGNER_PRIVATE_KEY"])
    with pytest.raises(Exception):
        # This will fail either at estimate gas or receipt status 0 due to revert
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise Exception("Reverted")

def test_bc14_blockchain_disabled_dev_mode(db_session: Session):
    # Set REQUIRED=false and ENABLED=false
    os.environ["BLOCKCHAIN_ENABLED"] = "false"
    os.environ["BLOCKCHAIN_REQUIRED"] = "false"
    
    block = BlockchainService.append_block(db_session, event_type="LOCAL_TEST", details={"action": "test"})
    
    assert block.blockchain_status == "LOCAL_ONLY"
    assert block.blockchain_transaction_hash is None
    
    # Restore
    os.environ["BLOCKCHAIN_ENABLED"] = "true"
    os.environ["BLOCKCHAIN_REQUIRED"] = "true"

def test_bc15_no_sensitive_plaintext(db_session: Session):
    require_docker()
    sensitive_details = {"password": "SuperSecretPassword123", "action": "LOGIN"}
    block = BlockchainService.append_block(db_session, event_type="SENSITIVE_TEST", details=sensitive_details)
    
    contract = BlockchainService.get_contract()
    anchor = contract.functions.anchors(block.id).call()
    
    # anchor[2] is eventHash, anchor[1] is auditIdHash, anchor[4] is eventTypeHash
    # The actual password is NOT on chain. Only hashes.
    assert "SuperSecretPassword123" not in str(anchor)
