import os
os.environ["BLOCKCHAIN_ENABLED"] = "true"
os.environ["BLOCKCHAIN_REQUIRED"] = "true"
os.environ["BLOCKCHAIN_RPC_URL"] = "http://127.0.0.1:8545"
os.environ["BLOCKCHAIN_SIGNER_ADDRESS"] = "0x906818496d579Ee37bb743e8f060aA16C2Cc943C"
os.environ["BLOCKCHAIN_SIGNER_PRIVATE_KEY"] = "0xdecfc029e90f96395a231e3d444bd070b7a858fcffe3db0fcbf5051fd556813d"

import json
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.database.db import Base
from app.database.models import AuditBlock
from app.services.blockchain_service import BlockchainService

print("Starting tests...")

engine = create_engine("sqlite:///./test_blockchain.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)
db = TestingSessionLocal()
db.query(AuditBlock).delete()
db.commit()

try:
    print("Test BC-01: Network Connectivity")
    w3 = BlockchainService._get_web3()
    assert w3 is not None, "Web3 is None"
    assert w3.is_connected(), "Web3 is not connected"
    assert w3.eth.block_number >= 0, "Block number invalid"
    print("BC-01 PASSED")

    print("Test BC-02: Smart Contract Deployment")
    contract = BlockchainService.get_contract()
    assert contract is not None, "Contract is None"
    assert BlockchainService._contract_address is not None, "Address is None"
    print("BC-02 PASSED")

    print("Test BC-03, 04, 05: Audit transaction submission and receipt")
    event_details = {"user_id": 1, "action": "FILE_UPLOAD"}
    block = BlockchainService.append_block(db, event_type="FILE_UPLOAD", details=event_details)
    assert block.blockchain_status == "CONFIRMED", f"Status is {block.blockchain_status}"
    anchor = contract.functions.anchors(block.id).call()
    assert anchor[2] == block.block_hash, "Hash mismatch"
    print("BC-03, 04, 05 PASSED")

    print("Test BC-06: Normal Verification")
    valid, errors = BlockchainService.verify_chain(db)
    assert valid is True, f"Errors: {errors}"
    print("BC-06 PASSED")

    print("Test BC-07: DB Tampering")
    block.event_type = "TAMPERED"
    db.commit()
    valid, errors = BlockchainService.verify_chain(db)
    assert valid is False
    assert any("Blockchain event_hash mismatch" in e for e in errors)
    print("BC-07 PASSED")
    
    print("Test BC-08: Recalculated Hash Chain")
    db.query(AuditBlock).delete()
    db.commit()
    b1 = BlockchainService.append_block(db, event_type="TEST", details={"action": "1"})
    b2 = BlockchainService.append_block(db, event_type="TEST", details={"action": "2"})
    
    b1.details_json = json.dumps({"action": "hacked"})
    h1 = BlockchainService._calculate_hash(event_type=b1.event_type, details_json=b1.details_json, previous_hash=b1.previous_hash, timestamp=b1.created_at.isoformat())
    b1.block_hash = h1
    b2.previous_hash = h1
    h2 = BlockchainService._calculate_hash(event_type=b2.event_type, details_json=b2.details_json, previous_hash=b2.previous_hash, timestamp=b2.created_at.isoformat())
    b2.block_hash = h2
    db.commit()
    
    valid, errors = BlockchainService.verify_chain(db)
    assert valid is False
    assert not any("mismatch in local DB" in e for e in errors)
    assert any("Blockchain event_hash mismatch" in e for e in errors)
    print("BC-08 PASSED")
    
    print("Test BC-09: Multi node consensus")
    bn1 = w3.eth.block_number
    time.sleep(3)
    bn2 = w3.eth.block_number
    assert bn2 > bn1, f"{bn2} not greater than {bn1}"
    print("BC-09 PASSED")

    print("ALL TESTS PASSED SUCCESSFULLY")
    
finally:
    db.close()
