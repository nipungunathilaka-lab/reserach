import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Tuple, List, Dict, Any, Optional

from sqlalchemy.orm import Session
from web3 import Web3
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
from eth_account import Account

from app.database.models import AuditBlock

logger = logging.getLogger(__name__)

BLOCKCHAIN_ENABLED = os.getenv("BLOCKCHAIN_ENABLED", "false").lower() == "true"
BLOCKCHAIN_REQUIRED = os.getenv("BLOCKCHAIN_REQUIRED", "false").lower() == "true"
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://localhost:8545")
BLOCKCHAIN_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "1337"))
BLOCKCHAIN_SIGNER_ADDRESS = os.getenv("BLOCKCHAIN_SIGNER_ADDRESS")
BLOCKCHAIN_SIGNER_PRIVATE_KEY = os.getenv("BLOCKCHAIN_SIGNER_PRIVATE_KEY")

class BlockchainService:
    """
    Permissioned decentralized blockchain-backed audit ledger.
    Integrates a Layer 1 off-chain database hash chain with a Layer 2 on-chain QBFT blockchain anchor.
    """
    _web3: Optional[Web3] = None
    _contract_abi: Optional[List[Dict[str, Any]]] = None
    _contract_bytecode: Optional[str] = None
    _contract_address: Optional[str] = None
    _contract_instance = None

    @classmethod
    def _get_web3(cls) -> Optional[Web3]:
        if not BLOCKCHAIN_ENABLED:
            return None
        if cls._web3 is None:
            cls._web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_RPC_URL))
            cls._web3.middleware_onion.inject(geth_poa_middleware, layer=0)
            if not cls._web3.is_connected():
                logger.error("Failed to connect to blockchain node at %s", BLOCKCHAIN_RPC_URL)
                return None
        return cls._web3

    @classmethod
    def _load_contract_data(cls):
        if cls._contract_abi is not None and cls._contract_bytecode is not None:
            return
        
        contract_path = os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "AuditLedger.json")
        if not os.path.exists(contract_path):
            logger.error("Contract JSON not found at %s", contract_path)
            return

        with open(contract_path, "r") as f:
            compiled = json.load(f)
        
        # Structure is usually compiled["contracts"]["/contracts/AuditLedger.sol:AuditLedger"] or similar
        # Depending on solc output format
        keys = list(compiled.get("contracts", {}).keys())
        if not keys:
            logger.error("No contracts found in compilation output.")
            return

        # Handle solc --combined-json abi,bin output
        contract_key = None
        for k in keys:
            if "AuditLedger" in k:
                contract_key = k
                break
                
        if not contract_key:
            logger.error("AuditLedger contract not found in compilation output.")
            return

        contract_data = compiled["contracts"][contract_key]
        if isinstance(contract_data.get("abi"), str):
            cls._contract_abi = json.loads(contract_data["abi"])
        else:
            cls._contract_abi = contract_data["abi"]
            
        cls._contract_bytecode = contract_data["bin"]

    @classmethod
    def _deploy_contract(cls) -> Optional[str]:
        w3 = cls._get_web3()
        if not w3 or not BLOCKCHAIN_SIGNER_PRIVATE_KEY:
            return None

        cls._load_contract_data()
        if not cls._contract_abi or not cls._contract_bytecode:
            return None

        AuditLedger = w3.eth.contract(abi=cls._contract_abi, bytecode=cls._contract_bytecode)
        
        account = Account.from_key(BLOCKCHAIN_SIGNER_PRIVATE_KEY)
        nonce = w3.eth.get_transaction_count(account.address)
        
        tx = AuditLedger.constructor().build_transaction({
            "chainId": BLOCKCHAIN_CHAIN_ID,
            "gas": 3000000,
            "gasPrice": w3.eth.gas_price,
            "nonce": nonce,
        })
        
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=BLOCKCHAIN_SIGNER_PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.info("Deploying contract, tx_hash: %s", tx_hash.hex())
        
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        cls._contract_address = receipt.contractAddress
        logger.info("Contract deployed at: %s", cls._contract_address)
        return cls._contract_address

    @classmethod
    def get_contract(cls):
        if not BLOCKCHAIN_ENABLED:
            return None
            
        if cls._contract_instance is not None:
            return cls._contract_instance
            
        w3 = cls._get_web3()
        if not w3:
            return None

        # Check if we already deployed in this run
        if not cls._contract_address:
            # We would usually read this from a config or env var, but for testing
            # we deploy if it doesn't exist
            try:
                addr = cls._deploy_contract()
                if not addr:
                    return None
            except Exception as e:
                logger.error("Contract deployment failed: %s", e)
                return None
                
        cls._contract_instance = w3.eth.contract(address=cls._contract_address, abi=cls._contract_abi)
        return cls._contract_instance

    @staticmethod
    def _calculate_hash(
        *,
        event_type: str,
        details_json: str,
        previous_hash: str,
        timestamp: str,
    ) -> str:
        canonical = json.dumps(
            {
                "event_type": event_type,
                "details_json": details_json,
                "previous_hash": previous_hash,
                "timestamp": timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()
        
    @staticmethod
    def _hash_string(val: str) -> str:
        return hashlib.sha256(val.encode('utf-8')).hexdigest()

    @classmethod
    def append_block(
        cls,
        db: Session,
        *,
        event_type: str,
        details: dict,
    ) -> AuditBlock:
        previous = db.query(AuditBlock).order_by(AuditBlock.id.desc()).first()
        previous_hash = previous.block_hash if previous else "0" * 64
        timestamp = datetime.utcnow().isoformat()
        details_json = json.dumps(details, sort_keys=True)

        block_hash = cls._calculate_hash(
            event_type=event_type,
            details_json=details_json,
            previous_hash=previous_hash,
            timestamp=timestamp,
        )

        block = AuditBlock(
            event_type=event_type,
            details_json=details_json,
            previous_hash=previous_hash,
            block_hash=block_hash,
            created_at=datetime.fromisoformat(timestamp),
            blockchain_status="LOCAL_ONLY"
        )
        db.add(block)
        db.commit()
        db.refresh(block)

        # Attempt Blockchain Anchoring
        if BLOCKCHAIN_ENABLED:
            w3 = cls._get_web3()
            if not w3 or not BLOCKCHAIN_SIGNER_PRIVATE_KEY:
                if BLOCKCHAIN_REQUIRED:
                    raise RuntimeError("Blockchain anchoring required but node/keys not available")
                else:
                    return block
                    
            contract = cls.get_contract()
            if not contract:
                if BLOCKCHAIN_REQUIRED:
                    raise RuntimeError("Blockchain anchoring required but contract unavailable")
                else:
                    return block

            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Idempotency check: verify if already anchored
                    try:
                        existing = contract.functions.anchors(block.id).call()
                        if existing[2] != "":
                            # Already anchored, break retry loop
                            break
                    except Exception:
                        pass # Ignore check failures, proceed to anchor
                        
                    account = Account.from_key(BLOCKCHAIN_SIGNER_PRIVATE_KEY)
                    nonce = w3.eth.get_transaction_count(account.address)
                    
                    auditIdHash = cls._hash_string(str(block.id))
                    eventTypeHash = cls._hash_string(event_type)
                    ts_int = int(block.created_at.timestamp())
                    
                    tx = contract.functions.appendAuditAnchor(
                        block.id,
                        auditIdHash,
                        block_hash,
                        previous_hash,
                        eventTypeHash,
                        ts_int
                    ).build_transaction({
                        "chainId": BLOCKCHAIN_CHAIN_ID,
                        "gas": 500000,
                        "gasPrice": w3.eth.gas_price,
                        "nonce": nonce,
                    })
                    
                    signed_tx = w3.eth.account.sign_transaction(tx, private_key=BLOCKCHAIN_SIGNER_PRIVATE_KEY)
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
                    
                    if receipt.status == 1:
                        block.blockchain_network_id = str(BLOCKCHAIN_CHAIN_ID)
                        block.blockchain_contract_address = cls._contract_address
                        block.blockchain_transaction_hash = tx_hash.hex()
                        block.blockchain_block_number = receipt.blockNumber
                        block.blockchain_block_hash = receipt.blockHash.hex()
                        block.blockchain_status = "CONFIRMED"
                        block.anchor_timestamp = datetime.utcnow()
                    else:
                        block.blockchain_status = "FAILED"
                        
                    db.commit()
                    db.refresh(block)
                    
                    if block.blockchain_status == "CONFIRMED":
                        break
                    elif attempt == max_retries - 1 and BLOCKCHAIN_REQUIRED:
                        raise RuntimeError("Blockchain transaction reverted")
                        
                except Exception as e:
                    logger.error("Blockchain anchoring attempt %d failed: %s", attempt + 1, e)
                    if attempt == max_retries - 1:
                        block.blockchain_status = "FAILED"
                        db.commit()
                        if BLOCKCHAIN_REQUIRED:
                            raise RuntimeError(f"Blockchain anchoring required but failed: {e}")

        return block

    @classmethod
    def verify_chain(cls, db: Session) -> Dict[str, Any]:
        try:
            blocks = db.query(AuditBlock).order_by(AuditBlock.id.asc()).all()
            
            if not blocks:
                return {
                    "valid": True,
                    "status": "EMPTY",
                    "message": "No audit records currently exist",
                    "checked_records": 0,
                    "verified_at": datetime.utcnow().isoformat() + "Z",
                    "invalid_record_id": None,
                    "invalid_sequence": None,
                    "reason": None
                }

            expected_previous = "0" * 64
            
            w3 = cls._get_web3() if BLOCKCHAIN_ENABLED else None
            contract = cls.get_contract()

            for sequence, block in enumerate(blocks, start=1):
                # 1. Off-chain Database Verification
                if block.previous_hash != expected_previous:
                    return {
                        "valid": False,
                        "status": "INVALID",
                        "message": "Audit ledger verification failed",
                        "checked_records": sequence - 1,
                        "verified_at": datetime.utcnow().isoformat() + "Z",
                        "invalid_record_id": str(block.id),
                        "invalid_sequence": sequence,
                        "reason": "PREVIOUS_HASH_MISMATCH"
                    }

                expected_hash = cls._calculate_hash(
                    event_type=block.event_type,
                    details_json=block.details_json,
                    previous_hash=block.previous_hash,
                    timestamp=block.created_at.isoformat(),
                )
                if expected_hash != block.block_hash:
                    return {
                        "valid": False,
                        "status": "INVALID",
                        "message": "Audit ledger verification failed",
                        "checked_records": sequence - 1,
                        "verified_at": datetime.utcnow().isoformat() + "Z",
                        "invalid_record_id": str(block.id),
                        "invalid_sequence": sequence,
                        "reason": "BLOCK_HASH_MISMATCH"
                    }

                expected_previous = block.block_hash
                
                # 2. On-chain Verification
                if BLOCKCHAIN_ENABLED and w3 and contract and block.blockchain_status == "CONFIRMED":
                    try:
                        anchor = contract.functions.anchors(block.id).call()
                        # Anchor tuple: sequenceNumber, auditIdHash, eventHash, previousAuditHash, eventTypeHash, timestamp
                        chain_event_hash = anchor[2]
                        
                        if chain_event_hash == "":
                            return {
                                "valid": False,
                                "status": "INVALID",
                                "message": "Audit ledger verification failed",
                                "checked_records": sequence - 1,
                                "verified_at": datetime.utcnow().isoformat() + "Z",
                                "invalid_record_id": str(block.id),
                                "invalid_sequence": sequence,
                                "reason": "ONCHAIN_ANCHOR_MISSING"
                            }
                        elif chain_event_hash != expected_hash:
                            return {
                                "valid": False,
                                "status": "INVALID",
                                "message": "Audit ledger verification failed",
                                "checked_records": sequence - 1,
                                "verified_at": datetime.utcnow().isoformat() + "Z",
                                "invalid_record_id": str(block.id),
                                "invalid_sequence": sequence,
                                "reason": "ONCHAIN_HASH_MISMATCH"
                            }
                        
                        # Verify transaction receipt exists and was successful
                        if block.blockchain_transaction_hash:
                            try:
                                receipt = w3.eth.get_transaction_receipt(block.blockchain_transaction_hash)
                                if receipt.status != 1:
                                    return {
                                        "valid": False,
                                        "status": "INVALID",
                                        "message": "Audit ledger verification failed",
                                        "checked_records": sequence - 1,
                                        "verified_at": datetime.utcnow().isoformat() + "Z",
                                        "invalid_record_id": str(block.id),
                                        "invalid_sequence": sequence,
                                        "reason": "ONCHAIN_TX_FAILED"
                                    }
                            except Exception:
                                return {
                                    "valid": False,
                                    "status": "INVALID",
                                    "message": "Audit ledger verification failed",
                                    "checked_records": sequence - 1,
                                    "verified_at": datetime.utcnow().isoformat() + "Z",
                                    "invalid_record_id": str(block.id),
                                    "invalid_sequence": sequence,
                                    "reason": "ONCHAIN_RECEIPT_NOT_FOUND"
                                }
                                
                    except Exception as e:
                        return {
                            "valid": False,
                            "status": "VERIFICATION_ERROR",
                            "message": "Audit ledger verification could not be completed",
                            "checked_records": sequence - 1,
                            "verified_at": datetime.utcnow().isoformat() + "Z",
                            "invalid_record_id": str(block.id),
                            "invalid_sequence": sequence,
                            "reason": f"ONCHAIN_VERIFICATION_EXCEPTION"
                        }

            return {
                "valid": True,
                "status": "VALID",
                "message": "Audit ledger hash chain verified successfully",
                "checked_records": len(blocks),
                "verified_at": datetime.utcnow().isoformat() + "Z",
                "invalid_record_id": None,
                "invalid_sequence": None,
                "reason": None
            }
        except Exception as e:
            return {
                "valid": False,
                "status": "VERIFICATION_ERROR",
                "message": "Audit ledger verification could not be completed",
                "checked_records": 0,
                "verified_at": datetime.utcnow().isoformat() + "Z",
                "invalid_record_id": None,
                "invalid_sequence": None,
                "reason": "DATABASE_UNAVAILABLE_OR_EXCEPTION"
            }
