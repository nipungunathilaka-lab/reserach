from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.database.models import AuditBlock, User
from app.routes.dependencies import get_current_user
from app.services.blockchain_service import BlockchainService


router = APIRouter(prefix="/audit", tags=["Audit Chain"])


@router.get("/chain")
def read_chain(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    blocks = db.query(AuditBlock).order_by(AuditBlock.id.asc()).all()
    verification = BlockchainService.verify_chain(db)

    return {
        "valid": verification["valid"],
        "errors": [verification["reason"]] if verification["reason"] else [],
        "blocks": [
            {
                "id": block.id,
                "event_type": block.event_type,
                "details_json": block.details_json,
                "previous_hash": block.previous_hash,
                "block_hash": block.block_hash,
                "created_at": block.created_at,
                "blockchain_network_id": block.blockchain_network_id,
                "blockchain_contract_address": block.blockchain_contract_address,
                "blockchain_transaction_hash": block.blockchain_transaction_hash,
                "blockchain_block_number": block.blockchain_block_number,
                "blockchain_status": block.blockchain_status,
                "anchor_timestamp": block.anchor_timestamp
            }
            for block in blocks
        ],
    }

@router.get("/{audit_id}/verify")
def verify_single_audit(
    audit_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    block = db.query(AuditBlock).filter(AuditBlock.id == audit_id).first()
    if not block:
        return {"error": "Audit not found"}
        
    verification = BlockchainService.verify_chain(db)
    
    # Check if verification failed on this block specifically
    is_tampered = not verification["valid"] and verification.get("invalid_record_id") == str(audit_id)
    block_errors = [verification["reason"]] if is_tampered else []
    
    return {
        "audit_id": audit_id,
        "blockchain_status": block.blockchain_status,
        "blockchain_network_id": block.blockchain_network_id,
        "blockchain_transaction_hash": block.blockchain_transaction_hash,
        "blockchain_block_number": block.blockchain_block_number,
        "verification_result": "TAMPERING DETECTED" if is_tampered else "VERIFIED",
        "errors": block_errors
    }
