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
    valid, errors = BlockchainService.verify_chain(db)

    return {
        "valid": valid,
        "errors": errors,
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
        
    valid, errors = BlockchainService.verify_chain(db)
    
    # Filter errors relevant to this block
    block_errors = [e for e in errors if f"Block {audit_id}:" in e]
    
    return {
        "audit_id": audit_id,
        "blockchain_status": block.blockchain_status,
        "blockchain_network_id": block.blockchain_network_id,
        "blockchain_transaction_hash": block.blockchain_transaction_hash,
        "blockchain_block_number": block.blockchain_block_number,
        "verification_result": "VERIFIED" if not block_errors else "TAMPERING DETECTED",
        "errors": block_errors
    }
