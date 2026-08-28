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
            }
            for block in blocks
        ],
    }
