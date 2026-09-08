from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.db import get_db
from app.database.models import AuditBlock
import json

#prefix change
router = APIRouter(prefix="/blockchain", tags=["Blockchain"])

@router.get("/logs")
def get_blockchain_logs(db: Session = Depends(get_db)):
    #new AuditBlock
    blocks = db.query(AuditBlock).order_by(AuditBlock.id.desc()).all()
    
    results = []
    for block in blocks:
        details = block.details_json
        try:
            # JSON Format corection   
            if isinstance(details, str):
                details = json.loads(details)
        except:
            pass
            
        results.append({
            "id": block.id,
            "timestamp": block.created_at,
            "event_type": block.event_type,
            "block_hash": block.block_hash,
            "previous_hash": block.previous_hash,
            "details": details
        })
        
    return results