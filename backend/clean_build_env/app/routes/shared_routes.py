from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
import io
from urllib.parse import quote
from fastapi.responses import StreamingResponse

from app.database.db import get_db
from app.database.models import Transfer
from app.services.crypto_service import CryptoService
from app.services.pfce_engine import PFCEEngine

router = APIRouter(prefix="/shared", tags=["Public Shared Files"])

class DownloadPinRequest(BaseModel):
    pin: str

@router.get("/{share_token}")
def get_shared_file_info(share_token: str, db: Session = Depends(get_db)):
    transfer = db.query(Transfer).filter(Transfer.share_token == share_token).first()
    if not transfer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shared file not found")
    
    classification_type = "Normal"
    if transfer.is_anomaly or transfer.high_risk_file_type:
        classification_type = "High Risk"
    # Or maybe it's stored in a different way, but we can return basic info
    
    return {
        "filename": transfer.file_name,
        "file_size": transfer.file_size,
        "classification_type": classification_type
    }

@router.post("/{share_token}/download")
def download_shared_file(share_token: str, payload: DownloadPinRequest, db: Session = Depends(get_db)):
    transfer = db.query(Transfer).filter(Transfer.share_token == share_token).first()
    if not transfer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shared file not found")
    
    if transfer.share_pin != payload.pin:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid PIN")
    
    try:
        pfce_engine = PFCEEngine()
        stream_generator = pfce_engine.process_download_stream(
            pfce_package_path=transfer.encrypted_path, 
            receiver_id=transfer.receiver_id
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Decryption failed: {exc}")

    quoted_name = quote(transfer.file_name)
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quoted_name}"}
    return StreamingResponse(stream_generator, media_type="application/octet-stream", headers=headers)
