from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload
from app.database.db import get_db
from app.database.models import AIAlert, BlockchainLog, Transfer, User
from app.routes.dependencies import get_current_user
from app.schemas.file_schema import TransferItem
from app.schemas.log_schema import AIAlertItem, BlockchainLogItem, ChainVerifyResponse
from app.services.blockchain_service import BlockchainService

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("/transfers", response_model=list[TransferItem])
def transfer_logs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Transfer).options(joinedload(Transfer.sender), joinedload(Transfer.receiver))
    if current_user.role != "admin":
        query = query.filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id))
    return query.order_by(Transfer.created_at.desc()).all()


@router.get("/blockchain", response_model=list[BlockchainLogItem])
def blockchain_logs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(BlockchainLog)
    if current_user.role != "admin":
        query = query.join(Transfer).filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id))
    return query.order_by(BlockchainLog.block_index.asc()).all()


@router.get("/blockchain/verify", response_model=ChainVerifyResponse)
def verify_blockchain(_: User = Depends(get_current_user), db: Session = Depends(get_db)):
    valid, checked_blocks, message = BlockchainService.verify_chain(db)
    return ChainVerifyResponse(valid=valid, checked_blocks=checked_blocks, message=message)


@router.get("/ai-alerts", response_model=list[AIAlertItem])
def ai_alerts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(AIAlert).outerjoin(Transfer)
    if current_user.role != "admin":
        query = query.filter(
            or_(
                Transfer.sender_id == current_user.id,
                Transfer.receiver_id == current_user.id,
                AIAlert.user_id == current_user.id,
            )
        )
    return query.order_by(AIAlert.created_at.desc()).all()
