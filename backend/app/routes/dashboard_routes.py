from fastapi import APIRouter, Depends
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload
from app.database.db import get_db
from app.database.models import AIAlert, Transfer, User
from app.routes.dependencies import get_current_user
from app.schemas.dashboard_schema import DashboardSummary
from app.services.blockchain_service import BlockchainService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    transfer_query = db.query(Transfer)
    alert_query = db.query(AIAlert).outerjoin(Transfer)
    if current_user.role != "admin":
        transfer_query = transfer_query.filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id))
        alert_query = alert_query.filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id, AIAlert.user_id == current_user.id))

    received_files = db.query(Transfer).filter(Transfer.receiver_id == current_user.id).count()
    total_transfers = transfer_query.count()
    ai_alerts = alert_query.count()
    valid, message = BlockchainService.verify_chain(db)
    recent_activity = (
        transfer_query.options(joinedload(Transfer.sender), joinedload(Transfer.receiver))
        .order_by(Transfer.created_at.desc())
        .limit(5)
        .all()
    )
    recent_alerts = alert_query.order_by(AIAlert.created_at.desc()).limit(5).all()
    return DashboardSummary(
        total_transfers=total_transfers,
        received_files=received_files,
        ai_alerts=ai_alerts,
        blockchain_status="Intact" if valid else "Compromised",
        blockchain_valid=valid,
        recent_activity=recent_activity,
        recent_alerts=recent_alerts,
    )
