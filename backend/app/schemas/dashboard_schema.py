from pydantic import BaseModel
from app.schemas.file_schema import TransferItem
from app.schemas.log_schema import AIAlertItem


class DashboardSummary(BaseModel):
    total_transfers: int
    received_files: int
    ai_alerts: int
    blockchain_status: str
    blockchain_valid: bool
    recent_activity: list[TransferItem]
    recent_alerts: list[AIAlertItem]
