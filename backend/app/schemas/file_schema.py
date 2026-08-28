from datetime import datetime
from pydantic import BaseModel
from app.schemas.auth_schema import UserPublic


class TransferItem(BaseModel):
    id: int
    file_name: str
    stored_name: str
    original_hash: str
    decrypted_hash: str | None
    file_size: int
    status: str
    integrity_status: str
    anomaly_score: float | None
    is_anomaly: bool
    anomaly_reason: str | None
    anomaly_level: str | None
    sender: UserPublic
    receiver: UserPublic
    created_at: datetime

    model_config = {"from_attributes": True}


class SendFileResponse(BaseModel):
    message: str = "File uploaded successfully"
    classification_type: str
    encryption_mechanism_used: str
    execution_time_ms: float
    cpu_usage_percent: float
    processing_bandwidth_mbps: float
    transfer: TransferItem
    encryption: dict
    integrity: dict
    ai: dict
    blockchain: dict
