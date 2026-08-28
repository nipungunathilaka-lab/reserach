from datetime import datetime
from pydantic import BaseModel
from app.schemas.auth_schema import UserPublic


class BlockchainLogItem(BaseModel):
    id: int
    block_index: int
    transfer_id: int
    data_hash: str
    previous_hash: str
    current_hash: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class ChainVerifyResponse(BaseModel):
    valid: bool
    checked_blocks: int
    message: str


class AIAlertItem(BaseModel):
    id: int
    transfer_id: int | None
    user_id: int | None = None
    level: str
    reason: str
    score: float
    file_name: str | None = None
    user: UserPublic | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
