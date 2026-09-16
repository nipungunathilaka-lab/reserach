from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, BigInteger, UniqueConstraint, event
from sqlalchemy.orm import Mapped, mapped_column
from app.database.db import Base

class AuditBlock(Base):
    __tablename__ = "audit_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[str] = mapped_column(Text)
    previous_hash: Mapped[str] = mapped_column(String(64))
    block_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )
    
    # Blockchain Audit Anchoring Layer
    blockchain_network_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blockchain_contract_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    blockchain_transaction_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    blockchain_block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    blockchain_block_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    blockchain_status: Mapped[str] = mapped_column(String(32), default="LOCAL_ONLY")
    anchor_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class PQCKey(Base):
    __tablename__ = "pqc_keys"
    __table_args__ = (UniqueConstraint('user_id', 'key_version', name='uq_pqc_user_version'),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(50), default="ML-KEM-768", nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False) # Storing base64 encoded bytes
    encrypted_private_key: Mapped[str] = mapped_column(Text, nullable=False) # Base64 encoded AES-GCM output
    private_key_nonce: Mapped[str] = mapped_column(String(64), nullable=False) # Base64 encoded nonce
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class ECDHPrekey(Base):
    __tablename__ = "ecdh_prekeys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    prekey_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    transfer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

class QuarantineItem(Base):
    __tablename__ = "quarantine_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    transfer_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    safe_identifier: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detection_engine: Mapped[str] = mapped_column(String(100), nullable=False)
    detection_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    malware_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    quarantine_reason: Mapped[str] = mapped_column(Text, nullable=False)
    quarantine_status: Mapped[str] = mapped_column(String(50), default="QUARANTINED", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    scan_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)

# ---------------------------------------------------------
# APPEND-ONLY PROTECTIONS FOR AUDIT LEDGER
# ---------------------------------------------------------
@event.listens_for(AuditBlock, 'before_update')
def receive_before_update(mapper, connection, target):
    raise Exception("SECURITY VIOLATION: AuditBlock records are append-only and cannot be updated.")

@event.listens_for(AuditBlock, 'before_delete')
def receive_before_delete(mapper, connection, target):
    raise Exception("SECURITY VIOLATION: AuditBlock records are append-only and cannot be deleted.")
