from datetime import datetime
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, BigInteger
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    company_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    job_role: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    sent_transfers = relationship("Transfer", back_populates="sender", foreign_keys="Transfer.sender_id")
    received_transfers = relationship("Transfer", back_populates="receiver", foreign_keys="Transfer.receiver_id")


class MfaChallenge(Base):
    __tablename__ = "mfa_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    otp_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    resend_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User")


class Transfer(Base):
    __tablename__ = "transfers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    file_group_id: Mapped[str] = mapped_column(String(64), nullable=False)
    original_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decrypted_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encrypted_path: Mapped[str] = mapped_column(String(500), nullable=False)
    decrypted_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    encrypted_key: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    ecdh_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecdh_wrapped_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    ecdh_key_nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="encrypted", nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(50), default="pending_download", nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    anomaly_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    anomaly_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    transfers_last_hour: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    mfa_failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_risk_file_type: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sender_failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sender_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    receiver_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    share_token: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    share_pin: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    sender = relationship("User", back_populates="sent_transfers", foreign_keys=[sender_id])
    receiver = relationship("User", back_populates="received_transfers", foreign_keys=[receiver_id])
    ai_alert = relationship("AIAlert", back_populates="transfer", uselist=False)


class BlockchainLog(Base):
    __tablename__ = "blockchain_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    block_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AIAlert(Base):
    __tablename__ = "ai_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    transfer_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("transfers.id"), nullable=True, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    transfer = relationship("Transfer", back_populates="ai_alert")
    user = relationship("User")


class ShareLink(Base):
    __tablename__ = "share_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    transfer_id: Mapped[int] = mapped_column(Integer, ForeignKey("transfers.id"), nullable=False, index=True)
    link_token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    allowed_roles: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    transfer = relationship("Transfer")


class PFCEMetadata(Base):
    __tablename__ = "pfce_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    transfer_id: Mapped[int] = mapped_column(Integer, ForeignKey("transfers.id"), nullable=False, index=True)
    encrypted_metadata: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

    transfer = relationship("Transfer")

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

