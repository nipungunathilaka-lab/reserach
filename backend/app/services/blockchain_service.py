import hashlib
import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import AuditBlock


class BlockchainService:
    """Database-backed tamper-evident audit chain.

    This is blockchain-inspired logging, not a distributed blockchain network.
    """

    @staticmethod
    def _calculate_hash(
        *,
        event_type: str,
        details_json: str,
        previous_hash: str,
        timestamp: str,
    ) -> str:
        canonical = json.dumps(
            {
                "event_type": event_type,
                "details_json": details_json,
                "previous_hash": previous_hash,
                "timestamp": timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def append_block(
        cls,
        db: Session,
        *,
        event_type: str,
        details: dict,
    ) -> AuditBlock:
        previous = db.query(AuditBlock).order_by(AuditBlock.id.desc()).first()
        previous_hash = previous.block_hash if previous else "0" * 64
        timestamp = datetime.utcnow().isoformat()
        details_json = json.dumps(details, sort_keys=True)

        block_hash = cls._calculate_hash(
            event_type=event_type,
            details_json=details_json,
            previous_hash=previous_hash,
            timestamp=timestamp,
        )

        block = AuditBlock(
            event_type=event_type,
            details_json=details_json,
            previous_hash=previous_hash,
            block_hash=block_hash,
            created_at=datetime.fromisoformat(timestamp),
        )
        db.add(block)
        db.commit()
        db.refresh(block)
        return block

    @classmethod
    def verify_chain(cls, db: Session) -> tuple[bool, list[str]]:
        blocks = db.query(AuditBlock).order_by(AuditBlock.id.asc()).all()
        errors: list[str] = []
        expected_previous = "0" * 64

        for block in blocks:
            if block.previous_hash != expected_previous:
                errors.append(
                    f"Block {block.id}: previous hash mismatch"
                )

            expected_hash = cls._calculate_hash(
                event_type=block.event_type,
                details_json=block.details_json,
                previous_hash=block.previous_hash,
                timestamp=block.created_at.isoformat(),
            )
            if expected_hash != block.block_hash:
                errors.append(f"Block {block.id}: block hash mismatch")

            expected_previous = block.block_hash

        return len(errors) == 0, errors
