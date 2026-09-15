import json
from typing import Optional, List
from sqlalchemy.orm import Session
from app.database.models import KMSKey
from app.core.config import settings

class KeyRegistry:
    
    @staticmethod
    def get_active_key(db: Session, purpose: str) -> Optional[KMSKey]:
        return db.query(KMSKey).filter(
            KMSKey.purpose == purpose,
            KMSKey.status == "ACTIVE"
        ).order_by(KMSKey.version.desc()).first()

    @staticmethod
    def get_key_by_version(db: Session, purpose: str, version: int) -> Optional[KMSKey]:
        return db.query(KMSKey).filter(
            KMSKey.purpose == purpose,
            KMSKey.version == version
        ).first()

    @staticmethod
    def register_key(
        db: Session,
        purpose: str,
        provider_key_id: str,
        alias: Optional[str] = None,
        provider_key_arn: Optional[str] = None,
        key_spec: Optional[str] = None,
        key_usage: Optional[str] = None
    ) -> KMSKey:
        
        # Check if there is an active key, if so, we are rotating
        active_key = KeyRegistry.get_active_key(db, purpose)
        new_version = 1
        if active_key:
            new_version = active_key.version + 1
            # We don't automatically retire the old one in case it's needed for verification,
            # but we mark it as VERIFY_ONLY or leave it ACTIVE but use the newer version.
            # Best practice for asymmetric rotation: old key becomes VERIFY_ONLY
            active_key.status = "VERIFY_ONLY"
            db.add(active_key)

        new_key = KMSKey(
            purpose=purpose,
            provider=settings.key_provider,
            provider_key_id=provider_key_id,
            provider_key_arn=provider_key_arn,
            alias=alias,
            key_spec=key_spec,
            key_usage=key_usage,
            version=new_version,
            status="ACTIVE"
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)
        return new_key
