from typing import Optional, Tuple
from app.database.db import SessionLocal
from app.database.models import PQCKey
import logging

logger = logging.getLogger(__name__)

class KeyIntegrityMonitor:
    def __init__(self):
        pass
        
    def verify_public_key(self, user_id: str, current_spki_fingerprint: str) -> Tuple[bool, Optional[str]]:
        from app.database.models import TrustedClientKey
        
        db = SessionLocal()
        try:
            trusted_key = db.query(TrustedClientKey).filter(TrustedClientKey.user_id == str(user_id)).first()
            
            # TOFU-based key continuity detects unexpected public-key changes after initial trust establishment; it does not independently authenticate the first contact.
            if not trusted_key:
                trusted_key = TrustedClientKey(user_id=str(user_id), fingerprint=current_spki_fingerprint, status="TRUSTED")
                db.add(trusted_key)
                db.commit()
                return True, current_spki_fingerprint
                
            if trusted_key.status == "REVOKED":
                return False, trusted_key.fingerprint
                
            if trusted_key.status == "ROTATION_PENDING" and trusted_key.fingerprint != current_spki_fingerprint:
                # Approved rotation workflow
                trusted_key.fingerprint = current_spki_fingerprint
                trusted_key.status = "ROTATED"
                db.commit()
                return True, current_spki_fingerprint

            if trusted_key.fingerprint != current_spki_fingerprint:
                # Fail closed. The old fingerprint is preserved in the database for audit evidence.
                logger.warning(f"Public key substitution attempt detected for user {user_id}. Expected {trusted_key.fingerprint}, got {current_spki_fingerprint}")
                return False, trusted_key.fingerprint
                
            return True, trusted_key.fingerprint
        finally:
            db.close()

key_integrity_monitor = KeyIntegrityMonitor()
