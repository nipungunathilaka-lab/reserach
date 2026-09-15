from typing import Optional, Tuple
from app.database.db import SessionLocal
from app.database.models import PQCKey
import logging

logger = logging.getLogger(__name__)

class KeyIntegrityMonitor:
    def __init__(self):
        pass
        
    def verify_public_key(self, user_id: int, current_spki_fingerprint: str) -> Tuple[bool, Optional[str]]:
        """
        Verify if the provided public key fingerprint matches the active key for the user.
        Returns (is_valid, expected_fingerprint).
        If no active key is found, we might accept the first one or require enrollment.
        For this prototype, if it doesn't match the known active key, we return False.
        """
        db = SessionLocal()
        try:
            active_key = db.query(PQCKey).filter(
                PQCKey.user_id == user_id, 
                PQCKey.is_active == True
            ).first()
            
            if not active_key:
                return True, None # No baseline yet
                
            from app.services.crypto_service import CryptoService
            expected_fingerprint = CryptoService.get_spki_fingerprint(active_key.public_key)
            
            if expected_fingerprint != current_spki_fingerprint:
                logger.warning(f"Public key substitution attempt detected for user {user_id}. Expected {expected_fingerprint}, got {current_spki_fingerprint}")
                return False, expected_fingerprint
                
            return True, expected_fingerprint
        finally:
            db.close()

key_integrity_monitor = KeyIntegrityMonitor()
