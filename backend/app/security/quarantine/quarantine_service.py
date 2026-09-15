import uuid
import hashlib
from datetime import datetime
from sqlalchemy.orm import Session
from app.database.db import SessionLocal
from app.database.models import QuarantineItem, AuditBlock
from .quarantine_storage import save_to_quarantine, load_from_quarantine, delete_from_quarantine
from app.services.malware_service import MalwareDetectionService

class QuarantineService:
    
    @classmethod
    def _log_audit_event(cls, db: Session, event_type: str, details: dict):
        import json
        prev_block = db.query(AuditBlock).order_by(AuditBlock.id.desc()).first()
        prev_hash = prev_block.block_hash if prev_block else "0" * 64
        
        block_content = f"{prev_hash}{event_type}{json.dumps(details)}"
        block_hash = hashlib.sha256(block_content.encode()).hexdigest()
        
        block = AuditBlock(
            event_type=event_type,
            details_json=json.dumps(details),
            previous_hash=prev_hash,
            block_hash=block_hash
        )
        db.add(block)
        db.commit()

    @classmethod
    def quarantine_file(
        cls, 
        user_id: int, 
        original_filename: str, 
        file_bytes: bytes, 
        detection_engine: str, 
        reason: str,
        detection_name: str = None,
        malware_score: float = None,
        transfer_id: str = None
    ) -> QuarantineItem:
        db = SessionLocal()
        try:
            safe_id = f"q_{uuid.uuid4().hex}"
            file_size = len(file_bytes)
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            
            # Save to isolated storage
            save_to_quarantine(safe_id, file_bytes)
            
            item = QuarantineItem(
                transfer_id=transfer_id,
                user_id=user_id,
                original_filename=original_filename,
                safe_identifier=safe_id,
                sha256=sha256,
                file_size=file_size,
                detection_engine=detection_engine,
                detection_name=detection_name,
                malware_score=malware_score,
                quarantine_reason=reason,
                quarantine_status="QUARANTINED"
            )
            
            db.add(item)
            db.commit()
            
            # Audit log
            cls._log_audit_event(db, "MALWARE_QUARANTINED", {
                "quarantine_id": item.id,
                "user_id": user_id,
                "filename": original_filename,
                "sha256": sha256,
                "engine": detection_engine,
                "reason": reason
            })
            
            db.refresh(item)
            db.expunge(item)
            return item
        finally:
            db.close()

    @classmethod
    def get_quarantine_list(cls):
        db = SessionLocal()
        try:
            items = db.query(QuarantineItem).filter(QuarantineItem.quarantine_status != "DELETED").all()
            for item in items:
                db.expunge(item)
            return items
        finally:
            db.close()
            
    @classmethod
    def get_item(cls, item_id: int):
        db = SessionLocal()
        try:
            item = db.query(QuarantineItem).filter(QuarantineItem.id == item_id).first()
            if item:
                db.expunge(item)
            return item
        finally:
            db.close()

    @classmethod
    def rescan_item(cls, item_id: int, admin_user: str) -> dict:
        db = SessionLocal()
        try:
            item = db.query(QuarantineItem).filter(QuarantineItem.id == item_id).first()
            if not item:
                return {"error": "Item not found"}
                
            file_bytes = load_from_quarantine(item.safe_identifier)
            
            # Perform new scan
            scan_result = MalwareDetectionService.scan_full_file(file_bytes, item.original_filename)
            
            item.reviewed_at = datetime.utcnow()
            item.reviewed_by = admin_user
            
            cls._log_audit_event(db, "QUARANTINE_RESCAN", {
                "quarantine_id": item.id,
                "admin": admin_user,
                "new_result": scan_result
            })
            
            db.commit()
            return {"status": "rescanned", "result": scan_result}
        finally:
            db.close()

    @classmethod
    def release_item(cls, item_id: int, admin_user: str) -> dict:
        db = SessionLocal()
        try:
            item = db.query(QuarantineItem).filter(QuarantineItem.id == item_id).first()
            if not item:
                return {"error": "Item not found"}
                
            # Must verify scan policy before release (Fail Closed)
            file_bytes = load_from_quarantine(item.safe_identifier)
            current_sha256 = hashlib.sha256(file_bytes).hexdigest()
            
            if current_sha256 != item.sha256:
                cls._log_audit_event(db, "QUARANTINE_RELEASE_DENIED", {"quarantine_id": item.id, "reason": "Hash mismatch"})
                return {"error": "Release denied: Integrity check failed."}
                
            scan_result = MalwareDetectionService.scan_full_file(file_bytes, item.original_filename)
            
            if scan_result.get("verdict") == "MALICIOUS":
                cls._log_audit_event(db, "QUARANTINE_RELEASE_DENIED", {"quarantine_id": item.id, "reason": "Still malicious"})
                return {"error": "Release denied: File is still flagged as malicious."}
                
            item.quarantine_status = "RELEASED"
            item.released_at = datetime.utcnow()
            item.reviewed_by = admin_user
            db.commit()
            
            cls._log_audit_event(db, "QUARANTINE_RELEASED", {
                "quarantine_id": item.id,
                "admin": admin_user
            })
            
            return {"status": "released", "item": item.id}
        finally:
            db.close()

    @classmethod
    def delete_item(cls, item_id: int, admin_user: str) -> dict:
        db = SessionLocal()
        try:
            item = db.query(QuarantineItem).filter(QuarantineItem.id == item_id).first()
            if not item:
                return {"error": "Item not found"}
                
            delete_from_quarantine(item.safe_identifier)
            
            item.quarantine_status = "DELETED"
            item.deleted_at = datetime.utcnow()
            db.commit()
            
            cls._log_audit_event(db, "QUARANTINE_DELETED", {
                "quarantine_id": item.id,
                "admin": admin_user
            })
            return {"status": "deleted"}
        finally:
            db.close()
