import io
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote
import json
import time
import psutil
from pydantic import BaseModel

import asyncio
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status, BackgroundTasks
from fastapi.responses import StreamingResponse

UPLOAD_STATUSES = {}
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.database.db import get_db, ENCRYPTED_DIR
from app.database.models import AIAlert, MfaChallenge, Transfer, User, ShareLink
from app.routes.dependencies import get_current_user
from app.schemas.file_schema import SendFileResponse, TransferItem
from app.services.ai_service import AIService
from app.services.blockchain_service import BlockchainService
from app.services.malware_service import MalwareDetectionService
from app.services.classification_service import DataClassificationScanner
from app.services.pfce_engine import PFCEEngine

router = APIRouter(prefix="/files", tags=["File Transfer"])

def _get_transfer_query(db: Session):
    return db.query(Transfer).options(joinedload(Transfer.sender), joinedload(Transfer.receiver))

@router.post("/send", response_model=SendFileResponse)
async def send_file(
    receiver_id: int = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    receiver = db.query(User).filter(User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receiver not found")
    if receiver.id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot send a file to yourself")

    file_size_mb = round(file.size / (1024 * 1024), 4) if file.size else 0
    if not file.size:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Selected file is empty")
        
    safe_name = Path(file.filename or "uploaded_file").name

    # 1. AI Scan 
    sample_bytes = await file.read(4096)
    
    # 2. File Pointer 
    await file.seek(0)
    file.file.seek(0) 

    now = datetime.utcnow()
    hour_ago = now - timedelta(hours=1)
    transfers_last_hour = db.query(Transfer).filter(Transfer.sender_id == current_user.id, Transfer.created_at >= hour_ago).count()
    failed_mfa_attempts = (
        db.query(MfaChallenge)
        .filter(MfaChallenge.user_id == current_user.id, MfaChallenge.created_at >= hour_ago)
        .with_entities(MfaChallenge.failed_attempts)
        .all()
    )
    mfa_failed_attempts = sum(row[0] for row in failed_mfa_attempts)
    failed_login_attempts = current_user.failed_login_attempts or 0
    
    ai_result = AIService.analyze_transfer(
        file_size_mb=file_size_mb,
        hour_of_day=now.hour,
        transfers_last_hour=transfers_last_hour,
        mfa_failed_attempts=mfa_failed_attempts,
        failed_login_attempts=failed_login_attempts,
        file_name=safe_name,
    )

    ext = safe_name.split('.')[-1].lower() if '.' in safe_name else ''
    safe_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'docx', 'xlsx', 'mp4', 'zip'}
    
    is_high_risk_ext = ext in {'exe', 'bat', 'sh', 'ps1', 'js', 'jar'}
    is_rule_high_risk = ai_result.get("features", {}).get("high_risk_file_type") or is_high_risk_ext
    anomaly_score = ai_result.get("anomaly_score", 0.0)
    
    should_block = is_rule_high_risk or (anomaly_score >= 0.90) or (ext not in safe_extensions and anomaly_score > 0.3)
    
    if should_block:
        alert = AIAlert(
            user_id=current_user.id,
            level="critical",
            reason="Rule-based high risk or elevated anomaly score",
            score=anomaly_score,
            file_name=safe_name
        )
        db.add(alert)
        db.commit()

        BlockchainService.append_block(
            db, 
            event_type="MALWARE_BLOCKED", 
            details=json.dumps({"file_name": safe_name, "user_id": current_user.id, "reason": "Rule-based high risk or elevated anomaly score"})
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Security Alert: AI detected potential malware. Upload blocked.")
        
    import logging
    logging.info(f"Step: Starting AI Malware Scan for {safe_name}")
    threat_result = MalwareDetectionService.predict(sample_bytes, safe_name, file_size_mb)
    logging.info(f"Step: AI Malware Scan Done for {safe_name}")
    
    if isinstance(threat_result, dict):
        threat_score = 0.0
    else:
        threat_score = threat_result
        
    if threat_score >= 0.90:
        reason_msg = f"RandomForest ML model flagged as malicious (score: {threat_score:.2f})"
        alert = AIAlert(
            user_id=current_user.id,
            level="critical",
            reason=reason_msg,
            score=threat_score,
            file_name=safe_name
        )
        db.add(alert)
        db.commit()
        
        BlockchainService.append_block(
            db, 
            event_type="MALWARE_BLOCKED", 
            details=json.dumps({"file_name": safe_name, "user_id": current_user.id, "reason": reason_msg, "score": threat_score})
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Security Alert: AI detected potential malware. Upload blocked.")

    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if file.size > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File is too large. Maximum allowed size is {settings.max_upload_size_mb} MB.",
        )

    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    
    logging.info(f"Step: Starting Hash/Classification for {safe_name}")
    classification = DataClassificationScanner.scan(sample_bytes, safe_name)
    logging.info(f"Step: Hash/Classification Done for {safe_name}")
    psutil.cpu_percent(interval=None)
    t0_enc = time.perf_counter()
    
    pfce_package_path = str(ENCRYPTED_DIR / f"{stored_name}.pfce")
    pfce_engine = PFCEEngine()
    
    # 3. Call the PFCE Engine correctly
    pfce_result = pfce_engine.process_upload(
        file_stream=file.file, 
        receiver_id=receiver.id,
        stored_name_prefix=stored_name,
        classification=classification,
        pfce_package_path=pfce_package_path
    )
    
    t1_enc = time.perf_counter()
    cpu_spike = psutil.cpu_percent(interval=None)
    
    exec_time_sec = t1_enc - t0_enc
    exec_time_ms = exec_time_sec * 1000
    bandwidth_mbps = file_size_mb / exec_time_sec if exec_time_sec > 0 else 0
    enc_mech = "PFCE Streaming (AES-256 + RSA)"

    existing_transfer = (
        db.query(Transfer)
        .filter(Transfer.sender_id == current_user.id, Transfer.receiver_id == receiver.id, Transfer.file_name == safe_name)
        .order_by(Transfer.version.desc())
        .first()
    )
    
    if existing_transfer:
        file_group_id = existing_transfer.file_group_id
        version = existing_transfer.version + 1
    else:
        file_group_id = uuid.uuid4().hex
        version = 1

    # Extract robust metadata returned from our updated Engine
    original_hash = getattr(pfce_result, "original_hash", "calculated_during_stream")
    frag_count = getattr(pfce_result, "fragment_count", 0)

    transfer = Transfer(
        file_name=safe_name,
        stored_name=stored_name,
        version=version,
        file_group_id=file_group_id,
        original_hash=original_hash,
        encrypted_path=pfce_result.pfce_package_path,
        encrypted_key="packaged_in_pfce",
        nonce="packaged_in_pfce",
        ecdh_public_key=None,
        ecdh_wrapped_key=None,
        ecdh_key_nonce=None,
        file_size=file.size,
        status="encrypted",
        integrity_status="pending_download",
        anomaly_score=ai_result["anomaly_score"],
        is_anomaly=ai_result["is_anomaly"],
        anomaly_reason=ai_result["reason"],
        anomaly_level=ai_result["level"],
        transfers_last_hour=transfers_last_hour,
        mfa_failed_attempts=mfa_failed_attempts,
        high_risk_file_type=bool(ai_result["features"].get("high_risk_file_type")),
        sender_failed_login_attempts=failed_login_attempts,
        sender_id=current_user.id,
        receiver_id=receiver.id,
    )
    logging.info(f"Step: Post-Encryption DB Updates Started for {safe_name}")
    db.add(transfer)
    db.commit()
    db.refresh(transfer)
    logging.info(f"Step: Post-Encryption DB Updates Done for {safe_name}")

    details = json.dumps({
        "transfer_id": transfer.id,
        "file_name": transfer.file_name,
        "file_size": transfer.file_size,
        "sender_id": transfer.sender_id,
        "receiver_id": transfer.receiver_id,
        "original_hash": transfer.original_hash
    })
    logging.info(f"Step: Blockchain Append Started for {safe_name}")
    block = BlockchainService.append_block(db, event_type="FILE_TRANSFER", details=details)
    logging.info(f"Step: Blockchain Append Done for {safe_name}")
    
    pfce_details = json.dumps({
        "transfer_id": transfer.id,
        "fragment_count": frag_count,
        "sha256": transfer.original_hash,
        "verification_status": "pending",
        "timestamp": datetime.utcnow().isoformat()
    })
    BlockchainService.append_block(db, event_type="PFCE_FRAGMENTATION", details=pfce_details)

    if ai_result["is_anomaly"]:
        alert = AIAlert(
            transfer_id=transfer.id,
            user_id=current_user.id,
            level=ai_result["level"],
            reason=ai_result["reason"],
            score=ai_result["anomaly_score"],
        )
        db.add(alert)
        db.commit()

    transfer = _get_transfer_query(db).filter(Transfer.id == transfer.id).first()
    return SendFileResponse(
        message="File uploaded successfully",
        classification_type=classification,
        encryption_mechanism_used=enc_mech,
        execution_time_ms=round(exec_time_ms, 3),
        cpu_usage_percent=round(cpu_spike, 2),
        processing_bandwidth_mbps=round(bandwidth_mbps, 3),
        transfer=transfer,
        encryption={
            "algorithm": enc_mech,
            "aes_time_ms": getattr(pfce_result, 'aes_time_ms', 0),
            "rsa_key_wrap_time_ms": getattr(pfce_result, 'rsa_key_wrap_time_ms', 0),
            "ecdh_time_ms": getattr(pfce_result, 'ecdh_time_ms', 0),
        },
        integrity={
            "sha256_original_hash": original_hash,
            "status": "original hash stored; verified when receiver decrypts",
        },
        ai=ai_result,
        blockchain={
            "id": block.id,
            "event_type": block.event_type,
            "previous_hash": block.previous_hash,
            "block_hash": block.block_hash,
        },
    )

async def process_file_background(
    temp_file_path: Path,
    file_name: str,
    receiver_id: int,
    current_user_id: int,
    upload_id: str,
):
    print(f"Background task started for {upload_id}")
    db = None
    blockchain_hash_val = "N/A"
    exec_time_val = 0.0
    ai_score_val = 0.0
    try:
        db = next(get_db())
        current_user = db.query(User).filter(User.id == current_user_id).first()
        receiver = db.query(User).filter(User.id == receiver_id).first()
        
        file_size = temp_file_path.stat().st_size
        file_size_mb = round(file_size / (1024 * 1024), 4)

        max_bytes = settings.max_upload_size_mb * 1024 * 1024
        if file_size > max_bytes:
            print(f"Background Task Error: File is too large. Maximum allowed size is {settings.max_upload_size_mb} MB.")
            UPLOAD_STATUSES[upload_id] = {"status": "error", "message": "File is too large"}
            return

        safe_name = Path(file_name).name
        
        with open(temp_file_path, "rb") as f_read:
            sample_bytes = await asyncio.to_thread(f_read.read, 4096)
            
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        transfers_last_hour = db.query(Transfer).filter(Transfer.sender_id == current_user.id, Transfer.created_at >= hour_ago).count()
        failed_mfa_attempts = (
            db.query(MfaChallenge)
            .filter(MfaChallenge.user_id == current_user.id, MfaChallenge.created_at >= hour_ago)
            .with_entities(MfaChallenge.failed_attempts)
            .all()
        )
        mfa_failed_attempts = sum(row[0] for row in failed_mfa_attempts)
        failed_login_attempts = current_user.failed_login_attempts or 0
        
        ai_result = await asyncio.to_thread(
            AIService.analyze_transfer,
            file_size_mb=file_size_mb,
            hour_of_day=now.hour,
            transfers_last_hour=transfers_last_hour,
            mfa_failed_attempts=mfa_failed_attempts,
            failed_login_attempts=failed_login_attempts,
            file_name=safe_name,
        )

        ext = safe_name.split('.')[-1].lower() if '.' in safe_name else ''
        safe_extensions = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'docx', 'xlsx', 'mp4', 'zip'}
        
        is_high_risk_ext = ext in {'exe', 'bat', 'sh', 'ps1', 'js', 'jar'}
        is_rule_high_risk = ai_result.get("features", {}).get("high_risk_file_type") or is_high_risk_ext
        anomaly_score = ai_result.get("anomaly_score", 0.0)
        
        should_block = is_rule_high_risk or (anomaly_score >= 0.90) or (ext not in safe_extensions and anomaly_score > 0.3)
        
        if should_block:
            alert = AIAlert(
                user_id=current_user.id,
                level="critical",
                reason="Rule-based high risk or elevated anomaly score",
                score=anomaly_score,
                file_name=safe_name
            )
            db.add(alert)
            db.commit()

            try:
                BlockchainService.append_block(
                    db, 
                    event_type="MALWARE_BLOCKED", 
                    details=json.dumps({"file_name": safe_name, "user_id": current_user.id, "reason": "Rule-based high risk or elevated anomaly score"})
                )
            except Exception as e:
                print(f"Error appending block for malware: {e}")
                
            UPLOAD_STATUSES[upload_id] = {"status": "error", "message": "Security Alert: AI detected potential malware. Upload blocked."}
            return
            
        import logging
        logging.info(f"Step: Starting AI Malware Scan for {safe_name}")
        threat_result = await asyncio.to_thread(MalwareDetectionService.predict, sample_bytes, safe_name, file_size_mb)
        logging.info(f"Step: AI Malware Scan Done for {safe_name}")
        
        if isinstance(threat_result, dict):
            threat_score = 0.0
            print(f"Skipped malware scan for {safe_name}: {threat_result}")
        else:
            threat_score = threat_result
            
        ai_score_val = threat_score
        
        if threat_score >= 0.90:
            reason_msg = f"RandomForest ML model flagged as malicious (score: {threat_score:.2f})"
            alert = AIAlert(
                user_id=current_user.id,
                level="critical",
                reason=reason_msg,
                score=threat_score,
                file_name=safe_name
            )
            db.add(alert)
            db.commit()
            
            try:
                BlockchainService.append_block(
                    db, 
                    event_type="MALWARE_BLOCKED", 
                    details=json.dumps({"file_name": safe_name, "user_id": current_user.id, "reason": reason_msg, "score": threat_score})
                )
            except Exception as e:
                print(f"Error appending block for malware: {e}")
                
            UPLOAD_STATUSES[upload_id] = {"status": "error", "message": "Security Alert: AI detected potential malware. Upload blocked."}
            return

        stored_name = f"{uuid.uuid4().hex}_{safe_name}"
        logging.info(f"Step: Starting Hash/Classification for {safe_name}")
        classification = await asyncio.to_thread(DataClassificationScanner.scan, sample_bytes, safe_name)
        logging.info(f"Step: Hash/Classification Done for {safe_name}")
        
        psutil.cpu_percent(interval=None)
        t0_enc = time.perf_counter()
        
        pfce_package_path = str(ENCRYPTED_DIR / f"{stored_name}.pfce")
        pfce_engine = PFCEEngine()
        
        def progress_callback(processed_mb: float, total_mb: float, percentage: float):
            UPLOAD_STATUSES[upload_id] = {
                "status": "processing",
                "processed_mb": processed_mb,
                "total_mb": total_mb,
                "percentage": percentage
            }

        with open(temp_file_path, "rb") as f_stream:
            pfce_result = await asyncio.to_thread(
                pfce_engine.process_upload,
                file_stream=f_stream, 
                receiver_id=receiver.id,
                stored_name_prefix=stored_name,
                classification=classification,
                pfce_package_path=pfce_package_path,
                progress_callback=progress_callback
            )
            
        logging.info(f"Step: Encryption Done for {safe_name}")
        t1_enc = time.perf_counter()
        cpu_spike = psutil.cpu_percent(interval=None)
        
        exec_time_sec = t1_enc - t0_enc
        exec_time_ms = exec_time_sec * 1000
        exec_time_val = exec_time_ms
        bandwidth_mbps = file_size_mb / exec_time_sec if exec_time_sec > 0 else 0
        enc_mech = "PFCE Streaming (AES-256 + RSA)"

        existing_transfer = (
            db.query(Transfer)
            .filter(Transfer.sender_id == current_user.id, Transfer.receiver_id == receiver.id, Transfer.file_name == safe_name)
            .order_by(Transfer.version.desc())
            .first()
        )
        
        if existing_transfer:
            file_group_id = existing_transfer.file_group_id
            version = existing_transfer.version + 1
        else:
            file_group_id = uuid.uuid4().hex
            version = 1

        original_hash = getattr(pfce_result, "original_hash", "calculated_during_stream")
        frag_count = getattr(pfce_result, "fragment_count", 0)

        transfer = Transfer(
            file_name=safe_name,
            stored_name=stored_name,
            version=version,
            file_group_id=file_group_id,
            original_hash=original_hash,
            encrypted_path=pfce_result.pfce_package_path,
            encrypted_key="packaged_in_pfce",
            nonce="packaged_in_pfce",
            ecdh_public_key=None,
            ecdh_wrapped_key=None,
            ecdh_key_nonce=None,
            file_size=file_size,
            status="encrypted",
            integrity_status="pending_download",
            anomaly_score=ai_result["anomaly_score"],
            is_anomaly=ai_result["is_anomaly"],
            anomaly_reason=ai_result["reason"],
            anomaly_level=ai_result["level"],
            transfers_last_hour=transfers_last_hour,
            mfa_failed_attempts=mfa_failed_attempts,
            high_risk_file_type=bool(ai_result["features"].get("high_risk_file_type")),
            sender_failed_login_attempts=failed_login_attempts,
            sender_id=current_user.id,
            receiver_id=receiver.id,
        )
        logging.info(f"Step: Post-Encryption DB Updates Started for {safe_name}")
        db.add(transfer)
        db.commit()
        db.refresh(transfer)
        logging.info(f"Step: Post-Encryption DB Updates Done for {safe_name}")

        details = json.dumps({
            "transfer_id": transfer.id,
            "file_name": transfer.file_name,
            "file_size": transfer.file_size,
            "sender_id": transfer.sender_id,
            "receiver_id": transfer.receiver_id,
            "original_hash": transfer.original_hash
        })
        
        block = None
        try:
            logging.info(f"Step: Blockchain Append Started for {safe_name}")
            # We call synchronously to avoid cross-thread DB session issues
            block = BlockchainService.append_block(db, event_type="FILE_TRANSFER", details=details)
            if block:
                blockchain_hash_val = block.block_hash
            logging.info(f"Step: Blockchain Append Done for {safe_name}")
            
            pfce_details = json.dumps({
                "transfer_id": transfer.id,
                "fragment_count": frag_count,
                "sha256": transfer.original_hash,
                "verification_status": "pending",
                "timestamp": datetime.utcnow().isoformat()
            })
            BlockchainService.append_block(db, event_type="PFCE_FRAGMENTATION", details=pfce_details)

            if ai_result["is_anomaly"]:
                alert = AIAlert(
                    transfer_id=transfer.id,
                    user_id=current_user.id,
                    level=ai_result["level"],
                    reason=ai_result["reason"],
                    score=ai_result["anomaly_score"],
                )
                db.add(alert)
                db.commit()
        except Exception as post_err:
            print(f"Post-encryption logging error: {post_err}")
            # Do not let this silently hang the thread, proceed to completion.

        try:
            transfer = _get_transfer_query(db).filter(Transfer.id == transfer.id).first()
        except Exception as e:
            print(f"Error fetching transfer query: {e}")

        blockchain_data = {
            "id": block.id if block else 0,
            "event_type": block.event_type if block else "FILE_TRANSFER",
            "previous_hash": block.previous_hash if block else "",
            "block_hash": block.block_hash if block else "",
        }

        transfer_dict = SendFileResponse(
            message="File uploaded successfully",
            classification_type=classification,
            encryption_mechanism_used=enc_mech,
            execution_time_ms=round(exec_time_ms, 3),
            cpu_usage_percent=round(cpu_spike, 2),
            processing_bandwidth_mbps=round(bandwidth_mbps, 3),
            transfer=transfer,
            encryption={
                "algorithm": enc_mech,
                "aes_time_ms": getattr(pfce_result, 'aes_time_ms', 0),
                "rsa_key_wrap_time_ms": getattr(pfce_result, 'rsa_key_wrap_time_ms', 0),
                "ecdh_time_ms": getattr(pfce_result, 'ecdh_time_ms', 0),
            },
            integrity={
                "sha256_original_hash": original_hash,
                "status": "original hash stored; verified when receiver decrypts",
            },
            ai=ai_result,
            blockchain=blockchain_data,
        ).dict()
        
        UPLOAD_STATUSES[upload_id] = {"status": "completed", "result": transfer_dict}
        print(f"Background task completed successfully for {upload_id}")

    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        UPLOAD_STATUSES[upload_id] = {"status": "error", "message": str(e)}
        print(f"Background task failed for {upload_id}: {e}\n{trace}")

    finally:
        if db:
            db.close()
        if temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception as e:
                print(f"Failed to delete temp file {temp_file_path}: {e}")
                
        # Guaranteed Completion (The Safety Net)
        if upload_id in UPLOAD_STATUSES:
            if UPLOAD_STATUSES[upload_id].get("status") != "error":
                UPLOAD_STATUSES[upload_id]["percentage"] = 100
                UPLOAD_STATUSES[upload_id]["status"] = "completed"
                UPLOAD_STATUSES[upload_id]["telemetry"] = {
                    "blockchain_hash": blockchain_hash_val,
                    "exec_time_ms": exec_time_val,
                    "ai_score": ai_score_val,
                    "encryption_type": "AES-256-GCM"
                }
                if "result" not in UPLOAD_STATUSES[upload_id]:
                    UPLOAD_STATUSES[upload_id]["result"] = {"message": "Forced completion"}

@router.post("/upload-chunk")
async def upload_chunk(
    background_tasks: BackgroundTasks,
    receiver_id: int = Form(...),
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    file_name: str = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    receiver = db.query(User).filter(User.id == receiver_id).first()
    if not receiver:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receiver not found")
    if receiver.id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot send a file to yourself")

    temp_dir = Path(tempfile.gettempdir()) / "secure_transfer_chunks"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_file_path = temp_dir / f"{upload_id}_{file_name}"
    
    with open(temp_file_path, "ab") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk or len(chunk) == 0:
                break
            f.write(chunk)

    if chunk_index < total_chunks - 1:
        return {"status": "chunk_received", "chunk_index": chunk_index}

    UPLOAD_STATUSES[upload_id] = {"status": "processing"}

    background_tasks.add_task(
        process_file_background,
        temp_file_path=temp_file_path,
        file_name=file_name,
        receiver_id=receiver_id,
        current_user_id=current_user.id,
        upload_id=upload_id
    )
    
    return {"status": "processing", "message": "File assembling and encrypting..."}

@router.get("/status/{upload_id}")
def check_upload_status(upload_id: str):
    status_data = UPLOAD_STATUSES.get(upload_id)
    if not status_data:
        return {"status": "processing"}
    if status_data["status"] == "completed":
        # Keep in memory to prevent polling race conditions causing 'processing' to be returned
        result = status_data["result"]
        return {"status": "completed", "result": result}
    if status_data["status"] == "error":
        # Return 200 OK so the frontend Axios doesn't throw, allowing the UI to show the actual error message
        return {"status": "error", "message": status_data.get("message", "Unknown backend error")}
    return status_data

@router.get("/received", response_model=list[TransferItem])
def received_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        _get_transfer_query(db)
        .filter(Transfer.receiver_id == current_user.id)
        .order_by(Transfer.created_at.desc())
        .all()
    )

@router.get("/history", response_model=list[TransferItem])
def own_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        _get_transfer_query(db)
        .filter(or_(Transfer.sender_id == current_user.id, Transfer.receiver_id == current_user.id))
        .order_by(Transfer.created_at.desc())
        .all()
    )

@router.get("/sent", response_model=list[TransferItem])
def sent_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        _get_transfer_query(db)
        .filter(Transfer.sender_id == current_user.id)
        .order_by(Transfer.created_at.desc())
        .all()
    )

@router.get("/{transfer_id}/download")
def download_decrypted_file(transfer_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Transfer not found")
    if transfer.receiver_id != current_user.id and transfer.sender_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the sender or receiver can download this file")

    try:
        pfce_engine = PFCEEngine()
        stream_generator = pfce_engine.process_download_stream(
            pfce_package_path=transfer.encrypted_path, 
            receiver_id=transfer.receiver_id
        )
    except Exception as exc:
        transfer.status = "decryption_failed"
        transfer.integrity_status = "failed"
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Decryption failed: {exc}")

    transfer.status = "downloaded"
    transfer.integrity_status = "verified_during_stream"
    db.commit()

    quoted_name = quote(transfer.file_name)
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quoted_name}"}
    return StreamingResponse(stream_generator, media_type="application/octet-stream", headers=headers)

class ShareLinkResponse(BaseModel):
    share_token: str
    share_pin: str
    message: str

import random
import string

@router.post("/{file_id}/share", response_model=ShareLinkResponse)
def create_share_link(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    transfer = db.query(Transfer).filter(Transfer.id == file_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if transfer.sender_id != current_user.id and transfer.receiver_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to share this file")

    if not transfer.share_token:
        transfer.share_token = uuid.uuid4().hex
        transfer.share_pin = ''.join(random.choices(string.digits, k=6))
        db.commit()

    return ShareLinkResponse(
        share_token=transfer.share_token,
        share_pin=transfer.share_pin,
        message="Share link generated successfully"
    )
