"""Export real system transfer logs into an AI training CSV.

Run from backend folder after the system has real/demo transfer history:
    python -m app.scripts.export_ai_training_data

The exported CSV can be selected for training by setting this in backend/.env:
    AI_DATASET_PATH=real_transfer_dataset.csv
"""

from __future__ import annotations

import csv

from app.database.db import ML_DIR, SessionLocal, init_db
from app.database.models import Transfer
from app.services.ai_service import AIService, FEATURES

OUTPUT_PATH = ML_DIR / "real_transfer_dataset.csv"


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        transfers = db.query(Transfer).order_by(Transfer.created_at.asc()).all()
        ML_DIR.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "transfer_id",
            "sender_id",
            "receiver_id",
            "file_name",
            "file_size_mb",
            "transfer_time",
            "hour_of_day",
            "transfers_last_hour",
            "mfa_failed_attempts",
            "failed_login_attempts",
            "is_unusual_hour",
            "high_risk_file_type",
            "archive_file_type",
            "integrity_status",
            "transfer_status",
            "is_anomaly",
            "anomaly_reason",
            "anomaly_level",
            "anomaly_score",
        ]
        with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for t in transfers:
                high_risk, archive = AIService.file_type_features(t.file_name)
                writer.writerow(
                    {
                        "transfer_id": t.id,
                        "sender_id": t.sender_id,
                        "receiver_id": t.receiver_id,
                        "file_name": t.file_name,
                        "file_size_mb": round(t.file_size / (1024 * 1024), 4),
                        "transfer_time": t.created_at.isoformat(),
                        "hour_of_day": t.created_at.hour,
                        "transfers_last_hour": t.transfers_last_hour,
                        "mfa_failed_attempts": t.mfa_failed_attempts,
                        "failed_login_attempts": t.sender_failed_login_attempts,
                        "is_unusual_hour": int(t.created_at.hour < 6 or t.created_at.hour > 22),
                        "high_risk_file_type": int(t.high_risk_file_type or high_risk),
                        "archive_file_type": archive,
                        "integrity_status": t.integrity_status,
                        "transfer_status": t.status,
                        "is_anomaly": int(t.is_anomaly),
                        "anomaly_reason": t.anomaly_reason or "",
                        "anomaly_level": t.anomaly_level or "low",
                        "anomaly_score": t.anomaly_score or 0,
                    }
                )
        print(f"Exported {len(transfers)} transfer record(s) to {OUTPUT_PATH}")
        print(f"Required AI feature columns: {', '.join(FEATURES)}")
        if len(transfers) < 50:
            print("Warning: collect at least 50-100 mostly normal real transfers before replacing the lab dataset.")
        print("After review/labeling, set AI_DATASET_PATH=real_transfer_dataset.csv and restart the backend.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
