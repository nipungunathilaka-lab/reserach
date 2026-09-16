import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from app.database.db import ML_DIR

logger = logging.getLogger(__name__)

TELEMETRY_LOG_PATH = ML_DIR / "production_telemetry.jsonl"

class TelemetryService:
    @staticmethod
    def record_transfer(features: Dict[str, Any]) -> None:
        """
        Record anonymized telemetry features from a secure transfer for 
        potential future evaluation and retraining.
        """
        try:
            # Ensure safe structure without PII or file contents
            telemetry_record = {
                "timestamp": datetime.utcnow().isoformat(),
                "file_size_mb": float(features.get("file_size_mb", 0.0)),
                "hour_of_day": int(features.get("hour_of_day", 0)),
                "transfers_last_hour": int(features.get("transfers_last_hour", 0)),
                "mfa_failed_attempts": int(features.get("mfa_failed_attempts", 0)),
                "failed_login_attempts": int(features.get("failed_login_attempts", 0)),
                "high_risk_file_type": int(features.get("high_risk_file_type", 0)),
                "archive_file_type": int(features.get("archive_file_type", 0)),
                "is_unusual_hour": int(features.get("is_unusual_hour", 0)),
                "anomaly_score": float(features.get("anomaly_score", 0.0)),
                "ml_prediction": str(features.get("ml_prediction", "normal"))
            }
            
            with open(TELEMETRY_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(telemetry_record) + "\n")
                
        except Exception as e:
            logger.error(f"Failed to record production telemetry: {e}")
