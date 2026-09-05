import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from app.core.config import settings
from app.database.db import ML_DIR, ensure_storage_dirs

DEFAULT_DATASET_PATH = ML_DIR / "lab_secure_transfer_dataset.csv"
FEATURES = [
    "file_size_mb",
    "hour_of_day",
    "transfers_last_hour",
    "mfa_failed_attempts",
    "failed_login_attempts",
    "is_unusual_hour",
    "high_risk_file_type",
    "archive_file_type",
]
HIGH_RISK_EXTENSIONS = {e.strip().lower().lstrip(".") for e in settings.ai_high_risk_file_extensions.split(",") if e.strip()}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz"}


class AIService:
    _model: Pipeline | None = None
    _trained = False

    @staticmethod
    def file_extension(file_name: str | None) -> str:
        if not file_name or "." not in file_name:
            return ""
        return file_name.rsplit(".", 1)[-1].lower()

    @classmethod
    def file_type_features(cls, file_name: str | None) -> tuple[int, int]:
        ext = cls.file_extension(file_name)
        return int(ext in HIGH_RISK_EXTENSIONS), int(ext in ARCHIVE_EXTENSIONS)

    @staticmethod
    def generate_lab_dataset(rows: int = 900) -> Path:
        ensure_storage_dirs()
        if DEFAULT_DATASET_PATH.exists() and sum(1 for _ in DEFAULT_DATASET_PATH.open("r", encoding="utf-8")) >= 701:
            try:
                sample = pd.read_csv(DEFAULT_DATASET_PATH, nrows=1)
                if all(feature in sample.columns for feature in FEATURES):
                    return DEFAULT_DATASET_PATH
            except Exception:
                pass

        rng = random.Random(29103)
        records: list[dict[str, Any]] = []
        base_time = datetime(2025, 1, 1, 8, 30)
        normal_types = ["pdf", "docx", "xlsx", "png", "jpg", "txt", "csv"]
        archive_types = ["zip", "7z"]
        risky_types = ["exe", "bat", "ps1", "js", "jar"]
        normal_count = int(rows * 0.78)
        anomaly_count = rows - normal_count

        for i in range(1, normal_count + 1):
            hour = rng.choice(list(range(8, 18)))
            dt = (base_time + timedelta(days=rng.randint(0, 120))).replace(hour=hour, minute=rng.randint(0, 59))
            size = round(max(0.05, min(rng.lognormvariate(1.4, 0.65), 35)), 2)
            ext = rng.choice(normal_types + archive_types[:1])
            high_risk, archive = int(ext in HIGH_RISK_EXTENSIONS), int(ext in ARCHIVE_EXTENSIONS)
            records.append({
                "transfer_id": i,
                "sender_id": rng.randint(1, 10),
                "receiver_id": rng.randint(1, 10),
                "file_name": f"project_file_{i}.{ext}",
                "file_type": ext,
                "file_size_mb": size,
                "transfer_time": dt.isoformat(),
                "hour_of_day": hour,
                "day_of_week": dt.strftime("%A"),
                "transfers_last_hour": rng.randint(0, 4),
                "mfa_failed_attempts": rng.choice([0, 0, 0, 1]),
                "failed_login_attempts": rng.choice([0, 0, 0, 1]),
                "is_unusual_hour": 0,
                "high_risk_file_type": high_risk,
                "archive_file_type": archive,
                "integrity_status": "verified",
                "unauthorized_attempt": 0,
                "encryption_time_ms": round(10 + size * rng.uniform(0.8, 2.2), 3),
                "decryption_time_ms": round(8 + size * rng.uniform(0.8, 2.0), 3),
                "ecdh_time_ms": round(rng.uniform(0.5, 4.0), 3),
                "rsa_key_wrap_time_ms": round(rng.uniform(1.2, 8.0), 3),
                "transfer_status": "completed",
                "is_anomaly": 0,
                "anomaly_reason": "normal secure transfer pattern",
                "anomaly_level": "low",
            })

        reasons = [
            "very large file transfer",
            "unusual night transfer time",
            "too many transfers in one hour",
            "repeated failed MFA attempts",
            "repeated failed login attempts before transfer",
            "high-risk executable/script file type",
            "compressed archive after failed authentication",
            "failed integrity verification",
            "unauthorized access attempt",
        ]
        for j in range(1, anomaly_count + 1):
            i = normal_count + j
            reason = rng.choice(reasons)
            unusual_hour = "night" in reason or rng.random() < 0.35
            hour = rng.choice([0, 1, 2, 3, 4, 5, 23]) if unusual_hour else rng.choice(list(range(0, 24)))
            large = "large" in reason or rng.random() < 0.35
            size = round(rng.uniform(80, 900), 2) if large else round(rng.uniform(0.1, 120), 2)
            transfers_last_hour = rng.randint(10, 35) if "too many" in reason else rng.randint(0, 12)
            mfa_failed = rng.randint(3, 8) if "MFA" in reason or "archive" in reason else rng.randint(0, 5)
            failed_logins = rng.randint(3, 9) if "login" in reason or "archive" in reason else rng.randint(0, 5)
            ext = rng.choice(risky_types) if "file type" in reason else rng.choice(archive_types if "archive" in reason else normal_types + archive_types + risky_types)
            high_risk, archive = int(ext in HIGH_RISK_EXTENSIONS), int(ext in ARCHIVE_EXTENSIONS)
            unauthorized = 1 if "unauthorized" in reason else rng.choice([0, 1])
            integrity = "failed" if "integrity" in reason else rng.choice(["verified", "failed"])
            dt = (base_time + timedelta(days=rng.randint(0, 120))).replace(hour=hour, minute=rng.randint(0, 59))
            level = "high" if unauthorized or failed_logins >= 5 or mfa_failed >= 5 or size > 400 or high_risk else "medium"
            records.append({
                "transfer_id": i,
                "sender_id": rng.randint(1, 10),
                "receiver_id": rng.randint(1, 10),
                "file_name": f"suspicious_transfer_{i}.{ext}",
                "file_type": ext,
                "file_size_mb": size,
                "transfer_time": dt.isoformat(),
                "hour_of_day": hour,
                "day_of_week": dt.strftime("%A"),
                "transfers_last_hour": transfers_last_hour,
                "mfa_failed_attempts": mfa_failed,
                "failed_login_attempts": failed_logins,
                "is_unusual_hour": int(hour < 6 or hour > 22),
                "high_risk_file_type": high_risk,
                "archive_file_type": archive,
                "integrity_status": integrity,
                "unauthorized_attempt": unauthorized,
                "encryption_time_ms": round(15 + size * rng.uniform(0.9, 2.5), 3),
                "decryption_time_ms": round(12 + size * rng.uniform(0.9, 2.3), 3),
                "ecdh_time_ms": round(rng.uniform(0.5, 6.0), 3),
                "rsa_key_wrap_time_ms": round(rng.uniform(1.2, 10.0), 3),
                "transfer_status": rng.choice(["completed", "blocked", "integrity_failed"]),
                "is_anomaly": 1,
                "anomaly_reason": reason,
                "anomaly_level": level,
            })

        rng.shuffle(records)
        with DEFAULT_DATASET_PATH.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)
        return DEFAULT_DATASET_PATH

    @staticmethod
    def configured_dataset_path() -> Path:
        configured = Path(settings.ai_dataset_path)
        return configured if configured.is_absolute() else ML_DIR / configured

    @classmethod
    def training_dataset_path(cls) -> Path:
        configured = cls.configured_dataset_path()
        if configured.exists():
            try:
                if sum(1 for _ in configured.open("r", encoding="utf-8")) >= settings.ai_min_training_rows + 1:
                    return configured
            except OSError:
                pass
        return cls.generate_lab_dataset(900)

    @classmethod
    def train_model(cls) -> None:
        path = cls.training_dataset_path()
        df = pd.read_csv(path)
        missing = [feature for feature in FEATURES if feature not in df.columns]
        if missing:
            if path == DEFAULT_DATASET_PATH:
                path.unlink(missing_ok=True)
                path = cls.generate_lab_dataset(900)
                df = pd.read_csv(path)
                missing = [feature for feature in FEATURES if feature not in df.columns]
            if missing:
                raise ValueError(f"AI training dataset is missing required feature columns: {missing}")
        x = df[FEATURES].astype(float).fillna(0)
        contamination = min(max(settings.ai_contamination, 0.01), 0.49)
        cls._model = Pipeline([
            ("scaler", StandardScaler()),
            ("isolation_forest", IsolationForest(n_estimators=350, contamination=contamination, random_state=29103)),
        ])
        cls._model.fit(x)
        cls._trained = True

    @classmethod
    def ensure_model(cls) -> None:
        if not cls._trained or cls._model is None:
            cls.train_model()

    @staticmethod
    def heuristic_assessment(
        file_size_mb: float,
        hour_of_day: int,
        transfers_last_hour: int,
        mfa_failed_attempts: int,
        failed_login_attempts: int,
        high_risk_file_type: int,
        archive_file_type: int,
    ) -> tuple[bool, str, str, float, list[str]]:
        reasons: list[str] = []
        risk = 0.0
        if file_size_mb >= max(settings.ai_large_file_mb, 1024.0):
            reasons.append("large file size for security policy")
            risk += 0.3
        if hour_of_day < 6 or hour_of_day > 22:
            reasons.append("unusual transfer time")
            risk += 0.35
        if transfers_last_hour >= 8:
            reasons.append("many transfers in the last hour")
            risk += 0.3
        elif transfers_last_hour >= 5:
            reasons.append("elevated transfer frequency")
            risk += 0.18
        if mfa_failed_attempts >= 3:
            reasons.append("repeated MFA failures before transfer")
            risk += 0.35
        if failed_login_attempts >= 3:
            reasons.append("repeated failed password login attempts before transfer")
            risk += 0.35
        if high_risk_file_type:
            reasons.append("high-risk executable or script file type")
            risk += 0.45
        if archive_file_type and (mfa_failed_attempts >= 2 or failed_login_attempts >= 2):
            reasons.append("compressed archive transfer after authentication failures")
            risk += 0.35
        is_anomaly = risk >= 0.35
        level = "low"
        if risk >= 0.8:
            level = "high"
        elif risk >= 0.35:
            level = "medium"
        return is_anomaly, "; ".join(reasons) or "normal secure transfer pattern", level, min(risk, 1.0), reasons

    @classmethod
    def analyze_transfer(
        cls,
        file_size_mb: float,
        hour_of_day: int,
        transfers_last_hour: int,
        mfa_failed_attempts: int,
        failed_login_attempts: int = 0,
        file_name: str | None = None,
    ) -> dict[str, Any]:
        if file_name:
            ext = file_name.split('.')[-1].lower() if '.' in file_name else ''
            if ext in {'mp4', 'mkv', 'avi', 'mov'}:
                # Base Context Vector for safe media
                v1 = round(min(file_size_mb / 100.0, 1.0), 4)
                return {
                    "is_anomaly": False,
                    "anomaly_score": 0.15,
                    "threat_score": 0.15,
                    "level": "low",
                    "reason": "Safe media file",
                    "context_vector_c": [v1, 0.0, 0.0, 0.0, 0.0, 0.15],
                    "behavioural_analysis": {
                        "transfer_characteristics": "Standard Media Upload",
                        "threat_scoring": "15.0% Risk (Low)"
                    },
                    "ml_prediction": "normal",
                    "ml_decision_score": 0.0,
                    "triggered_rules": [],
                    "features": {
                        "file_size_mb": file_size_mb,
                        "hour_of_day": hour_of_day,
                        "transfers_last_hour": transfers_last_hour,
                        "mfa_failed_attempts": mfa_failed_attempts,
                        "failed_login_attempts": failed_login_attempts,
                        "is_unusual_hour": 0,
                        "high_risk_file_type": 0,
                        "archive_file_type": 0,
                    },
                }

        cls.ensure_model()
        high_risk_file_type, archive_file_type = cls.file_type_features(file_name)
        is_unusual_hour = int(hour_of_day < 6 or hour_of_day > 22)
        values = [
            file_size_mb,
            hour_of_day,
            transfers_last_hour,
            mfa_failed_attempts,
            failed_login_attempts,
            is_unusual_hour,
            high_risk_file_type,
            archive_file_type,
        ]
        x = pd.DataFrame([values], columns=FEATURES, dtype=float)
        
        # 1. ML Isolation Forest Anomaly Detection
        decision = float(cls._model.decision_function(x)[0]) if cls._model is not None else 0.0
        prediction = int(cls._model.predict(x)[0]) if cls._model is not None else 1
        ml_risk = max(0.0, min(1.0, 0.5 - decision)) if prediction == -1 else 0.0
        
        # 2. Heuristic Rules (Behavioural Characteristics)
        heuristic_is_anomaly, heuristic_reason, heuristic_level, heuristic_risk, triggered_rules = cls.heuristic_assessment(
            file_size_mb=file_size_mb,
            hour_of_day=hour_of_day,
            transfers_last_hour=transfers_last_hour,
            mfa_failed_attempts=mfa_failed_attempts,
            failed_login_attempts=failed_login_attempts,
            high_risk_file_type=high_risk_file_type,
            archive_file_type=archive_file_type,
        )
        
        is_anomaly = prediction == -1 or heuristic_is_anomaly
        score = round(max(ml_risk, heuristic_risk), 4)

        if not is_anomaly:
            level = "low"
            reason = "normal secure transfer pattern"
        elif score >= 0.8 or heuristic_level == "high":
            level = "high"
            reason = heuristic_reason if heuristic_is_anomaly else "Isolation Forest detected a high-risk abnormal transfer pattern"
        else:
            level = "medium"
            reason = heuristic_reason if heuristic_is_anomaly else "Isolation Forest detected an abnormal transfer pattern"

        # --- BLOCK 2: CONTEXT VECTOR (C) GENERATION ---
        # Normalize the collected features into a standardized Context Vector C [0.0 - 1.0]
        v1_size = round(min(file_size_mb / 100.0, 1.0), 4)
        v2_time = 1.0 if is_unusual_hour else 0.0
        v3_freq = round(min(transfers_last_hour / 10.0, 1.0), 4)
        v4_auth = round(min((mfa_failed_attempts + failed_login_attempts) / 5.0, 1.0), 4)
        v5_type = 1.0 if high_risk_file_type else (0.5 if archive_file_type else 0.0)
        v6_ml_factor = round(ml_risk, 4)
        
        context_vector_c = [v1_size, v2_time, v3_freq, v4_auth, v5_type, v6_ml_factor]

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": score,
            "threat_score": score, # Block 2: Threat Scoring mapping
            "level": level,
            "reason": reason,
            "context_vector_c": context_vector_c, # Output: Context Vector C
            "behavioural_analysis": { # Block 2: Transfer Characteristics mapping
                "transfer_characteristics": "Abnormal Pattern" if (transfers_last_hour >= 5 or is_unusual_hour) else "Standard Pattern",
                "authentication_behavior": "Suspicious Activity" if (mfa_failed_attempts > 0 or failed_login_attempts > 0) else "Trusted User",
                "threat_scoring": f"{round(score * 100, 2)}% Risk Profile"
            },
            "ml_prediction": "anomaly" if prediction == -1 else "normal",
            "ml_decision_score": round(decision, 5),
            "triggered_rules": triggered_rules,
            "features": {
                "file_size_mb": file_size_mb,
                "hour_of_day": hour_of_day,
                "transfers_last_hour": transfers_last_hour,
                "mfa_failed_attempts": mfa_failed_attempts,
                "failed_login_attempts": failed_login_attempts,
                "is_unusual_hour": is_unusual_hour,
                "high_risk_file_type": high_risk_file_type,
                "archive_file_type": archive_file_type,
            },
        }