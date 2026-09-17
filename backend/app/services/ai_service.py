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
from app.security.privacy.differential_privacy import DifferentialPrivacyService, PrivacyBudgetExhausted, DPAccountantUnavailable

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
    
    # Dataset Provenance Metadata (GAP 25)
    model_provenance: dict[str, Any] = {
        "dataset_name": "lab_secure_transfer_dataset.csv",
        "source_type": "synthetic_laboratory",
        "record_count": 900,
        "normal_records": 702,
        "anomalous_records": 198,
        "collection_environment": "research laboratory",
        "contains_enterprise_production_data": False,
        "schema_version": "1.0",
        "feature_names": FEATURES,
    }

    @staticmethod
    def file_extension(file_name: str | None) -> str:
        if not file_name or "." not in file_name:
            return ""
        return file_name.rsplit(".", 1)[-1].lower()

    @classmethod
    def file_type_features(cls, file_name: str | None) -> tuple[int, int]:
        ext = cls.file_extension(file_name)
        return int(ext in HIGH_RISK_EXTENSIONS), int(ext in ARCHIVE_EXTENSIONS)

    def configured_dataset_path() -> Path:
        configured = Path(settings.ai_dataset_path)
        return configured if configured.is_absolute() else ML_DIR / configured

    @classmethod
    def training_dataset_path(cls) -> Path:
        configured = cls.configured_dataset_path()
        if not configured.exists() or sum(1 for _ in configured.open("r", encoding="utf-8")) <= settings.ai_min_training_rows:
            raise FileNotFoundError(f"Training dataset not found or insufficient rows at {configured}. Run scripts/generate_dataset.py first.")
        return configured

    @classmethod
    def train_model(cls) -> None:
        path = cls.training_dataset_path()
        df = pd.read_csv(path)
        missing = [feature for feature in FEATURES if feature not in df.columns]
        
        # Update provenance accurately from the actual dataframe
        cls.model_provenance["record_count"] = len(df)
        cls.model_provenance["dataset_name"] = path.name
        if "is_anomaly" in df.columns:
            cls.model_provenance["anomalous_records"] = int(df["is_anomaly"].sum())
            cls.model_provenance["normal_records"] = len(df) - cls.model_provenance["anomalous_records"]
        cls.model_provenance["training_timestamp"] = datetime.utcnow().isoformat()
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
    def dp_heuristic_assessment(
        file_size_mb: float,
        hour_of_day: int,
        transfers_last_hour: int,
        mfa_failed_attempts: int,
        failed_login_attempts: int,
        high_risk_file_type: int,
        archive_file_type: int,
    ) -> tuple[bool, str, str, float, list[str]]:
        """
        Behavioural heuristic assessment that consumes DP-protected telemetry.
        """
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

    DETERMINISTIC_FALLBACK_ALLOWED_FIELDS = {
        'file_size_violates_policy',
        'authentication_policy_violation',
        'account_locked',
        'high_risk_file_type',
        'archive_file_type'
    }

    @staticmethod
    def deterministic_security_assessment(
        fallback_features: dict[str, Any]
    ) -> tuple[bool, str, str, float, list[str]]:
        """
        Deterministic security control fallback that ONLY uses explicit non-sensitive inputs.
        Does NOT use behavioural frequency or time of day.
        """
        # Strictly enforce allowlist
        for key in fallback_features.keys():
            if key not in AIService.DETERMINISTIC_FALLBACK_ALLOWED_FIELDS:
                raise ValueError(f"Feature '{key}' is not in the deterministic fallback allowlist.")

        reasons: list[str] = []
        risk = 0.0
        
        if fallback_features.get('file_size_violates_policy'):
            reasons.append("large file size for security policy")
            risk += 0.3
        if fallback_features.get('account_locked'):
            reasons.append("account locked before transfer")
            risk += 0.5
        elif fallback_features.get('authentication_policy_violation'):
            reasons.append("repeated authentication failures before transfer")
            risk += 0.4
            
        high_risk_file_type = fallback_features.get('high_risk_file_type', 0)
        archive_file_type = fallback_features.get('archive_file_type', 0)
        
        if high_risk_file_type:
            reasons.append("high-risk executable or script file type")
            risk += 0.45
        if archive_file_type and fallback_features.get('authentication_policy_violation'):
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
        user_id: str = "system",
        analysis_id: str = None,
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

        raw_features = {
            "file_size_mb": file_size_mb,
            "hour_of_day": hour_of_day,
            "transfers_last_hour": transfers_last_hour,
            "mfa_failed_attempts": mfa_failed_attempts,
            "failed_login_attempts": failed_login_attempts,
            "is_unusual_hour": is_unusual_hour,
            "high_risk_file_type": high_risk_file_type,
            "archive_file_type": archive_file_type,
        }

        try:
            # Request privatization with analysis class
            analysis_class = "INITIAL"
            if analysis_id and ":" in analysis_id: # Quick heuristics to detect periodic monitor requests
                analysis_class = "PERIODIC"
                
            dp_result = DifferentialPrivacyService.privatize_features(
                user_id=user_id,
                transfer_id=file_name or "unknown",
                raw_features=raw_features,
                analysis_id=analysis_id,
                analysis_class=analysis_class
            )
            privatized = dp_result.features
            ml_available = True
            dp_err_msg = ""
        except (PrivacyBudgetExhausted, DPAccountantUnavailable) as e:
            from app.security.privacy.config import dp_settings
            if isinstance(e, PrivacyBudgetExhausted):
                policy = dp_settings.dp_exhaustion_policy
            else:
                policy = dp_settings.dp_accountant_fail_policy
                
            if policy == "fail_closed":
                from app.services.continuous_monitor import TransferBlockedError
                raise TransferBlockedError(f"AI Behavioural Monitor blocked: {str(e)}", anomaly_score=1.0, risk_level="BLOCKED")
            else:
                # fallback_heuristics
                privatized = raw_features
                ml_available = False
                dp_err_msg = "privacy budget exhausted" if isinstance(e, PrivacyBudgetExhausted) else "privacy accountant unavailable"
                dp_result = None

        if ml_available:
            dp_values = [
                privatized.get("file_size_mb", file_size_mb),
                privatized.get("hour_of_day", hour_of_day),
                privatized.get("transfers_last_hour", transfers_last_hour),
                privatized.get("mfa_failed_attempts", mfa_failed_attempts),
                privatized.get("failed_login_attempts", failed_login_attempts),
                privatized.get("is_unusual_hour", is_unusual_hour),
                privatized.get("high_risk_file_type", high_risk_file_type),
                privatized.get("archive_file_type", archive_file_type),
            ]
    
            x = pd.DataFrame([dp_values], columns=FEATURES, dtype=float)
            
            # 1. ML Isolation Forest Anomaly Detection
            decision = float(cls._model.decision_function(x)[0]) if cls._model is not None else 0.0
            prediction = int(cls._model.predict(x)[0]) if cls._model is not None else 1
            ml_risk = max(0.0, min(1.0, 0.5 - decision)) if prediction == -1 else 0.0
            ml_prediction = "anomaly" if prediction == -1 else "normal"
            ml_decision_score = round(decision, 5)
            
            # 2. DP-Heuristic Rules (Behavioural Characteristics)
            heuristic_is_anomaly, heuristic_reason, heuristic_level, heuristic_risk, triggered_rules = cls.dp_heuristic_assessment(
                file_size_mb=dp_values[0],
                hour_of_day=dp_values[1],
                transfers_last_hour=dp_values[2],
                mfa_failed_attempts=dp_values[3],
                failed_login_attempts=dp_values[4],
                high_risk_file_type=dp_values[6],
                archive_file_type=dp_values[7],
            )
        else:
            decision = None
            prediction = None
            ml_risk = None
            ml_prediction = None
            ml_decision_score = None
            
            # Strict Deterministic Fallback (No privacy-sensitive inputs)
            fallback_features = {
                'file_size_violates_policy': file_size_mb >= max(settings.ai_large_file_mb, 1024.0),
                'authentication_policy_violation': mfa_failed_attempts >= 3 or failed_login_attempts >= 3,
                'account_locked': False, # Explicit derived state
                'high_risk_file_type': high_risk_file_type,
                'archive_file_type': archive_file_type
            }

            heuristic_is_anomaly, heuristic_reason, heuristic_level, heuristic_risk, triggered_rules = cls.deterministic_security_assessment(
                fallback_features=fallback_features
            )
        
        is_anomaly = (prediction == -1 or heuristic_is_anomaly) if ml_available else heuristic_is_anomaly
        score = round(max(ml_risk, heuristic_risk), 4) if ml_available else heuristic_risk

        if not is_anomaly:
            level = "low"
            reason = "normal secure transfer pattern"
        elif score >= 0.8 or heuristic_level == "high":
            level = "high"
            if not ml_available:
                reason = heuristic_reason if heuristic_is_anomaly else "High risk transfer pattern"
            else:
                reason = heuristic_reason if heuristic_is_anomaly else "Isolation Forest detected a high-risk abnormal transfer pattern"
        else:
            level = "medium"
            if not ml_available:
                reason = heuristic_reason if heuristic_is_anomaly else "Medium risk transfer pattern"
            else:
                reason = heuristic_reason if heuristic_is_anomaly else "Isolation Forest detected an abnormal transfer pattern"
                
        if not ml_available:
            reason = f"AI behavioural assessment unavailable: {dp_err_msg}. Independent security controls remain active. " + reason

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
            "behavioural_ai": {
                "performed": ml_available,
                "reason": dp_err_msg if not ml_available else "COMPLETED",
                "score": ml_risk,
                "prediction": ml_prediction,
                "decision_score": ml_decision_score
            },
            "deterministic_controls": {
                "performed": True,
                "decision": heuristic_is_anomaly,
                "risk": heuristic_risk,
                "level": heuristic_level
            },
            "overall_policy": {
                "decision": is_anomaly,
            },
            "ml_prediction": ml_prediction,
            "ml_decision_score": ml_decision_score,
            "triggered_rules": triggered_rules,
            "features": privatized,
            "dp_metadata": {
                "dp_enabled": dp_result.applied if dp_result else False,
                "mechanism": dp_result.mechanism if dp_result else "unavailable",
                "epsilon_used": dp_result.epsilon_spent if dp_result else 0.0,
                "remaining_budget": dp_result.remaining_budget if dp_result else 0.0,
                "protected_features": dp_result.protected_features if dp_result else [],
                "status": "active" if ml_available else dp_err_msg
            }
        }