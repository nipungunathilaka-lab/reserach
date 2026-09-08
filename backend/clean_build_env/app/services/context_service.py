from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class TransferContext:
    classification: str
    file_size_bytes: int
    file_extension: str
    threat_score: float
    malware_threat_score: float
    time_anomaly_score: float
    size_anomaly_score: float
    combined_risk_score: float
    cpu_usage_percent: float
    memory_usage_percent: float
    network_profile: str
    receiver_policy: str


class ContextAnalysisService:
    """Explainable baseline context analyser.

    Replace or extend this component with a trained and validated model.
    """

    HIGH_RISK_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".ps1", ".jar", ".js", ".vbs"
    }

    SENSITIVE_KEYWORDS = {
        "medical", "finance", "salary", "confidential",
        "private", "patient", "bank", "password",
    }
    
    LARGE_FILE_THRESHOLD_BYTES = 500 * 1024 * 1024  # 500 MB

    @classmethod
    def analyse(
        cls,
        *,
        file_name: str,
        file_size_bytes: int,
        requested_classification: str,
        cpu_usage_percent: float,
        memory_usage_percent: float,
        transfer_time: Optional[datetime] = None,
    ) -> TransferContext:
        if transfer_time is None:
            transfer_time = datetime.now()
            
        lower_name = file_name.lower()
        extension = "." + lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""

        # 1. Malware Threat Score
        malware_threat_score = 0.05
        if extension in cls.HIGH_RISK_EXTENSIONS:
            malware_threat_score = 0.95
        elif any(word in lower_name for word in cls.SENSITIVE_KEYWORDS):
            malware_threat_score = 0.65

        # 2. Time Anomaly Score (e.g., flag operations between 1:00 AM and 5:00 AM as high risk)
        time_anomaly_score = 0.05
        if 1 <= transfer_time.hour < 5:
            time_anomaly_score = 0.85
            
        # 3. Size Anomaly Score (e.g., unusually large compared to standard thresholds)
        size_anomaly_score = 0.05
        if file_size_bytes > cls.LARGE_FILE_THRESHOLD_BYTES:
            size_anomaly_score = 0.80

        # Combined Risk Score (Max value of anomalies represents highest risk vector)
        combined_risk_score = max(malware_threat_score, time_anomaly_score, size_anomaly_score)

        classification = requested_classification.strip() or "Normal"
        if combined_risk_score >= 0.60 and classification.lower() == "normal":
            classification = "Sensitive"

        return TransferContext(
            classification=classification,
            file_size_bytes=file_size_bytes,
            file_extension=extension,
            threat_score=combined_risk_score,  # Retained for backward compatibility
            malware_threat_score=malware_threat_score,
            time_anomaly_score=time_anomaly_score,
            size_anomaly_score=size_anomaly_score,
            combined_risk_score=combined_risk_score,
            cpu_usage_percent=cpu_usage_percent,
            memory_usage_percent=memory_usage_percent,
            network_profile="unknown",
            receiver_policy="standard",
        )
