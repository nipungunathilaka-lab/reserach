import time
import logging
from dataclasses import dataclass
from typing import Any, Dict
from app.services.ai_service import AIService
from app.core.config import settings
from app.database.db import SessionLocal
from app.services.blockchain_service import BlockchainService

logger = logging.getLogger(__name__)

class TransferBlockedError(Exception):
    def __init__(self, message: str, anomaly_score: float, risk_level: str):
        self.message = message
        self.anomaly_score = anomaly_score
        self.risk_level = risk_level
        super().__init__(self.message)

@dataclass
class TransferTelemetry:
    transfer_id: str
    sender_id: str
    receiver_id: str
    file_name: str
    file_size: int
    started_at: float
    bytes_processed: int = 0
    chunks_processed: int = 0
    last_evaluation_at: float = 0.0
    last_evaluation_chunks: int = 0
    current_risk_level: str = "NORMAL"
    current_ai_score: float = 0.0
    maximum_ai_score: float = 0.0
    samples_count: int = 0
    status: str = "IN_PROGRESS"
    
    # Context features from start
    transfers_last_hour: int = 0
    mfa_failed_attempts: int = 0
    failed_login_attempts: int = 0
    hour_of_day: int = 0

class ContinuousTransferMonitor:
    def __init__(
        self, 
        transfer_id: str, 
        sender_id: str, 
        receiver_id: str, 
        file_name: str, 
        file_size: int,
        transfers_last_hour: int,
        mfa_failed_attempts: int,
        failed_login_attempts: int,
        hour_of_day: int
    ):
        self.telemetry = TransferTelemetry(
            transfer_id=transfer_id,
            sender_id=str(sender_id),
            receiver_id=str(receiver_id),
            file_name=file_name,
            file_size=file_size,
            started_at=time.time(),
            transfers_last_hour=transfers_last_hour,
            mfa_failed_attempts=mfa_failed_attempts,
            failed_login_attempts=failed_login_attempts,
            hour_of_day=hour_of_day
        )
        self.last_logged_time = time.time()

    def update_telemetry(self, chunk_size: int) -> None:
        self.telemetry.bytes_processed += chunk_size
        self.telemetry.chunks_processed += 1

    def should_reanalyse(self) -> bool:
        if not settings.ai_continuous_monitoring_enabled:
            return False

        now = time.time()
        time_since_last = now - self.telemetry.last_evaluation_at
        chunks_since_last = self.telemetry.chunks_processed - self.telemetry.last_evaluation_chunks

        # Check soft limit to reduce frequency if approaching budget exhaustion
        from app.security.privacy.differential_privacy import PrivacyBudgetAccountant
        from app.security.privacy.config import dp_settings
        
        # Enforce max analyses per transfer
        if self.telemetry.samples_count >= dp_settings.dp_max_analyses_per_transfer:
            return False
            
        status = PrivacyBudgetAccountant.get_budget_status(self.telemetry.sender_id)
        
        is_soft_limit = False
        if status.get("status") == "available":
            consumed = status.get("consumed", 0)
            max_budget = dp_settings.dp_total_epsilon
            
            # Reserved Budget Hard Stop for Continuous Monitoring
            if (max_budget - consumed) <= dp_settings.dp_reserved_epsilon:
                return False
                
            # Soft Limit Check (Consumed Percentage)
            if (consumed / max_budget) * 100 >= dp_settings.dp_soft_limit_consumed_percent:
                is_soft_limit = True

        monitor_interval = settings.ai_monitor_interval_seconds
        monitor_chunks = settings.ai_monitor_every_n_chunks
        
        if is_soft_limit:
            # Privacy conservation mode: reduce discretionary reassessments
            monitor_interval *= 3
            monitor_chunks *= 3

        # Evaluate if interval passed or enough chunks processed
        if self.telemetry.last_evaluation_at == 0.0:
            return True # Always evaluate at least once
            
        return (time_since_last >= monitor_interval) or \
               (chunks_since_last >= monitor_chunks)

    def _calculate_rolling_heuristics(self, ai_result: Dict[str, Any]) -> None:
        """
        Enhance the initial AI result with deterministic rolling metrics.
        This preserves the underlying ML Isolation Forest dimensions while adding
        continuous behavioural monitoring (e.g. transfer rate anomalies).
        """
        elapsed_time = max(0.1, time.time() - self.telemetry.started_at)
        transfer_rate_mbps = (self.telemetry.bytes_processed / (1024 * 1024)) / elapsed_time
        
        reasons = []
        extra_risk = 0.0
        
        # Example of continuous heuristics:
        # 1. Very slow transfer of a large file might be suspicious (data exfiltration throttling)
        # 2. Or very fast transfer exceeding normal bounds
        if transfer_rate_mbps < 0.05 and self.telemetry.file_size > 50 * 1024 * 1024 and elapsed_time > 10:
            reasons.append("Unusually slow transfer rate for large file (potential throttled exfiltration)")
            extra_risk += 0.2
            
        if extra_risk > 0:
            new_score = min(1.0, ai_result["anomaly_score"] + extra_risk)
            ai_result["anomaly_score"] = new_score
            
            existing_reason = ai_result.get("reason", "normal")
            if "normal" in existing_reason.lower():
                ai_result["reason"] = "; ".join(reasons)
            else:
                ai_result["reason"] = existing_reason + "; " + "; ".join(reasons)
                
            if new_score >= 0.8:
                ai_result["level"] = "high"
                ai_result["is_anomaly"] = True
            elif new_score >= 0.4:
                if ai_result.get("level", "low") != "high":
                    ai_result["level"] = "medium"
                    ai_result["is_anomaly"] = True

    def reanalyze_transfer(self) -> Dict[str, Any]:
        """
        Call the AI service to recalculate the base score using original features
        (preserving Isolation Forest validity), then combine with rolling heuristics.
        """
        file_size_mb = self.telemetry.file_size / (1024 * 1024)
        
        import uuid
        analysis_id = f"{self.telemetry.transfer_id}:{self.telemetry.chunks_processed}:{uuid.uuid4().hex[:6]}"
        
        ai_result = AIService.analyze_transfer(
            file_size_mb=file_size_mb,
            hour_of_day=self.telemetry.hour_of_day,
            transfers_last_hour=self.telemetry.transfers_last_hour,
            mfa_failed_attempts=self.telemetry.mfa_failed_attempts,
            failed_login_attempts=self.telemetry.failed_login_attempts,
            file_name=self.telemetry.file_name,
            user_id=self.telemetry.sender_id,
            analysis_id=analysis_id
        )
        
        # Overlay rolling heuristics
        self._calculate_rolling_heuristics(ai_result)
        
        # Update telemetry state
        score = ai_result["anomaly_score"]
        self.telemetry.current_ai_score = score
        self.telemetry.maximum_ai_score = max(self.telemetry.maximum_ai_score, score)
        self.telemetry.last_evaluation_at = time.time()
        self.telemetry.last_evaluation_chunks = self.telemetry.chunks_processed
        self.telemetry.samples_count += 1
        
        # State Machine update
        if score >= settings.ai_block_threshold or ai_result.get("level") == "critical":
            self.telemetry.current_risk_level = "BLOCKED"
        elif score >= 0.6 or ai_result.get("level") == "high":
            self.telemetry.current_risk_level = "HIGH_RISK"
        elif score >= 0.35 or ai_result.get("level") == "medium":
            self.telemetry.current_risk_level = "ELEVATED"
        else:
            self.telemetry.current_risk_level = "NORMAL"

        self._audit_state_transition(ai_result)
        
        if self.telemetry.current_risk_level == "BLOCKED":
            self.telemetry.status = "BLOCKED"
            raise TransferBlockedError(
                message=f"Continuous monitoring triggered block. Reason: {ai_result.get('reason')}",
                anomaly_score=score,
                risk_level=self.telemetry.current_risk_level
            )
            
        return ai_result
        
    def _audit_state_transition(self, ai_result: Dict[str, Any]) -> None:
        """Audit risk level changes."""
        # Only log significant state changes or first evaluation to avoid database spam
        if self.telemetry.samples_count == 1:
            self._log_to_blockchain("AI_MONITORING_STARTED", ai_result)
        elif self.telemetry.current_risk_level == "BLOCKED":
            self._log_to_blockchain("AI_TRANSFER_BLOCKED", ai_result)
        elif self.telemetry.current_risk_level == "HIGH_RISK" and getattr(self, '_last_audited_risk', '') != "HIGH_RISK":
            self._log_to_blockchain("AI_RISK_ELEVATED", ai_result)
            self._last_audited_risk = "HIGH_RISK"
            
    def _log_to_blockchain(self, event_type: str, ai_result: Dict[str, Any]) -> None:
        try:
            with SessionLocal() as db:
                BlockchainService.append_block(
                    db=db,
                    event_type=event_type,
                    details={
                        "transfer_id": self.telemetry.transfer_id,
                        "sender_id": self.telemetry.sender_id,
                        "receiver_id": self.telemetry.receiver_id,
                        "risk_level": self.telemetry.current_risk_level,
                        "score": self.telemetry.current_ai_score,
                        "reason": ai_result.get("reason", ""),
                        "bytes_processed": self.telemetry.bytes_processed,
                        "chunks_processed": self.telemetry.chunks_processed,
                        "samples": self.telemetry.samples_count
                    }
                )
        except Exception as e:
            logger.error(f"Failed to log {event_type} to blockchain: {e}")

    def complete_monitoring(self) -> None:
        if self.telemetry.status != "BLOCKED":
            self.telemetry.status = "COMPLETED"
            self._log_to_blockchain("AI_MONITORING_COMPLETED", {"reason": "Transfer finished"})
