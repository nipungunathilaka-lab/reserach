from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class MITMDetectionResult:
    detected: bool
    risk_score: float
    severity: str
    indicators: List[str] = field(default_factory=list)
    detector_results: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    interface: Optional[str] = None
    transfer_id: Optional[str] = None

class MITMIndicators:
    ARP_MAC_CONFLICT = "ARP_MAC_CONFLICT"
    ARP_GATEWAY_CHANGE = "ARP_GATEWAY_CHANGE"
    ARP_REPLY_ANOMALY = "ARP_REPLY_ANOMALY"
    TLS_CERTIFICATE_CHANGE = "TLS_CERTIFICATE_CHANGE"
    TLS_FINGERPRINT_MISMATCH = "TLS_FINGERPRINT_MISMATCH"
    TRUSTED_KEY_CHANGED = "TRUSTED_KEY_CHANGED"
    PUBLIC_KEY_SUBSTITUTION_ATTEMPT = "PUBLIC_KEY_SUBSTITUTION_ATTEMPT"
    DEFAULT_GATEWAY_CHANGED = "DEFAULT_GATEWAY_CHANGED"
    TCP_RESET_ANOMALY = "TCP_RESET_ANOMALY"
    TCP_SEQUENCE_ANOMALY = "TCP_SEQUENCE_ANOMALY"
    NETWORK_PATH_CHANGE = "NETWORK_PATH_CHANGE"
