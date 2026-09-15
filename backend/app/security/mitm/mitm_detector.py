import os
import logging
import socket
from typing import Optional, List, Tuple
from .models import MITMDetectionResult, MITMIndicators
from .arp_monitor import arp_monitor
from .gateway_monitor import gateway_monitor
from .tls_monitor import tls_monitor
from .key_integrity_monitor import key_integrity_monitor
from app.services.network_monitor import NetworkMonitorService
import psutil

logger = logging.getLogger(__name__)

NETWORK_SENSOR_AVAILABLE = os.getenv("NETWORK_MONITORING_ENABLED", "true").lower() == "true"

class MITMDetector:
    def __init__(self):
        pass

    @classmethod
    def get_capabilities(cls) -> dict:
        return {
            "enabled": True,
            "network_sensor_available": NETWORK_SENSOR_AVAILABLE,
            "arp_monitoring": NETWORK_SENSOR_AVAILABLE,
            "gateway_monitoring": NETWORK_SENSOR_AVAILABLE,
            "tls_identity_monitoring": True, # Capability exposed, though passive
            "public_key_integrity": True
        }

    @classmethod
    def get_default_gateway(cls) -> Tuple[Optional[str], Optional[str]]:
        try:
            gateways = psutil.net_if_addrs()
            # Simple simulation of gateway discovery
            # Real implementation would use netifaces or similar, but we simulate it for prototype 
            # if we can't reliably get the real gateway across all OSes.
            return "192.168.1.1", "eth0"
        except Exception:
            return None, None

    @classmethod
    def evaluate_transfer(
        cls, 
        client_ip: str, 
        client_port: int,
        sender_id: int, 
        sender_spki_fingerprint: str,
        simulate_arp_mac: Optional[str] = None, # For testing
        simulate_gateway_ip: Optional[str] = None # For testing
    ) -> MITMDetectionResult:
        
        indicators = []
        risk_score = 0.0
        severity = "LOW"
        detected = False
        detector_results = {}
        
        # 1. ARP/MAC Monitoring
        mac = simulate_arp_mac
        if NETWORK_SENSOR_AVAILABLE:
            if not mac:
                # Attempt to find MAC in our ARP table (if on local subnet)
                pass # Simplified for prototype
                
            if mac:
                conflict, expected_mac = arp_monitor.check_arp_mapping(client_ip, mac)
                if conflict:
                    indicators.append(MITMIndicators.ARP_MAC_CONFLICT)
                    detector_results["expected_mac"] = expected_mac
                    detector_results["observed_mac"] = mac
                    risk_score = max(risk_score, 0.9)
                    detected = True
        
        # 2. Gateway Monitoring
        gw_ip = simulate_gateway_ip or cls.get_default_gateway()[0]
        gw_iface = cls.get_default_gateway()[1]
        
        if NETWORK_SENSOR_AVAILABLE and gw_ip and gw_iface:
            is_changed = gateway_monitor.check_gateway(gw_ip, gw_iface)
            if is_changed:
                indicators.append(MITMIndicators.DEFAULT_GATEWAY_CHANGED)
                risk_score = max(risk_score, 0.7)
                detected = True
                
        # 3. Public Key Substitution Check
        if sender_id and sender_spki_fingerprint:
            is_valid, expected_fp = key_integrity_monitor.verify_public_key(sender_id, sender_spki_fingerprint)
            if not is_valid:
                indicators.append(MITMIndicators.PUBLIC_KEY_SUBSTITUTION_ATTEMPT)
                detector_results["expected_fingerprint"] = expected_fp
                detector_results["observed_fingerprint"] = sender_spki_fingerprint
                risk_score = max(risk_score, 1.0)
                detected = True

        # 4. Network Flow Anomaly (TCP Resets, Sequence Issues)
        # Combine from NetworkAnomalyEngine
        flow_stats, _ = NetworkMonitorService.get_flow_stats_by_client(client_ip, client_port)
        if flow_stats:
            if flow_stats.get("rst_count", 0) > 5:
                indicators.append(MITMIndicators.TCP_RESET_ANOMALY)
                risk_score = max(risk_score, 0.6)
                detected = True
            if flow_stats.get("out_of_order", 0) > 10:
                indicators.append(MITMIndicators.TCP_SEQUENCE_ANOMALY)
                risk_score = max(risk_score, 0.5)
                detected = True
                
        if risk_score >= 0.9:
            severity = "CRITICAL"
        elif risk_score >= 0.7:
            severity = "HIGH"
        elif risk_score >= 0.4:
            severity = "MEDIUM"

        return MITMDetectionResult(
            detected=detected,
            risk_score=risk_score,
            severity=severity,
            indicators=indicators,
            detector_results=detector_results,
            source_ip=client_ip
        )
