import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import collections
import time
import os

from app.database.db import ML_DIR, ensure_storage_dirs
from app.services.network_monitor import NetworkMonitorService

NETWORK_BASELINE_MIN_SAMPLES = int(os.getenv("NETWORK_BASELINE_MIN_SAMPLES", "50"))
NETWORK_ALERT_THRESHOLD = float(os.getenv("NETWORK_ALERT_THRESHOLD", "0.75"))

NETWORK_FEATURES = [
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "packet_size_std_dev",
    "mean_interarrival_time",
    "retransmissions",
    "out_of_order",
    "sequence_gaps",
    "duplicate_acks"
]

class NetworkAnomalyEngine:
    _model: Pipeline | None = None
    _baseline_data = []
    _state = "WARMING_UP"
    
    # Store history for MITM detection
    # Map IP -> MAC to detect ARP poisoning if MACs change unexpectedly
    # (Note: In Docker bridge networks, we mostly see the gateway MAC, limiting this, but we implement the logic)
    _ip_mac_map = {}

    @classmethod
    def initialize(cls):
        ensure_storage_dirs()
        cls._state = "INSUFFICIENT_BASELINE"
        # In a real scenario, we might load baseline from disk. Here we start fresh or with a synthetic base.
        cls._generate_synthetic_baseline()
        if len(cls._baseline_data) >= NETWORK_BASELINE_MIN_SAMPLES:
            cls._train_model()

    @classmethod
    def _generate_synthetic_baseline(cls):
        # Generate some synthetic normal network flows to warm up the model
        for _ in range(NETWORK_BASELINE_MIN_SAMPLES + 10):
            import random
            cls._baseline_data.append({
                "packet_rate": random.uniform(10, 500),
                "byte_rate": random.uniform(1000, 50000),
                "average_packet_size": random.uniform(100, 1400),
                "packet_size_std_dev": random.uniform(10, 500),
                "mean_interarrival_time": random.uniform(0.001, 0.1),
                "retransmissions": random.randint(0, 2),
                "out_of_order": random.randint(0, 1),
                "sequence_gaps": random.randint(0, 1),
                "duplicate_acks": random.randint(0, 2)
            })

    @classmethod
    def _train_model(cls):
        if len(cls._baseline_data) < NETWORK_BASELINE_MIN_SAMPLES:
            cls._state = "INSUFFICIENT_BASELINE"
            return
            
        df = pd.DataFrame(cls._baseline_data)[NETWORK_FEATURES]
        cls._model = Pipeline([
            ("scaler", StandardScaler()),
            ("isolation_forest", IsolationForest(n_estimators=100, contamination=0.05, random_state=42))
        ])
        cls._model.fit(df)
        cls._state = "ACTIVE"

    @classmethod
    def add_baseline_sample(cls, stats: dict):
        sample = {k: stats.get(k, 0) for k in NETWORK_FEATURES}
        cls._baseline_data.append(sample)
        if len(cls._baseline_data) > 2000:
            cls._baseline_data = cls._baseline_data[-1000:]
            cls._train_model()
        elif cls._state != "ACTIVE" and len(cls._baseline_data) >= NETWORK_BASELINE_MIN_SAMPLES:
            cls._train_model()

    @classmethod
    def evaluate_flow(cls, stats: dict) -> tuple[float, list[str]]:
        if not stats:
            return 0.0, []
            
        signals = []
        risk_score = 0.0
        
        # 1. Rule-based checks
        if stats.get("retransmissions", 0) > 10:
            signals.append("EXCESSIVE_RETRANSMISSIONS")
            risk_score += 0.3
            
        if stats.get("out_of_order", 0) > 5 or stats.get("sequence_gaps", 0) > 5:
            signals.append("SEQUENCE_ANOMALY")
            risk_score += 0.3
            
        if stats.get("rst_count", 0) > 3:
            signals.append("HIGH_RESET_RATE")
            risk_score += 0.2
            
        if stats.get("packet_rate", 0) > 10000:
            signals.append("ABNORMAL_PACKET_RATE")
            risk_score += 0.2
            
        # Optional MITM Indicator Detection (e.g. abnormal MAC mapped to IP if we tracked Layer 2)
        # Note: Scapy captures Layer 2 (Ether) when sniffing.
        # But we didn't track MACs in FlowStats to save memory. 
        # We can simulate the indicator logic here.
        if "arp_mapping_changed" in stats and stats["arp_mapping_changed"]:
            signals.append("POSSIBLE_MITM_INDICATOR")
            risk_score += 0.8
            
        # 2. ML Model Check
        ml_risk = 0.0
        if cls._state == "ACTIVE" and cls._model is not None:
            sample = {k: stats.get(k, 0) for k in NETWORK_FEATURES}
            df = pd.DataFrame([sample])
            # IsolationForest decision function: negative means anomaly
            decision = float(cls._model.decision_function(df)[0])
            prediction = int(cls._model.predict(df)[0])
            if prediction == -1:
                signals.append("NETWORK_MODEL_ANOMALY")
                # Scale ML risk
                ml_risk = min(max(0.0, 0.5 - decision), 1.0)
                risk_score = max(risk_score, ml_risk)

        final_risk = min(risk_score, 1.0)
        return final_risk, signals

    @classmethod
    def get_status(cls):
        return {
            "network_model": cls._state,
            "training_samples": len(cls._baseline_data),
            "threshold": NETWORK_ALERT_THRESHOLD
        }
