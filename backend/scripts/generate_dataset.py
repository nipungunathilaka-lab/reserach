import csv
import math
import secrets
from datetime import datetime
import pandas as pd
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parents[2]
ML_DIR = BASE_DIR / "backend" / "app" / "ml"
DEFAULT_DATASET_PATH = ML_DIR / "lab_secure_transfer_dataset.csv"
PROVENANCE_PATH = ML_DIR / "lab_secure_transfer_dataset_provenance.json"

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

def generate_lab_dataset(rows: int = 900) -> None:
    print(f"Generating lab dataset with {rows} rows...")
    ML_DIR.mkdir(parents=True, exist_ok=True)
    
    rng = secrets.SystemRandom()
    # Ensure consistent count for reproducibility in this generation script
    # We will generate 702 normal, 198 anomalous (sum = 900)
    normal_count = int(rows * 0.78)
    anomaly_count = rows - normal_count
    records = []

    for _ in range(normal_count):
        hour = rng.randint(6, 21)
        size = round(rng.uniform(0.1, 50.0), 2)
        transfers_last_hour = rng.randint(0, 3)
        records.append({
            "file_size_mb": size,
            "hour_of_day": hour,
            "transfers_last_hour": transfers_last_hour,
            "mfa_failed_attempts": 0,
            "failed_login_attempts": rng.choice([0, 0, 0, 1]),
            "is_unusual_hour": 0,
            "high_risk_file_type": 0,
            "archive_file_type": rng.choice([0, 1]),
            "integrity_status": "verified",
            "unauthorized_attempt": 0,
            "encryption_time_ms": round(10 + size * rng.uniform(0.5, 1.5), 3),
            "decryption_time_ms": round(8 + size * rng.uniform(0.5, 1.3), 3),
            "ecdh_time_ms": round(rng.uniform(0.5, 3.0), 3),
            "rsa_key_wrap_time_ms": round(rng.uniform(1.2, 5.0), 3),
            "transfer_status": "completed",
            "is_anomaly": 0,
            "anomaly_reason": "",
            "anomaly_level": "none",
        })

    for _ in range(anomaly_count):
        hour = rng.choice([rng.randint(0, 5), rng.randint(22, 23)])
        size = round(rng.uniform(500.0, 999.0), 2)
        transfers_last_hour = rng.randint(5, 15)
        mfa_failed = rng.randint(1, 5)
        failed_logins = rng.randint(2, 10)
        high_risk = rng.choice([0, 1])
        archive = 1
        integrity = rng.choice(["verified", "failed"])
        unauthorized = rng.choice([0, 1])
        level = rng.choice(["medium", "high", "critical"])
        reason = "Off-hour massive transfer; repeated auth failures"
        
        records.append({
            "file_size_mb": size,
            "hour_of_day": hour,
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

    import hashlib
    import json
    
    with open(DEFAULT_DATASET_PATH, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
        
    provenance = {
        "dataset_generation_version": "1.0",
        "schema_version": "1.0",
        "generation_timestamp": datetime.utcnow().isoformat(),
        "sha256_hash": file_hash,
        "record_counts": {
            "total": rows,
            "normal": normal_count,
            "anomalous": anomaly_count
        },
        "source_type": "synthetic_laboratory"
    }
    
    with PROVENANCE_PATH.open("w") as f:
        json.dump(provenance, f, indent=2)

    print(f"Dataset generated at {DEFAULT_DATASET_PATH}")
    print(f"Provenance saved at {PROVENANCE_PATH}")

if __name__ == "__main__":
    generate_lab_dataset(900)
