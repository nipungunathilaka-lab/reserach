#!/bin/bash
set -e

export PYTHONPATH=/app
export DATABASE_URL="sqlite:////tmp/secure_file_transfer.db"

echo "=== Running DB Migrations ==="
python migrate_pqc.py

echo "=== Running Pytest ==="
python -m pytest test_pfce.py test_crypto_roundtrip.py test_mlkem.py

echo "=== Running UPCE/PFCE Verification ==="
python verify_upce.py

echo "=== Running Startup Check ==="
python startup_check_test.py

echo "=== Running PQC REQUIRED Test ==="
python test_pqc_required.py

echo "=== Running Verify UPCE ==="
python verify_upce.py
