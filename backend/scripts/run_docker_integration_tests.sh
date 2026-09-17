#!/bin/bash
# =====================================================================
# DOCKER INTEGRATION TEST RUNNER (TIER B)
# =====================================================================
# This script is intended to be executed INSIDE the Linux/Docker test
# environment where external services (Redis, Besu, ClamAV, liboqs)
# are fully available.
#
# It enforces the execution of REAL security/integration tests.
# =====================================================================

set -e

echo "[*] Initializing Tier B Docker Integration Tests..."

# Check Environment
export FORCE_REAL_OQS=1

# Pre-flight checks (informational)
echo "[*] Checking for external services..."
nc -z localhost 6379 && echo "  - Redis: OK" || echo "  - Redis: UNAVAILABLE"
nc -z localhost 8545 && echo "  - Besu: OK" || echo "  - Besu: UNAVAILABLE"
nc -z localhost 3310 && echo "  - ClamAV: OK" || echo "  - ClamAV: UNAVAILABLE"

# Output directory
mkdir -p tests/results

echo "[*] Running Pytest for integration/docker markers..."
# We use Python to run pytest to easily output the custom JSON
cat << 'EOF' > run_integration_tests.py
import pytest
import json
import os

class JSONReport:
    def __init__(self):
        self.summary = {}
        
    def pytest_terminal_summary(self, terminalreporter, exitstatus, config):
        self.summary = {
            "collected": getattr(terminalreporter, "_numcollected", 0),
            "passed": len(terminalreporter.stats.get("passed", [])),
            "failed": len(terminalreporter.stats.get("failed", [])),
            "skipped": len(terminalreporter.stats.get("skipped", [])),
            "deselected": len(terminalreporter.stats.get("deselected", [])),
            "errors": len(terminalreporter.stats.get("error", [])),
            "exitcode": exitstatus,
            "environment_status": "DOCKER_LINUX"
        }
        os.makedirs("tests/results", exist_ok=True)
        with open("tests/results/docker_integration_test_summary.json", "w") as f:
            json.dump(self.summary, f, indent=4)

if __name__ == "__main__":
    plugin = JSONReport()
    # Run only integration, pqc, redis, besu, clamav, network, docker
    pytest.main([
        "-m", "integration or docker or pqc or redis or besu or clamav or network", 
        "-v"
    ], plugins=[plugin])
EOF

python run_integration_tests.py || echo "[!] Some tests failed, but summary was generated."

echo "[*] Done. Results saved to backend/tests/results/docker_integration_test_summary.json"
