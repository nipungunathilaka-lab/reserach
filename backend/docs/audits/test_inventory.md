# Backend Test Inventory

| Test File | Purpose | Tier | OS Compatible | Requires Redis? | Requires liboqs? | Requires Besu? | Requires ClamAV? | Requires Docker? | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `smoke_test.py` | E2E test verifying full system flow. | Integration | No | Yes | Yes | Yes | Yes | Yes | FIXED |
| `test_audit_chain.py` | Validates hash chain anchoring logic. | Integration | No | No | No | Yes | No | Yes | FIXED |
| `test_audit_chain_rewrite.py` | Verifies protection against ledger rewrite. | Integration | No | No | No | Yes | No | Yes | FIXED |
| `test_audit_immutability.py` | Verifies strict ledger append-only constraints. | Integration | No | No | No | Yes | No | Yes | FIXED |
| `test_blockchain_audit.py` | E2E smart contract validation. | Integration | No | No | No | Yes | No | Yes | FIXED |
| `test_continuous_monitor.py` | Streaming anomaly detection. | Integration | No | No | Yes (via UPCE) | No | No | Yes | FIXED |
| `test_crypto_roundtrip.py` | Validate file encryption/decryption mathematically. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_digital_signatures.py` | Ed25519 payload signature checks. | Unit | Yes | No | No | No | No | No | FAILING |
| `test_forward_secrecy.py` | PFS key exchange lifecycle. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_full_file_scan.py` | E2E Malware scanning logic. | Integration | No | No | No | No | Yes | Yes | FIXED |
| `test_kms.py` | Boto3 AWS KMS Envelope wrapper tests. | Unit | Yes | No | No | No | No | No | SKIPPED |
| `test_malware_fail_closed.py` | Verify scanner failures block traffic. | Integration | No | No | No | No | Yes | Yes | FIXED |
| `test_mlkem.py` | Base tests for Kyber PQC algorithms. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_network_anomaly_monitor.py` | IP/MAC/Route change anomaly metrics. | Unit | Yes | No | No | No | No | No | OBSOLETE |
| `test_pfce.py` | UPCE Polymorphic fragment wrapper logic. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_pfce_stream.py` | Large-file streaming variant for UPCE. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_policy.py` | Dynamic threat-policy selection mechanism. | Unit | Yes | No | No | No | No | No | OBSOLETE |
| `test_pqc_required.py` | Tests fail-closed mechanism when PQC unavailable. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_quarantine_lifecycle.py` | Isolated malicious payload handling. | Integration | No | No | No | No | Yes | Yes | FIXED |
| `test_redis_dp_accountant.py` | Atomic budget consumption in Redis. | Integration | No | Yes | No | No | No | Yes | FIXED |
| `test_residual_hardening.py` | FastAPI internal JWT authentication checks. | Integration | No | Yes | No | No | No | Yes | FIXED |
| `test_scapy_visibility.py` | Verify interface bounds and docker encryption leaks. | Integration | No | No | No | No | No | Yes | FIXED |
| `test_secure_memory.py` | PQC shared secret memory clearance checks. | Integration | No | No | Yes | No | No | Yes | FIXED |
| `test_tofu.py` | Trust On First Use key mapping logic. | Unit | Yes | No | No | No | No | No | FAILING |
| `tests/test_ai_fallback_allowlist.py` | Validates classification override behavior. | Unit | Yes | No | No | No | No | No | PASSING |
| `tests/test_differential_privacy.py` | DP feature clipping and mathematical bounds. | Unit | Yes | No | No | No | No | No | PASSING |
| `tests/test_dp_integration.py` | Real pipeline exhaustion handling. | Integration | No | Yes | No | No | No | Yes | FIXED |
| `tests/test_dp_reserve_concurrency.py` | Race condition tests for periodic analysis budgets. | Integration | No | Yes | No | No | No | Yes | FIXED |
| `tests/test_final_data_architecture.py` | Validates DB schemas and bounds. | Unit | Yes | No | No | No | No | No | PASSING |
| `tests/test_plaintext_boundaries.py` | Verifies isolation of plaintext contexts. | Unit | Yes | No | No | No | No | No | FAILING |

**Action Taken**: Broad ignores have been removed from `pytest.ini`. All tests are now dynamically skipped based on their marker constraints and real runtime capabilities detected in `conftest.py`.
