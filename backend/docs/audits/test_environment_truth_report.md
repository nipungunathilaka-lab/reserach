# Test Environment Truth Report

## 1. Global Mocks Analysis
### Previous State
- **`sys.modules["oqs"] = mock.MagicMock()`**: This global mock silently bypassed the `liboqs` cryptographic bindings in ALL tests (including security and integration tests). This created false positives where tests appeared to pass without actually validating the post-quantum algorithms.
- **`get_sync_redis` mocked globally**: DP tests and authentication tests implicitly fell back to an in-memory dictionary or mock without validating atomic locking or Redis execution, making it impossible to detect integration failures with the live database.

### Current State
- **`REAL_OQS` isolation**: The `sys.modules["oqs"]` mock is now strictly limited to Windows collection runs to prevent C-compilation hangs. An environment variable `REAL_OQS` explicitly flags whether a real `liboqs` backend is loaded. Tests requiring PQC (marked `@pytest.mark.pqc`) will explicitly `SKIP` if `REAL_OQS` is false, rather than falsely passing with the mock.
- **`REAL_REDIS` detection**: Redis is dynamically detected via ping. The `auto_mock_redis_for_unit_tests` fixture ONLY applies to tests marked as `@pytest.mark.unit`. Any test marked with `@pytest.mark.redis` will run against a live server or skip if unavailable.

## 2. Test Exclusions
### Previous State
- Permanent `pytest.ini` exclusions: `--ignore=test_blockchain_audit.py`, `--ignore=test_continuous_monitor.py`, etc., were hiding valid Docker/Linux integration tests from the local developer.
- Blanket skips for obsolete tests.

### Current State
- Exclusions have been replaced with explicit pytest markers (`unit`, `integration`, `docker`, `pqc`, `besu`).
- Only broken/obsolete tests that no longer map to the current architecture (e.g., `test_network_anomaly_monitor.py` replacing `MITMDetector`) and the build cache (`clean_build_env`) are excluded.

## 3. Environment Dependencies Identified
- **Post-Quantum Cryptography**: `liboqs` (Linux C-library bindings)
- **Differential Privacy & Auth**: `Redis` (Atomic LUA scripts, TTL)
- **Blockchain Ledger**: `Hyperledger Besu` / `Web3`
- **Malware Scanning**: `ClamAV Daemon`

## Conclusion
The testing environment is now scientifically truthful. Unit tests accurately reflect isolated component behavior on Windows, while Integration tests gracefully decline to run (SKIP) instead of reporting false positive SUCCESS statuses when critical security dependencies are absent.
