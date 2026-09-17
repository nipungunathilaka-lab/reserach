# Backend Test Environment Validation Report

## 1. Previous Test Problem
The `pytest` environment on the Windows host was unstable, primarily failing during the test collection phase (hanging indefinitely) or reporting misleading results for security tests. Critical cryptography, distributed ledger, and privacy services were heavily coupled to a Linux/Docker environment, making local execution impossible without catastrophic blocking or masking of failures.

## 2. Root Causes
- **`liboqs` C-library auto-builds**: The `liboqs-python` package dynamically triggered a C-compiler build process on Windows because precompiled `.so` binaries were missing. This hung the `pytest` collector on any module importing `oqs`.
- **Global Mock Masking**: To solve the hang, a previous patch globally mocked `sys.modules["oqs"] = MagicMock()`. This catastrophically compromised security test validity, allowing Post-Quantum Cryptography tests to report a `PASS` state without ever executing real mathematical crypto functions.
- **Unreachable Service Dependencies**: Differential Privacy and Blockchain tests implicitly relied on Redis and Besu being bound to localhost, resulting in connection timeouts or misleading failures natively.
- **Obsolete Tests**: Refactored components (`MITMDetector` -> `NetworkAnomalyEngine`) left legacy tests broken.

## 3. Windows Unit-Test Architecture (Tier A)
The environment now supports a Windows-compatible Tier A test suite. 
- **Command**: `pytest -m "unit and not docker" -v`
- **Scope**: Validates component logic, mathematical bounds, DP clipping functions, and data transformations.
- **Mocking**: Services like Redis are explicitly mocked (`fakeredis`) via the `auto_mock_redis_for_unit_tests` fixture **only** for tests explicitly marked as `@pytest.mark.unit`.

## 4. Docker Integration-Test Architecture (Tier B)
We introduced `scripts/run_docker_integration_tests.sh` to enforce the execution of Tier B tests.
- **Scope**: Full End-to-End E2EE payload validation, atomic Redis budget consumption, Smart Contract anchoring, and ClamAV binary analysis.
- **Enforcement**: Tier B explicitly checks for service health (`nc -z localhost 6379`) before execution and outputs a dedicated `docker_integration_test_summary.json`. If executed natively on Windows, these tests gracefully `SKIP` with the message `"Requires real [...] runtime; run inside Linux/Docker integration environment."` instead of throwing obscure connection faults.

## 5. OQS Mock Isolation
The `sys.modules["oqs"]` global mock is now aggressively constrained. 
It is only applied on the `win32` platform to prevent collection hanging, but crucially, it simultaneously sets an internal `REAL_OQS = False` flag. Any test explicitly validating PQC (`@pytest.mark.pqc`) enforces `REAL_OQS == True`, immediately skipping the test locally rather than granting a false positive.

## 6. Redis Mock Isolation
DP Unit tests (verifying mathematical DP mechanisms) run against `fakeredis`. However, concurrency, race condition, and atomic locking tests (e.g., `test_redis_dp_accountant.py`) are strictly marked with `@pytest.mark.redis`. They ignore the fake fixture and bind to a real Redis socket (which correctly fails over to a SKIP state on Windows).

## 7. Marker Strategy
Broad `--ignore` arguments in `pytest.ini` were permanently removed. Instead, tests are semantically tagged:
- `@pytest.mark.unit`
- `@pytest.mark.integration`
- `@pytest.mark.docker`
- `@pytest.mark.pqc`, `@pytest.mark.besu`, `@pytest.mark.clamav`, `@pytest.mark.network`, `@pytest.mark.redis`

## 8. Obsolete Test Resolution
Legacy tests were updated rather than permanently ignored:
- `test_network_anomaly_monitor.py` & `test_policy.py`: Marked as `OBSOLETE/SKIPPED` due to complete upstream engine rewrites (`NetworkAnomalyEngine` and `UPCE` respectively).
- `test_kms.py`: Bypassed with `skipif("boto3" not in sys.modules)` to prevent `ImportError` crashes.
- `smoke_test.py`: Stripped of legacy ORM references (`Transfer` model) and refactored to use raw SQL for tamper testing.

## 9. Windows Test Results
**Execution Command**: `pytest -m "unit and not docker" -v`
- **Collected**: 100
- **Passed**: 12
- **Failed**: 6
- **Skipped**: 4
- **Deselected**: 82 (Integration/Service-dependent tests safely skipped)

## 10. Docker Test Results
- **Status**: `ENVIRONMENT_UNAVAILABLE` / `NOT_RUN` (Pending deployment to the Linux TEE/Docker stack).

## 11. Remaining Failures
The 6 failures observed natively on Windows are legitimate unit test regressions caused by recent API refactoring (e.g., missing positional arguments in `CryptoService`, signature mismatches in `test_digital_signatures.py`). **They are NOT environment failures.**

## 12. Environment Requirements
- **Tier A (Windows)**: Python 3.11+, Pytest, Fakeredis.
- **Tier B (Linux/Docker)**: Redis (Port 6379), Hyperledger Besu (Port 8545), ClamAV (Port 3310), `liboqs` C-Libraries.

## 13. Which Results Are Thesis Evidence
- **Tier B Integration Results**: Security guarantees (Forward Secrecy lifecycle, UPCE Memory Wiping, Ledger Immutability, Atomic DP Budgets, Malware fail-closed states). 

## 14. Which Results Are Development-Only Evidence
- **Tier A Unit Results**: Mathematical bounds, basic API schema routing, and classification logic overrides.
