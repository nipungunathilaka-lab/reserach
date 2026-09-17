import os
import sys
import pytest
from unittest import mock
import fakeredis

# =====================================================================
# ENVIRONMENT SERVICE DETECTION
# =====================================================================

# 1. PQC (liboqs) Detection
if sys.platform == "win32" and not os.environ.get("FORCE_REAL_OQS"):
    # On Windows, importing oqs attempts to build C-libraries and hangs indefinitely.
    # We must globally mock it here ONLY for collection safety on Windows.
    if "oqs" not in sys.modules:
        sys.modules["oqs"] = mock.MagicMock()
    REAL_OQS = False
else:
    try:
        import oqs
        REAL_OQS = True
    except ImportError:
        REAL_OQS = False

# 2. Redis Detection
try:
    import redis
    # Fast fail ping
    r = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), socket_connect_timeout=0.5, socket_timeout=0.5)
    r.ping()
    REAL_REDIS = True
except Exception:
    REAL_REDIS = False

# 3. Besu (Web3) Detection
REAL_BESU = False
try:
    import requests
    resp = requests.post(
        os.environ.get("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545"), 
        json={"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":1},
        timeout=0.5
    )
    if resp.status_code == 200:
        REAL_BESU = True
except Exception:
    pass

# =====================================================================
# TEST ENFORCEMENT FIXTURES
# =====================================================================

@pytest.fixture(autouse=True)
def enforce_environment_requirements(request):
    """
    Globally intercepts tests marked with specific requirements.
    If the requirement is not met, the test is explicitly skipped.
    """
    if request.node.get_closest_marker('pqc'):
        if not REAL_OQS:
            pytest.skip("Requires real liboqs runtime; run inside Linux/Docker integration environment.")
            
    if request.node.get_closest_marker('redis'):
        if not REAL_REDIS:
            pytest.skip("Requires real Redis backend; run inside Linux/Docker integration environment.")
            
    if request.node.get_closest_marker('besu'):
        if not REAL_BESU:
            pytest.skip("Requires real Hyperledger Besu node; run inside Linux/Docker integration environment.")

# Ensure fast fail for any unmocked network calls during unit tests
if not REAL_REDIS:
    os.environ["REDIS_URL"] = "redis://localhost:6379/0"

def _apply_redis_mock(monkeypatch):
    fake_sync = fakeredis.FakeStrictRedis(decode_responses=True)
    try:
        import app.security.privacy.differential_privacy as dp
        monkeypatch.setattr(dp, "get_sync_redis", lambda: fake_sync)
    except ImportError:
        pass
    try:
        import app.security.internal_auth as internal_auth
        monkeypatch.setattr(internal_auth, "get_redis", lambda: fake_sync)
    except ImportError:
        pass

@pytest.fixture(autouse=True)
def auto_mock_redis_for_unit_tests(request, monkeypatch):
    """
    Mocks Redis globally using fakeredis. 
    Only applied if the test is NOT explicitly marked with @pytest.mark.redis.
    """
    if not request.node.get_closest_marker('redis'):
        _apply_redis_mock(monkeypatch)
