import os
import io
import pytest
import time
import uuid
import tempfile
from fastapi import HTTPException
from app.services.pfce_engine import PFCEEngine
from app.services.continuous_monitor import ContinuousTransferMonitor, TransferBlockedError
from app.core.config import settings

@pytest.fixture
def override_settings():
    original_enabled = settings.ai_continuous_monitoring_enabled
    original_interval = settings.ai_monitor_interval_seconds
    original_chunks = settings.ai_monitor_every_n_chunks
    original_block = settings.ai_block_threshold
    
    settings.ai_continuous_monitoring_enabled = True
    settings.ai_monitor_interval_seconds = 0  # Force immediate check
    settings.ai_monitor_every_n_chunks = 1    # Check every chunk
    settings.ai_block_threshold = 0.8
    os.environ["UPCE_REQUIRE_TEE"] = "false"
    
    # Mock Blockchain logging to avoid db errors
    import app.services.continuous_monitor as cm
    original_log = cm.ContinuousTransferMonitor._log_to_blockchain
    cm.ContinuousTransferMonitor._log_to_blockchain = lambda self, event_type, result: None
    
    # Mock CryptoService prekey methods
    import app.services.crypto_service as cs
    original_claim_prekey = cs.CryptoService.claim_prekey
    original_get_delete_prekey = cs.CryptoService.get_and_delete_prekey
    cs.CryptoService.claim_prekey = lambda *args, **kwargs: "mock_prekey_pem"
    cs.CryptoService.get_and_delete_prekey = lambda *args, **kwargs: "mock_prekey_private_pem"
    
    yield
    
    settings.ai_continuous_monitoring_enabled = original_enabled
    settings.ai_monitor_interval_seconds = original_interval
    settings.ai_monitor_every_n_chunks = original_chunks
    settings.ai_block_threshold = original_block
    os.environ.pop("UPCE_REQUIRE_TEE", None)
    cm.ContinuousTransferMonitor._log_to_blockchain = original_log

def test_monitoring_starts(override_settings):
    monitor = ContinuousTransferMonitor(
        transfer_id="test_1",
        sender_id="1",
        receiver_id="2",
        file_name="safe_file.txt",
        file_size=1024,
        transfers_last_hour=0,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        hour_of_day=12
    )
    assert monitor.telemetry.transfer_id == "test_1"
    assert monitor.telemetry.status == "IN_PROGRESS"

def test_multiple_evaluations_and_rolling_metrics(override_settings):
    monitor = ContinuousTransferMonitor(
        transfer_id="test_2",
        sender_id="1",
        receiver_id="2",
        file_name="safe_file.txt",
        file_size=10 * 1024 * 1024,
        transfers_last_hour=0,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        hour_of_day=12
    )
    
    # First chunk
    monitor.update_telemetry(1024 * 1024)
    assert monitor.should_reanalyse() == True
    monitor.reanalyze_transfer()
    assert monitor.telemetry.samples_count == 1
    assert monitor.telemetry.bytes_processed == 1024 * 1024
    
    # Second chunk
    monitor.update_telemetry(1024 * 1024)
    assert monitor.should_reanalyse() == True
    monitor.reanalyze_transfer()
    assert monitor.telemetry.samples_count == 2
    assert monitor.telemetry.bytes_processed == 2 * 1024 * 1024

def test_mid_transfer_blocking(override_settings):
    monitor = ContinuousTransferMonitor(
        transfer_id="test_3",
        sender_id="1",
        receiver_id="2",
        file_name="suspicious.exe", # high risk extension
        file_size=60 * 1024 * 1024,
        transfers_last_hour=10, # elevated
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        hour_of_day=2 # unusual hour
    )
    
    # Simulate a very slow transfer (triggers our rolling heuristic)
    monitor.update_telemetry(1024)
    time.sleep(0.2) # Fast in real life, but we'll manually manipulate telemetry started_at to simulate slowness
    monitor.telemetry.started_at -= 15 # Simulate 15 seconds elapsed
    
    with pytest.raises(TransferBlockedError) as exc:
        monitor.reanalyze_transfer()
        
    assert "Continuous monitoring triggered block" in str(exc.value)
    assert monitor.telemetry.status == "BLOCKED"
    assert monitor.telemetry.current_risk_level == "BLOCKED"

def test_pfce_engine_blocks_mid_flight(override_settings):
    # Integration test with PFCE engine
    engine = PFCEEngine()
    
    # Create dummy data (20 MB)
    data = os.urandom(20 * 1024 * 1024)
    file_stream = io.BytesIO(data)
    
    monitor = ContinuousTransferMonitor(
        transfer_id="test_4",
        sender_id="1",
        receiver_id="2",
        file_name="suspicious.exe",
        file_size=len(data),
        transfers_last_hour=10,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        hour_of_day=2
    )
    
    # We will modify the monitor to simulate slowness on the second chunk
    original_reanalyze = monitor.reanalyze_transfer
    def fake_reanalyze():
        if monitor.telemetry.chunks_processed > 1:
            monitor.telemetry.started_at -= 20 # trigger slow heuristic block
        return original_reanalyze()
    
    monitor.reanalyze_transfer = fake_reanalyze
    
    with tempfile.TemporaryDirectory() as temp_dir:
        pfce_package_path = os.path.join(temp_dir, "out.pfce")
        
        with pytest.raises(TransferBlockedError):
            engine.process_upload(
                file_stream=file_stream,
                sender_id="1",
                receiver_id="2",
                stored_name_prefix="test",
                classification="standard",
                pfce_package_path=pfce_package_path,
                transfer_monitor=monitor
            )
            
        # Verify cleanup occurred (the pfce package should not exist or be complete)
        assert not os.path.exists(pfce_package_path) or os.path.getsize(pfce_package_path) == 0

