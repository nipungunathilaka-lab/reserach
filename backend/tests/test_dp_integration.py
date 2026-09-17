import pytest
from app.services.continuous_monitor import ContinuousTransferMonitor, TransferBlockedError
from app.security.privacy.differential_privacy import PrivacyBudgetAccountant
from app.security.privacy.config import dp_settings

pytestmark = [pytest.mark.integration, pytest.mark.redis]

def setup_function(function):
    PrivacyBudgetAccountant.reset_for_tests()
    dp_settings.dp_enabled = True
    dp_settings.dp_total_epsilon = 10.0
    dp_settings.dp_epsilon_per_analysis = 0.5
    dp_settings.dp_fail_policy = "fail_closed"

def test_active_pipeline_integration():
    """
    Simulates a transfer monitor analyzing a transfer, which in turn should invoke the DP service, 
    consume budget, and pass DP-protected features to the AI model.
    """
    monitor = ContinuousTransferMonitor(
        transfer_id="test_transfer_active",
        sender_id="sender_1",
        receiver_id="receiver_1",
        file_name="test.txt",
        file_size=1024,
        transfers_last_hour=100,
        mfa_failed_attempts=0,
        failed_login_attempts=0,
        hour_of_day=14
    )
    
    # Trigger AI analysis
    ai_result = monitor.reanalyze_transfer()
    
    # DP should be applied
    assert ai_result.get("dp_applied") is True
    assert "transfers_last_hour" in ai_result.get("dp_protected_features", [])
    
    # Features in the AI result should be protected
    # e.g., the original was 100, it should be perturbed (though it could theoretically be exactly 100, it's very unlikely)
    # But definitely it should be present in the ML features list
    features = ai_result.get("features", {})
    
    # Ensure budget was consumed
    # Remaining budget should be 10.0 - 0.5 = 9.5
    remaining = PrivacyBudgetAccountant._budget_store.get(f"sender_1:{PrivacyBudgetAccountant.get_epoch()}", 0.0)
    assert remaining == 0.5 # Wait, the store records SPENT budget.
    
def test_dp_exhaustion_fallback_policy():
    """
    Simulate what happens when a user exhausts their privacy budget.
    """
    dp_settings.dp_total_epsilon = 1.0
    dp_settings.dp_epsilon_per_analysis = 0.6
    
    # First transfer succeeds
    m1 = ContinuousTransferMonitor(
        transfer_id="t1", sender_id="user_exhaust", receiver_id="r1",
        file_name="f1.txt", file_size=1024, transfers_last_hour=1, mfa_failed_attempts=0, failed_login_attempts=0, hour_of_day=14
    )
    m1.reanalyze_transfer()
    
    # Second transfer should fail due to budget exhaustion (since policy = fail_closed)
    m2 = ContinuousTransferMonitor(
        transfer_id="t2", sender_id="user_exhaust", receiver_id="r1",
        file_name="f2.txt", file_size=1024, transfers_last_hour=1, mfa_failed_attempts=0, failed_login_attempts=0, hour_of_day=14
    )
    
    with pytest.raises(TransferBlockedError) as exc_info:
        m2.reanalyze_transfer()
        
    assert "Privacy budget exhausted" in str(exc_info.value.message)
    
def test_dp_exhaustion_open_policy():
    """
    If the fail policy is NOT fail_closed, it should skip AI analysis but NOT block the transfer.
    """
    dp_settings.dp_total_epsilon = 1.0
    dp_settings.dp_epsilon_per_analysis = 0.6
    dp_settings.dp_fail_policy = "fail_open"
    
    m1 = ContinuousTransferMonitor(
        transfer_id="t3", sender_id="user_open", receiver_id="r1",
        file_name="f1.txt", file_size=1024, transfers_last_hour=1, mfa_failed_attempts=0, failed_login_attempts=0, hour_of_day=14
    )
    m1.reanalyze_transfer()
    
    m2 = ContinuousTransferMonitor(
        transfer_id="t4", sender_id="user_open", receiver_id="r1",
        file_name="f2.txt", file_size=1024, transfers_last_hour=1, mfa_failed_attempts=0, failed_login_attempts=0, hour_of_day=14
    )
    
    # Should NOT raise an exception, but should return a safe fallback result
    ai_result = m2.reanalyze_transfer()
    
    assert ai_result["dp_applied"] is False
    assert ai_result["is_anomaly"] is False
    assert "Analysis skipped due to DP Budget Exhaustion" in ai_result["reason"]
