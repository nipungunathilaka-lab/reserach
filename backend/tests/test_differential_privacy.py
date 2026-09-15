import pytest
import math
import time
from app.security.privacy.differential_privacy import (
    DifferentialPrivacyService, 
    PrivacyBudgetExhausted, 
    PrivacyBudgetAccountant, 
    SecureLaplaceMechanism,
    DP_FEATURE_POLICY
)
from app.security.privacy.config import dp_settings

def setup_module(module):
    dp_settings.dp_enabled = True
    dp_settings.dp_total_epsilon = 10.0
    dp_settings.dp_epsilon_per_analysis = 0.5
    dp_settings.dp_budget_window_hours = 24

def setup_function(function):
    PrivacyBudgetAccountant.reset_for_tests()
    dp_settings.dp_enabled = True

def test_dp_configuration():
    assert dp_settings.dp_enabled == True
    assert dp_settings.dp_total_epsilon == 10.0
    assert dp_settings.dp_epsilon_per_analysis == 0.5

def test_laplace_mechanism_sanity():
    # epsilon=0.5, sensitivity=1.0 -> scale = 2.0
    mech = SecureLaplaceMechanism(epsilon=0.5, sensitivity=1.0)
    
    # Run multiple times to ensure variance
    samples = [mech.add_noise(10.0) for _ in range(100)]
    
    # Check that we are actually getting variance and not just 10.0
    assert any(s != 10.0 for s in samples)
    
    # Check if there are both positive and negative perturbations
    has_positive = any(s > 10.0 for s in samples)
    has_negative = any(s < 10.0 for s in samples)
    assert has_positive
    assert has_negative
    
    # Mean should be roughly around 10.0
    mean = sum(samples) / len(samples)
    assert 5.0 < mean < 15.0

def test_budget_accounting():
    user_id = "test_user_budget"
    
    # Consume budget once
    remaining = PrivacyBudgetAccountant.consume_budget(user_id, 2.0)
    assert remaining == 8.0
    
    # Consume again
    remaining = PrivacyBudgetAccountant.consume_budget(user_id, 3.0)
    assert remaining == 5.0
    
    # Exhaust budget
    with pytest.raises(PrivacyBudgetExhausted):
        PrivacyBudgetAccountant.consume_budget(user_id, 6.0)

def test_feature_bounding():
    raw_features = {
        "transfers_last_hour": 1000, # Above upper bound (500)
        "mfa_failed_attempts": -5,   # Below lower bound (0)
        "failed_login_attempts": 10, # Within bounds (0-20)
    }
    
    dp_result = DifferentialPrivacyService.privatize_features(
        user_id="test_user_bounds",
        transfer_id="transfer_123",
        raw_features=raw_features
    )
    
    features = dp_result.features
    assert features["transfers_last_hour"] <= 500
    assert features["mfa_failed_attempts"] >= 0
    assert 0 <= features["failed_login_attempts"] <= 20
    assert "transfers_last_hour" in dp_result.protected_features
    
def test_dp_disabled():
    dp_settings.dp_enabled = False
    raw_features = {"transfers_last_hour": 10}
    
    dp_result = DifferentialPrivacyService.privatize_features(
        user_id="test_user_disabled",
        transfer_id="transfer_123",
        raw_features=raw_features
    )
    
    assert dp_result.applied == False
    assert dp_result.epsilon_spent == 0.0
    assert dp_result.features["transfers_last_hour"] == 10

def test_dp_budget_exhaustion_in_service():
    dp_settings.dp_total_epsilon = 1.0
    dp_settings.dp_epsilon_per_analysis = 0.6
    
    user_id = "test_user_exhaustion"
    
    # First call succeeds
    DifferentialPrivacyService.privatize_features(user_id, "transfer_1", {"transfers_last_hour": 5})
    
    # Second call fails due to budget
    with pytest.raises(PrivacyBudgetExhausted):
        DifferentialPrivacyService.privatize_features(user_id, "transfer_2", {"transfers_last_hour": 5})
