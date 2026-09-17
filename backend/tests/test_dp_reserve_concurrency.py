import pytest
import asyncio
import time
from unittest.mock import patch, MagicMock

from app.security.privacy.differential_privacy import PrivacyBudgetAccountant, DifferentialPrivacyService, PrivacyBudgetExhausted
from app.security.privacy.config import dp_settings

pytestmark = [pytest.mark.integration, pytest.mark.redis]

@pytest.fixture(autouse=True)
def setup_redis_accountant():
    PrivacyBudgetAccountant.reset_for_tests()
    # Mock settings for testing
    dp_settings.dp_total_epsilon = 10.0
    dp_settings.dp_reserved_epsilon = 2.0
    dp_settings.dp_epsilon_per_analysis = 1.0
    yield
    PrivacyBudgetAccountant.reset_for_tests()

def test_a_ordinary_before_boundary():
    # Test A — Ordinary assessment before reserve boundary
    remaining = PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_A", "PERIODIC")
    assert remaining == 9.0

def test_b_ordinary_enters_reserve():
    # Test B — Ordinary assessment would enter reserved budget
    for i in range(8):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, f"analysis_B_{i}", "PERIODIC")
        
    status = PrivacyBudgetAccountant.get_budget_status("user_test")
    assert status["remaining"] == 2.0 # Exactly at reserve boundary
    
    with pytest.raises(PrivacyBudgetExhausted):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_B_8", "PERIODIC")
        
    status = PrivacyBudgetAccountant.get_budget_status("user_test")
    assert status["remaining"] == 2.0 # Ensure budget was not mutated

def test_c_critical_at_boundary():
    # Test C — Critical assessment at reserve boundary
    for i in range(8):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, f"analysis_C_{i}", "PERIODIC")
        
    # Periodic fails
    with pytest.raises(PrivacyBudgetExhausted):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_C_periodic_fail", "PERIODIC")
        
    # Critical succeeds
    remaining = PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_C_critical_1", "CRITICAL")
    assert remaining == 1.0

def test_d_critical_insufficient_total():
    # Test D — Critical assessment with insufficient total epsilon
    for i in range(10):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, f"analysis_D_{i}", "CRITICAL")
        
    status = PrivacyBudgetAccountant.get_budget_status("user_test")
    assert status["remaining"] == 0.0
    
    with pytest.raises(PrivacyBudgetExhausted):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_D_fail", "CRITICAL")

@pytest.mark.asyncio
async def test_e_concurrent_requests():
    # Test E — Concurrent ordinary and critical requests
    # Prove the final total never exceeds the epoch budget and the reserve policy is preserved.
    
    async def consume_concurrently(analysis_id, a_class):
        try:
            await asyncio.to_thread(PrivacyBudgetAccountant.consume_budget, "user_test", 1.0, analysis_id, a_class)
            return True
        except PrivacyBudgetExhausted:
            return False

    tasks = []
    # Launch 20 periodic requests and 10 critical requests concurrently
    for i in range(20):
        tasks.append(consume_concurrently(f"analysis_E_P_{i}", "PERIODIC"))
    for i in range(10):
        tasks.append(consume_concurrently(f"analysis_E_C_{i}", "CRITICAL"))
        
    results = await asyncio.gather(*tasks)
    
    status = PrivacyBudgetAccountant.get_budget_status("user_test")
    
    # We should have exactly 10 consumptions total (budget is 10)
    assert status["consumed"] == 10.0
    assert status["remaining"] == 0.0
    assert sum(results) == 10

def test_f_idempotent_critical_retry():
    # Test F — Idempotent critical retry
    for i in range(8):
        PrivacyBudgetAccountant.consume_budget("user_test", 1.0, f"analysis_F_P_{i}", "PERIODIC")
        
    # Initial critical
    rem1 = PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_F_critical", "CRITICAL")
    assert rem1 == 1.0
    
    # Retry identical critical (idempotency kicks in)
    rem2 = PrivacyBudgetAccountant.consume_budget("user_test", 1.0, "analysis_F_critical", "CRITICAL")
    assert rem2 == 1.0
    
    status = PrivacyBudgetAccountant.get_budget_status("user_test")
    assert status["remaining"] == 1.0
