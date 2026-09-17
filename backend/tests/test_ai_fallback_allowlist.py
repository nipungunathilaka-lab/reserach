import pytest
pytestmark = [pytest.mark.unit]
import pytest
from app.services.ai_service import AIService

def test_deterministic_fallback_allowlist():
    valid_features = {
        'file_size_violates_policy': True,
        'authentication_policy_violation': False,
        'account_locked': False,
        'high_risk_file_type': 0,
        'archive_file_type': 0
    }
    
    # Should pass
    is_anomaly, reason, level, risk, reasons = AIService.deterministic_security_assessment(valid_features)
    assert risk >= 0.3 # because file_size_violates_policy is True
    
    invalid_features = {
        'file_size_violates_policy': True,
        'authentication_policy_violation': False,
        'account_locked': False,
        'high_risk_file_type': 0,
        'archive_file_type': 0,
        'sender_id': 'user_123', # Not allowed!
        'file_name': 'secret.txt', # Not allowed!
        'hour_of_day': 3 # Not allowed!
    }
    
    with pytest.raises(ValueError, match="is not in the deterministic fallback allowlist"):
        AIService.deterministic_security_assessment(invalid_features)
