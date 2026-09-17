import os
from pydantic_settings import BaseSettings

class DpSettings(BaseSettings):
    dp_enabled: bool = os.environ.get("DP_ENABLED", "true").lower() == "true"
    dp_mechanism: str = os.environ.get("DP_MECHANISM", "Laplace")
    dp_total_epsilon: float = float(os.environ.get("DP_TOTAL_EPSILON", "10.0"))
    dp_epsilon_per_analysis: float = float(os.environ.get("DP_EPSILON_PER_ANALYSIS", "0.5"))
    dp_budget_window_hours: int = int(os.environ.get("DP_BUDGET_WINDOW", "24"))
    dp_epoch_hours: int = int(os.environ.get("DP_EPOCH_HOURS", "24"))
    dp_soft_limit_consumed_percent: int = int(os.environ.get("DP_SOFT_LIMIT_CONSUMED_PERCENT", "80"))
    dp_max_analyses_per_transfer: int = int(os.environ.get("DP_MAX_ANALYSES_PER_TRANSFER", "5"))
    dp_reserved_epsilon: float = float(os.environ.get("DP_RESERVED_EPSILON", "1.0"))
    dp_exhaustion_policy: str = os.environ.get("DP_EXHAUSTION_POLICY", "fallback_heuristics")
    dp_accountant_fail_policy: str = os.environ.get("DP_ACCOUNTANT_FAIL_POLICY", "fail_closed")
    dp_fail_policy: str = os.environ.get("DP_FAIL_POLICY", "fail_closed")

dp_settings = DpSettings()
