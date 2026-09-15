import os
from pydantic_settings import BaseSettings

class DpSettings(BaseSettings):
    dp_enabled: bool = os.environ.get("DP_ENABLED", "true").lower() == "true"
    dp_mechanism: str = os.environ.get("DP_MECHANISM", "Laplace")
    dp_total_epsilon: float = float(os.environ.get("DP_TOTAL_EPSILON", "10.0"))
    dp_epsilon_per_analysis: float = float(os.environ.get("DP_EPSILON_PER_ANALYSIS", "0.5"))
    dp_budget_window_hours: int = int(os.environ.get("DP_BUDGET_WINDOW", "24"))
    dp_fail_policy: str = os.environ.get("DP_FAIL_POLICY", "fail_closed")

dp_settings = DpSettings()
