import os
import math
import time
import secrets
import threading
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from app.security.privacy.config import dp_settings

@dataclass
class DPFeaturePolicy:
    lower_bound: float
    upper_bound: float
    sensitivity: float

# The feature policy registry
DP_FEATURE_POLICY = {
    "transfers_last_hour": DPFeaturePolicy(lower_bound=0.0, upper_bound=500.0, sensitivity=1.0),
    "mfa_failed_attempts": DPFeaturePolicy(lower_bound=0.0, upper_bound=20.0, sensitivity=1.0),
    "failed_login_attempts": DPFeaturePolicy(lower_bound=0.0, upper_bound=20.0, sensitivity=1.0),
}

class PrivacyBudgetExhausted(Exception):
    pass

class PrivacyConfigurationError(Exception):
    pass

class PrivacyBudgetAccountant:
    _lock = threading.Lock()
    # Mocking a persistence store using an in-memory dict for the sake of simplicity.
    # In production with multiple workers, this would be backed by Redis using INCR/SETEX.
    # Format: { "user_id:epoch": epsilon_spent }
    _budget_store: Dict[str, float] = {}

    @classmethod
    def get_epoch(cls) -> str:
        # Calculate epoch based on the current window
        window_seconds = dp_settings.dp_budget_window_hours * 3600
        current_time = int(time.time())
        return str(current_time // window_seconds)

    @classmethod
    def consume_budget(cls, user_id: str, epsilon: float) -> float:
        if epsilon <= 0:
            raise PrivacyConfigurationError("Epsilon must be greater than 0.")
        
        epoch = cls.get_epoch()
        key = f"{user_id}:{epoch}"
        
        with cls._lock:
            current_spent = cls._budget_store.get(key, 0.0)
            if current_spent + epsilon > dp_settings.dp_total_epsilon:
                raise PrivacyBudgetExhausted(f"Privacy budget exhausted for user {user_id}. Remaining: {dp_settings.dp_total_epsilon - current_spent}")
            
            cls._budget_store[key] = current_spent + epsilon
            return dp_settings.dp_total_epsilon - (current_spent + epsilon)
            
    @classmethod
    def reset_for_tests(cls):
        with cls._lock:
            cls._budget_store.clear()

class SecureLaplaceMechanism:
    """
    Mathematically correct Laplace mechanism implementation that uses `secrets.SystemRandom()`
    to guarantee cryptographically secure randomness, preventing deterministic RNG sequence attacks.
    """
    def __init__(self, epsilon: float, sensitivity: float):
        if epsilon <= 0:
            raise ValueError("Epsilon must be > 0")
        self.scale = sensitivity / epsilon
        self.rng = secrets.SystemRandom()

    def add_noise(self, value: float) -> float:
        # Generate Laplace noise: -scale * sgn(u) * ln(1 - 2|u|) where u ~ U(-0.5, 0.5)
        u = self.rng.uniform(-0.5, 0.5)
        sgn = 1.0 if u > 0 else -1.0
        noise = -self.scale * sgn * math.log(1.0 - 2.0 * abs(u))
        return value + noise

@dataclass
class DPResult:
    features: Dict[str, Any]
    applied: bool
    mechanism: str
    epsilon_spent: float
    remaining_budget: float
    protected_features: List[str]

class DifferentialPrivacyService:
    @classmethod
    def privatize_features(cls, user_id: str, transfer_id: str, raw_features: Dict[str, Any]) -> DPResult:
        if not dp_settings.dp_enabled:
            return DPResult(
                features=raw_features,
                applied=False,
                mechanism="none",
                epsilon_spent=0.0,
                remaining_budget=dp_settings.dp_total_epsilon,
                protected_features=[]
            )
            
        epsilon_per_feature = dp_settings.dp_epsilon_per_analysis / len(DP_FEATURE_POLICY)
        
        # Consume budget for the entire analysis step before proceeding.
        remaining = PrivacyBudgetAccountant.consume_budget(str(user_id), dp_settings.dp_epsilon_per_analysis)
        
        privatized_features = dict(raw_features)
        protected_list = []
        
        for feature_name, policy in DP_FEATURE_POLICY.items():
            if feature_name in privatized_features:
                raw_val = float(privatized_features[feature_name])
                
                # 1. Clip
                clipped_val = max(policy.lower_bound, min(raw_val, policy.upper_bound))
                
                # 2. Add Noise
                mechanism = SecureLaplaceMechanism(epsilon=epsilon_per_feature, sensitivity=policy.sensitivity)
                noisy_val = mechanism.add_noise(clipped_val)
                
                # 3. Post-process (clamp to domain again if appropriate, though DP technically is post-processing immune,
                # restricting output to logical bounds helps the downstream ML model).
                final_val = max(policy.lower_bound, min(noisy_val, policy.upper_bound))
                
                # If original was int, ensure int (post-processing)
                if isinstance(privatized_features[feature_name], int):
                    final_val = int(round(final_val))
                
                privatized_features[feature_name] = final_val
                protected_list.append(feature_name)
                
        return DPResult(
            features=privatized_features,
            applied=True,
            mechanism="Laplace",
            epsilon_spent=dp_settings.dp_epsilon_per_analysis,
            remaining_budget=remaining,
            protected_features=protected_list
        )
