import os
import math
import time
import secrets
import threading
import redis
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from app.security.privacy.config import dp_settings

@dataclass
class DPFeaturePolicy:
    lower_bound: float
    upper_bound: float
    sensitivity: float

# The feature policy registry
# In Server-Side Differential Privacy, where the privacy unit is a single transfer event, 
# the sensitivity of a feature is exactly its domain range (upper_bound - lower_bound).
#
# Feature Classifications:
# - Continuous: file_size_mb
# - Count: transfers_last_hour, mfa_failed_attempts, failed_login_attempts
# - Binary/Categorical: hour_of_day (pseudo-continuous here), is_unusual_hour, high_risk_file_type, archive_file_type
# 
# Note on Binary Features:
# Currently, the continuous Laplace Mechanism is applied globally across all feature types.
# For binary features (e.g., is_unusual_hour), injecting heavy continuous noise and clipping 
# back to [0,1] causes severe distribution overlap (effective uniform randomness).
# A future iteration should evaluate Randomized Response (or similar discrete mechanisms) 
# for binary/categorical features to better preserve class-discriminative utility under strict epsilons.
DP_FEATURE_POLICY = {
    "file_size_mb": DPFeaturePolicy(lower_bound=0.0, upper_bound=1000.0, sensitivity=1000.0),
    "hour_of_day": DPFeaturePolicy(lower_bound=0.0, upper_bound=23.0, sensitivity=23.0),
    "transfers_last_hour": DPFeaturePolicy(lower_bound=0.0, upper_bound=500.0, sensitivity=500.0),
    "mfa_failed_attempts": DPFeaturePolicy(lower_bound=0.0, upper_bound=20.0, sensitivity=20.0),
    "failed_login_attempts": DPFeaturePolicy(lower_bound=0.0, upper_bound=20.0, sensitivity=20.0),
    "is_unusual_hour": DPFeaturePolicy(lower_bound=0.0, upper_bound=1.0, sensitivity=1.0),
    "high_risk_file_type": DPFeaturePolicy(lower_bound=0.0, upper_bound=1.0, sensitivity=1.0),
    "archive_file_type": DPFeaturePolicy(lower_bound=0.0, upper_bound=1.0, sensitivity=1.0),
}

class PrivacyBudgetExhausted(Exception):
    pass

class DPAccountantUnavailable(Exception):
    pass

class PrivacyConfigurationError(Exception):
    pass

# Synchronous Redis client for the accountant
_redis_client_sync = None

def get_sync_redis():
    global _redis_client_sync
    if not _redis_client_sync:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client_sync = redis.from_url(url, decode_responses=True)
    return _redis_client_sync

class PrivacyBudgetAccountant:
    _LUA_SCRIPT = """
    local budget_key = KEYS[1]
    local analysis_id = ARGV[1]
    local cost = tonumber(ARGV[2])
    local max_budget = tonumber(ARGV[3])
    local ttl = tonumber(ARGV[4])
    local analysis_class = ARGV[5]
    local reserved_budget = tonumber(ARGV[6])
    
    local seen_field = "seen:" .. analysis_id
    local already_charged = redis.call('HGET', budget_key, seen_field)
    local consumed = tonumber(redis.call('HGET', budget_key, 'consumed') or "0")
    local remaining_epsilon = max_budget - consumed
    
    if already_charged then
        return {1, tonumber(already_charged), consumed}
    end
    
    if analysis_class == "PERIODIC" then
        if remaining_epsilon - reserved_budget < cost then
            return {0, 0, consumed}
        end
    else
        if remaining_epsilon < cost then
            return {0, 0, consumed}
        end
    end
    
    redis.call('HINCRBY', budget_key, 'consumed', cost)
    redis.call('HINCRBY', budget_key, 'count', 1)
    redis.call('HSET', budget_key, seen_field, cost)
    
    local current_ttl = redis.call('TTL', budget_key)
    if current_ttl == -1 or current_ttl == -2 then
        redis.call('EXPIRE', budget_key, ttl)
    end
    
    return {2, cost, consumed + cost}
    """
    
    _script_hash = None

    @classmethod
    def get_epoch(cls) -> tuple[str, int]:
        now = datetime.now(timezone.utc)
        epoch_hours = dp_settings.dp_epoch_hours
        epoch_seconds = epoch_hours * 3600
        epoch_id = int(now.timestamp() // epoch_seconds)
        
        next_epoch_time = (epoch_id + 1) * epoch_seconds
        ttl = int(next_epoch_time - now.timestamp())
        
        return str(epoch_id), ttl

    @classmethod
    def consume_budget(cls, user_id: str, epsilon: float, analysis_id: str, analysis_class: str = "INITIAL") -> float:
        if epsilon <= 0:
            raise PrivacyConfigurationError("Epsilon must be greater than 0.")
            
        epoch, ttl = cls.get_epoch()
        key = f"dp:budget:{user_id}:{epoch}"
        
        scale = 1_000_000
        cost_int = int(epsilon * scale)
        max_budget_int = int(dp_settings.dp_total_epsilon * scale)
        reserved_budget_int = int(dp_settings.dp_reserved_epsilon * scale)
        
        try:
            r = get_sync_redis()
            if not cls._script_hash:
                cls._script_hash = r.script_load(cls._LUA_SCRIPT)
            result = r.evalsha(cls._script_hash, 1, key, analysis_id, cost_int, max_budget_int, ttl, analysis_class, reserved_budget_int)
        except redis.RedisError as e:
            raise DPAccountantUnavailable(f"Privacy accountant unavailable: {str(e)}")
            
        status, charged, new_consumed = result
        
        if status == 0:
            remaining = (max_budget_int - new_consumed) / scale
            raise PrivacyBudgetExhausted(f"Privacy budget exhausted. Remaining: {remaining}")
            
        return (max_budget_int - new_consumed) / scale
            
    @classmethod
    def get_budget_status(cls, user_id: str) -> dict:
        epoch, ttl = cls.get_epoch()
        key = f"dp:budget:{user_id}:{epoch}"
        try:
            r = get_sync_redis()
            consumed_str = r.hget(key, 'consumed')
            count_str = r.hget(key, 'count')
        except redis.RedisError:
            return {"status": "unavailable"}
            
        scale = 1_000_000
        consumed_int = int(consumed_str) if consumed_str else 0
        consumed = consumed_int / scale
        remaining = dp_settings.dp_total_epsilon - consumed
        return {
            "status": "available" if remaining > 0 else "exhausted",
            "consumed": consumed,
            "remaining": remaining,
            "count": int(count_str) if count_str else 0,
            "epoch_id": epoch,
            "ttl": ttl
        }

    @classmethod
    def reset_for_tests(cls):
        try:
            r = get_sync_redis()
            r.flushdb()
        except redis.RedisError:
            pass

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
    def privatize_features(cls, user_id: str, transfer_id: str, raw_features: Dict[str, Any], analysis_id: str = None, analysis_class: str = "INITIAL") -> DPResult:
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
        if not analysis_id:
            analysis_id = str(secrets.token_hex(8))
            
        # Consume budget atomically.
        remaining = PrivacyBudgetAccountant.consume_budget(str(user_id), dp_settings.dp_epsilon_per_analysis, analysis_id, analysis_class)
        
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
                
                # 3. Post-process (clamp to domain again if appropriate)
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
