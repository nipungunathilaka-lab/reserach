import os
import sys

# Just importing the main app should trigger any startup logic if it's executed on load,
# but startup_check is called manually in most places, or inside `app.main`.
# Let's see if we can just call it to get the safe capability message.
from app.services.mlkem_service import MLKEMService, OQS_AVAILABLE

print("=== Backend Startup Test ===")
try:
    if OQS_AVAILABLE:
        print("PQC capability: ML-KEM-768 available")
    else:
        print("PQC capability unavailable")
except Exception as e:
    print(f"Startup check failed: {e}")
