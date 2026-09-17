import pytest
pytestmark = [pytest.mark.integration, pytest.mark.pqc]
import os
import sys

from app.services.mlkem_service import MLKEMService

# Force PQC_REQUIRED=true in settings
from app.core.config import settings
settings.pqc_required = True

# Force OQS_AVAILABLE=False by patching the module
import app.services.mlkem_service as module
module.OQS_AVAILABLE = False

try:
    MLKEMService.startup_check()
    print("PQC_REQUIRED failure test: FAIL (Did not raise exception)")
except RuntimeError as e:
    if "PQC is required but liboqs-python could not be imported" in str(e) or "PQC is enabled but liboqs-python could not be imported" in str(e):
        print("PQC_REQUIRED failure test: PASS")
    else:
        print(f"PQC_REQUIRED failure test: FAIL (Wrong exception: {e})")
except Exception as e:
    print(f"PQC_REQUIRED failure test: FAIL (Wrong exception type: {e})")
