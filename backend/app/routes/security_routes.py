import os
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/security", tags=["Security"])

class TEEStatusResponse(BaseModel):
    configured_provider: str
    tee_supported: bool
    tee_initialized: bool
    tee_active: bool
    provider: str | None = None
    enclave_version: str | None = None
    last_self_test: str | None = None

@router.get("/tee/status", response_model=TEEStatusResponse)
def get_tee_status():
    """
    Returns the current status of the Trusted Execution Environment (TEE).
    Currently unsupported/fail-closed on this host due to missing VBS build tooling.
    """
    # By default, TEE is unsupported on this machine configuration.
    provider = os.environ.get("UPCE_TEE_PROVIDER", "vbs")
    return TEEStatusResponse(
        configured_provider=provider,
        tee_supported=False,
        tee_initialized=False,
        tee_active=False
    )

from app.security.mitm import MITMDetector
from app.security.quarantine import QuarantineService
from fastapi import HTTPException, Depends

@router.get("/capabilities")
def get_security_capabilities():
    import os
    clamav_host = os.environ.get("CLAMAV_HOST", "localhost")
    clamav_available = False
    try:
        import pyclamd
        cd = pyclamd.ClamdNetworkSocket(clamav_host, 3310)
        clamav_available = cd.ping()
    except:
        pass

    return {
        "mitm_detection": MITMDetector.get_capabilities(),
        "malware": {
            "full_file_scanning": True,
            "clamav_available": clamav_available,
            "yara_enabled": False,  # Not implemented yet
            "heuristic_ml_enabled": True,
            "quarantine_enabled": True
        }
    }

@router.get("/quarantine")
def list_quarantine(admin_id: str = "admin"):
    # Simulated RBAC for prototype
    return QuarantineService.get_quarantine_list()

@router.get("/quarantine/{item_id}")
def get_quarantine_item(item_id: int):
    item = QuarantineService.get_item(item_id)
    if not item:
        raise HTTPException(404, "Item not found")
    return item

@router.post("/quarantine/{item_id}/rescan")
def rescan_quarantine_item(item_id: int, admin_user: str = "admin"):
    return QuarantineService.rescan_item(item_id, admin_user)

@router.post("/quarantine/{item_id}/release")
def release_quarantine_item(item_id: int, admin_user: str = "admin"):
    res = QuarantineService.release_item(item_id, admin_user)
    if "error" in res:
        raise HTTPException(400, res["error"])
    return res

@router.delete("/quarantine/{item_id}")
def delete_quarantine_item(item_id: int, admin_user: str = "admin"):
    res = QuarantineService.delete_item(item_id, admin_user)
    if "error" in res:
        raise HTTPException(400, res["error"])
    return res
