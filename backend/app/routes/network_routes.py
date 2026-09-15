from fastapi import APIRouter
from app.services.network_monitor import NetworkMonitorService
from app.services.network_anomaly import NetworkAnomalyEngine

router = APIRouter(prefix="/network", tags=["Network Security"])

@router.get("/status")
def get_network_status():
    monitor_status = NetworkMonitorService.get_status()
    anomaly_status = NetworkAnomalyEngine.get_status()
    
    return {
        **monitor_status,
        **anomaly_status
    }
