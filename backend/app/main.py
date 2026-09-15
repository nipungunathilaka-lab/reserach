from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.rate_limiter import InMemoryRateLimitMiddleware
from app.core.config import settings
from app.database.db import ensure_storage_dirs, init_db
from app.routes import internal_engine_routes
from app.services.ai_service import AIService
from app.services.malware_service import MalwareDetectionService
from app.services.mlkem_service import MLKEMService
from app.services.network_monitor import NetworkMonitorService
from app.services.network_anomaly import NetworkAnomalyEngine

app = FastAPI(title="Internal AI & Crypto Engine", version="1.0.0")

app.add_middleware(InMemoryRateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    try:
        ensure_storage_dirs()
        init_db()
        MLKEMService.startup_check()
        MLKEMService.backfill_keys()
        AIService.train_model()
        MalwareDetectionService.load_model()
        NetworkAnomalyEngine.initialize()
        NetworkMonitorService.start()
    except Exception as e:
        print(f"Error during startup: {e}")
        raise e


@app.get("/")
def health_check():
    return {"status": "ok", "app": "Internal AI/Crypto Service"}

from app.routes import (
    auth_routes,
    user_routes,
    shared_routes,
    log_routes,
    internal_engine_routes,
    email_otp_routes,
    dashboard_routes,
    crypto_routes,
    blockchain_routes,
    audit_routes,
    security_routes,
    network_routes
)
from fastapi import APIRouter

api_router = APIRouter(prefix="/api")
api_router.include_router(auth_routes.router)
api_router.include_router(user_routes.router)
api_router.include_router(shared_routes.router)
api_router.include_router(log_routes.router)
    # internal_engine_routes is mounted directly on app below
api_router.include_router(email_otp_routes.router)
api_router.include_router(dashboard_routes.router)
api_router.include_router(crypto_routes.router)
api_router.include_router(blockchain_routes.router)
api_router.include_router(audit_routes.router)
api_router.include_router(security_routes.router)
api_router.include_router(network_routes.router)

app.include_router(api_router)
app.include_router(internal_engine_routes.router)