from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.rate_limiter import InMemoryRateLimitMiddleware
from app.core.config import settings
from app.database.db import ensure_storage_dirs
from app.routes import internal_engine_routes
from app.services.ai_service import AIService
from app.services.malware_service import MalwareDetectionService
from app.services.mlkem_service import MLKEMService

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
        MLKEMService.startup_check()
        MLKEMService.backfill_keys()
        AIService.train_model()
        MalwareDetectionService.load_model()
    except Exception as e:
        print(f"Error during startup: {e}")
        import sys
        sys.exit(1)


@app.get("/")
def health_check():
    return {"status": "ok", "app": "Internal AI/Crypto Service"}


app.include_router(internal_engine_routes.router)