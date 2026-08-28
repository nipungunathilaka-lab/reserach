from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.rate_limiter import InMemoryRateLimitMiddleware
from app.core.config import settings
from app.database.db import SessionLocal, init_db
from app.database.seed import seed_demo_data
from app.routes import auth_routes, dashboard_routes, file_routes, log_routes, user_routes, crypto_routes, email_otp_routes, blockchain_routes, shared_routes
from app.services.ai_service import AIService
from app.services.malware_service import MalwareDetectionService
from app.routes import audit_routes 

app = FastAPI(title=settings.app_name, version="1.1.0")

app.include_router(audit_routes.router, prefix="/api/audit", tags=["Audit"])

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
    init_db()
    db = SessionLocal()
    try:
        if settings.seed_demo_users:
            seed_demo_data(db)
        AIService.train_model()
        MalwareDetectionService.load_model()
    finally:
        db.close()


@app.get("/")
def health_check():
    return {"status": "ok", "app": settings.app_name}


app.include_router(auth_routes.router, prefix="/api")
app.include_router(user_routes.router, prefix="/api")
app.include_router(file_routes.router, prefix="/api")
app.include_router(log_routes.router, prefix="/api")
app.include_router(dashboard_routes.router, prefix="/api")
app.include_router(crypto_routes.router, prefix="/api")
app.include_router(email_otp_routes.router, prefix="/api")
app.include_router(blockchain_routes.router, prefix="/api")
app.include_router(shared_routes.router, prefix="/api")