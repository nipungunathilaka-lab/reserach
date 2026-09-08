from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

BASE_DIR = Path(__file__).resolve().parents[1]
STORAGE_DIR = BASE_DIR / "storage"
UPLOAD_DIR = STORAGE_DIR / "uploads"
ENCRYPTED_DIR = STORAGE_DIR / "encrypted"
DECRYPTED_DIR = STORAGE_DIR / "decrypted"
KEYS_DIR = STORAGE_DIR / "keys"
MAILBOX_DIR = STORAGE_DIR / "mailbox"
ML_DIR = BASE_DIR / "ml"


def ensure_storage_dirs() -> None:
    for directory in [UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR, KEYS_DIR, MAILBOX_DIR, ML_DIR]:
        directory.mkdir(parents=True, exist_ok=True)


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()


def init_db() -> None:
    from app.database import models  # noqa: F401
    ensure_storage_dirs()
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
