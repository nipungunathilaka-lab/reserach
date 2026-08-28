import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Any
import jwt
import pyotp
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import AIAlert, User
from app.services.crypto_service import CryptoService

ALGORITHM = "HS256"


class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        salt = os.urandom(16)
        # Stronger iteration count than the initial prototype while keeping local demo speed acceptable.
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
        return f"pbkdf2_sha256${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            scheme, salt_b64, hash_b64 = password_hash.split("$", 2)
            if scheme != "pbkdf2_sha256":
                return False
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            # Support older seeded hashes created with 120k by re-seeding the DB is recommended.
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000)
            if hmac.compare_digest(actual, expected):
                return True
            legacy_actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
            return hmac.compare_digest(legacy_actual, expected)
        except Exception:
            return False

    @staticmethod
    def create_access_token(user: User) -> str:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
        payload: dict[str, Any] = {"sub": str(user.id), "email": user.email, "role": user.role, "exp": expire}
        return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        try:
            return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except jwt.PyJWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    @staticmethod
    def _record_login_alert(db: Session, user: User, reason: str, level: str, score: float) -> None:
        recent = (
            db.query(AIAlert)
            .filter(AIAlert.transfer_id.is_(None), AIAlert.user_id == user.id, AIAlert.reason.like("Suspicious login%"))
            .order_by(AIAlert.created_at.desc())
            .first()
        )
        if recent and (datetime.utcnow() - recent.created_at).total_seconds() < 180:
            return
        db.add(AIAlert(transfer_id=None, user_id=user.id, level=level, reason=reason, score=score))

    @staticmethod
    def _handle_failed_password(db: Session, user: User) -> None:
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= settings.auth_max_failed_logins:
            user.locked_until = datetime.utcnow() + timedelta(minutes=settings.auth_lockout_minutes)
            AuthService._record_login_alert(
                db,
                user,
                f"Suspicious login behaviour: account locked after {user.failed_login_attempts} failed password attempt(s).",
                "high",
                0.95,
            )
        elif user.failed_login_attempts >= 3:
            AuthService._record_login_alert(
                db,
                user,
                f"Suspicious login behaviour: {user.failed_login_attempts} failed password attempt(s).",
                "medium",
                0.7,
            )
        db.commit()

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> User:
        user = db.query(User).filter(User.email == email.lower()).first()
        generic_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
        if not user:
            raise generic_error

        now = datetime.utcnow()
        if user.locked_until and user.locked_until > now:
            minutes = max(1, int((user.locked_until - now).total_seconds() // 60) + 1)
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Account temporarily locked. Try again in about {minutes} minute(s).")

        if not AuthService.verify_password(password, user.password_hash):
            AuthService._handle_failed_password(db, user)
            raise generic_error
        return user

    @staticmethod
    def mark_login_success(db: Session, user: User, client_ip: str | None = None) -> None:
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = client_ip
        db.commit()

    @staticmethod
    def create_user(db: Session, full_name: str, email: str, password: str, role: str = "user", company_name: str | None = None, job_role: str | None = None) -> User:
        existing = db.query(User).filter(User.email == email.lower()).first()
        if existing:
            CryptoService.ensure_user_keypair(existing.id)
            return existing
        user = User(
            full_name=full_name,
            email=email.lower(),
            password_hash=AuthService.hash_password(password),
            role=role,
            company_name=company_name,
            job_role=job_role,
            mfa_enabled=True,
            totp_secret=pyotp.random_base32(),
        )
        db.add(user)
        db.flush()
        CryptoService.ensure_user_keypair(user.id)
        db.commit()
        db.refresh(user)
        return user
