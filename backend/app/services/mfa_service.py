import hashlib
import hmac
import random
from datetime import datetime, timedelta

import pyotp
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.models import AIAlert, MfaChallenge, User
from app.services.email_service import EmailService
import logging

logger = logging.getLogger(__name__)

class MfaService:
    @staticmethod
    def _hash_otp(otp: str) -> str:
        return hmac.new(settings.secret_key.encode("utf-8"), otp.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _mask_email(email: str) -> str:
        local, _, domain = email.partition("@")
        if len(local) <= 2:
            masked_local = local[:1] + "*"
        else:
            masked_local = local[:2] + "*" * max(1, len(local) - 2)
        return f"{masked_local}@{domain}" if domain else masked_local

    @staticmethod
    def _record_mfa_alert(db: Session, user: User, failed_attempts: int) -> None:
        """Create an AI/security alert for suspicious login/MFA behaviour."""
        if failed_attempts < 3:
            return
        existing = (
            db.query(AIAlert)
            .filter(
                AIAlert.transfer_id.is_(None),
                AIAlert.user_id == user.id,
                AIAlert.reason.like("Repeated failed MFA%"),
            )
            .order_by(AIAlert.created_at.desc())
            .first()
        )
        if existing and (datetime.utcnow() - existing.created_at).total_seconds() < 300:
            return
        level = "high" if failed_attempts >= settings.mfa_max_attempts else "medium"
        score = 0.9 if level == "high" else 0.65
        db.add(
            AIAlert(
                transfer_id=None,
                user_id=user.id,
                level=level,
                reason=f"Repeated failed MFA attempts during login ({failed_attempts} failed attempt(s)).",
                score=score,
            )
        )

    @staticmethod
    def create_challenge(db: Session, user: User, resend_count: int = 0) -> tuple[MfaChallenge, str, str]:
        """Create a challenge to track the login attempt and expect a 6-digit email OTP."""
        db.query(MfaChallenge).filter(
            MfaChallenge.user_id == user.id,
            MfaChallenge.consumed_at.is_(None),
            MfaChallenge.expires_at > datetime.utcnow(),
        ).update({"consumed_at": datetime.utcnow()})

        now = datetime.utcnow()
        otp = f"{random.randint(0, 999999):06d}"
        
        # Log for local dev fallback
        print("\n" + "="*50)
        print(f" LOCAL DEV OTP FALLBACK")
        print(f" Email: {user.email}")
        print(f" OTP Code: {otp}")
        print("="*50 + "\n")
        
        challenge = MfaChallenge(
            user_id=user.id,
            otp_hash=MfaService._hash_otp(otp),
            expires_at=now + timedelta(minutes=settings.mfa_otp_expire_minutes),
            last_sent_at=now,
            resend_count=resend_count,
        )
        db.add(challenge)
        db.commit()
        db.refresh(challenge)
        
        try:
            EmailService.send_otp_email(user.email, otp)
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            
        return challenge, otp, "email"

    @staticmethod
    def resend_challenge(db: Session, challenge_id: int) -> tuple[MfaChallenge, str, str]:
        existing = db.query(MfaChallenge).filter(MfaChallenge.id == challenge_id).first()
        if not existing:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA challenge")
        if existing.consumed_at is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This MFA challenge is already closed. Start login again.")
        if existing.expires_at < datetime.utcnow():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA code expired. Start login again.")
        if existing.resend_count >= settings.mfa_max_resends:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Maximum MFA resend limit reached. Start login again.")
        if existing.last_sent_at:
            seconds_since = (datetime.utcnow() - existing.last_sent_at).total_seconds()
            if seconds_since < settings.mfa_resend_cooldown_seconds:
                wait = max(1, int(settings.mfa_resend_cooldown_seconds - seconds_since))
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=f"Please wait {wait} second(s) before resending the code.")
        next_resend_count = existing.resend_count + 1
        existing.resend_count = next_resend_count
        existing.consumed_at = datetime.utcnow()
        db.commit()
        return MfaService.create_challenge(db, existing.user, resend_count=next_resend_count)

    @staticmethod
    def verify_challenge(db: Session, challenge_id: int, otp: str) -> User:
        challenge = db.query(MfaChallenge).filter(MfaChallenge.id == challenge_id).first()
        if not challenge:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA challenge")
        if challenge.consumed_at is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA challenge already used or replaced")
        if challenge.expires_at < datetime.utcnow():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA code expired. Please request a new code.")
        if challenge.failed_attempts >= settings.mfa_max_attempts:
            challenge.consumed_at = datetime.utcnow()
            db.commit()
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many incorrect MFA attempts. Start login again.")

        submitted_otp = "".join(ch for ch in otp.strip() if ch.isdigit())
        
        if challenge.otp_hash != MfaService._hash_otp(submitted_otp):
            challenge.failed_attempts += 1
            MfaService._record_mfa_alert(db, challenge.user, challenge.failed_attempts)
            remaining = max(0, settings.mfa_max_attempts - challenge.failed_attempts)
            if remaining == 0:
                challenge.consumed_at = datetime.utcnow()
                db.commit()
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many incorrect MFA attempts. Start login again.")
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid MFA code. {remaining} attempt(s) remaining.")

        challenge.consumed_at = datetime.utcnow()
        db.commit()
        return challenge.user
