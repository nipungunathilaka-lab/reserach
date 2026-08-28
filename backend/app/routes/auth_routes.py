from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.db import get_db
from app.database.models import User
from app.routes.dependencies import get_current_user
from app.schemas.auth_schema import LoginRequest, LoginResponse, MfaResendRequest, MfaVerifyRequest, TokenResponse, UserPublic, RegisterRequest, RegisterResponse
from app.services.auth_service import AuthService
import pyotp
from app.services.mfa_service import MfaService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _login_response(challenge, otp: str | None, delivery_method: str) -> LoginResponse:
    return LoginResponse(
        requires_mfa=True,
        challenge_id=challenge.id,
        dev_otp=None,
        masked_email=MfaService._mask_email(challenge.user.email),
        expires_in_minutes=settings.mfa_otp_expire_minutes,
        delivery_method=delivery_method,
        message="Password verified. Please enter the 6-digit code from your Authenticator app.",
    )


@router.post("/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    user = AuthService.create_user(
        db, 
        full_name=payload.full_name, 
        email=payload.email, 
        password=payload.password, 
        role=payload.role,
        company_name=payload.company_name,
        job_role=payload.job_role
    )
    
    provisioning_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name=settings.app_name
    )
    
    response = RegisterResponse.model_validate(user)
    response.provisioning_uri = provisioning_uri
    return response


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = AuthService.authenticate_user(db, payload.email, payload.password)
    challenge, otp, delivery_method = MfaService.create_challenge(db, user)
    return _login_response(challenge, otp, delivery_method)


@router.post("/verify-mfa", response_model=TokenResponse)
def verify_mfa(payload: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)):
    user = MfaService.verify_challenge(db, payload.challenge_id, payload.otp)
    client_ip = request.client.host if request.client else None
    AuthService.mark_login_success(db, user, client_ip=client_ip)
    token = AuthService.create_access_token(user)
    return TokenResponse(access_token=token, user=user)


@router.post("/resend-mfa", response_model=LoginResponse)
def resend_mfa(payload: MfaResendRequest, db: Session = Depends(get_db)):
    challenge, otp, delivery_method = MfaService.resend_challenge(db, payload.challenge_id)
    return _login_response(challenge, otp, delivery_method)


@router.get("/me", response_model=UserPublic)
def me(current_user: User = Depends(get_current_user)):
    return current_user
