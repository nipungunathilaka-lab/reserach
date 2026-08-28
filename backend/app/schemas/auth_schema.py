from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: str = "user"
    company_name: Optional[str] = None
    job_role: Optional[str] = None


class LoginResponse(BaseModel):
    requires_mfa: bool
    challenge_id: int
    message: str
    masked_email: str
    expires_in_minutes: int
    delivery_method: str
    dev_otp: str | None = None


class MfaVerifyRequest(BaseModel):
    challenge_id: int
    otp: str = Field(..., min_length=4, max_length=12)


class MfaResendRequest(BaseModel):
    challenge_id: int


class UserPublic(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    mfa_enabled: bool

    model_config = {"from_attributes": True}


class RegisterResponse(UserPublic):
    provisioning_uri: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic
