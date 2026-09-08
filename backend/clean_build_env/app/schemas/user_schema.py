from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserListItem(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    mfa_enabled: bool
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReceiverItem(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    role: str
    company_name: str | None = None
    job_role: str | None = None

    model_config = {"from_attributes": True}


class UserCreateRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)
    role: str = Field(default="user", pattern="^(admin|user)$")

    @field_validator("password")
    @classmethod
    def strong_password(cls, value: str) -> str:
        if not any(ch.isalpha() for ch in value) or not any(ch.isdigit() for ch in value):
            raise ValueError("Password must contain both letters and numbers")
        return value


class UserUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    role: str | None = Field(default=None, pattern="^(admin|user)$")
