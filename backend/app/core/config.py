from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI-Enhanced Secure File Transfer System"
    environment: str = "development"
    database_url: str = "sqlite:///./secure_file_transfer.db"
    secret_key: str = "change-this-secret-key-before-real-use"
    access_token_expire_minutes: int = 1440
    max_upload_size_mb: int = 50000

    # Authentication hardening.
    auth_max_failed_logins: int = 5
    auth_lockout_minutes: int = 15

    # Lightweight API rate limiting. This is in-memory and suitable for local/prototype hardening.
    rate_limit_enabled: bool = True
    rate_limit_window_seconds: int = 60
    rate_limit_general_requests: int = 180
    rate_limit_auth_requests: int = 15
    rate_limit_upload_requests: int = 20

    # MFA settings. OTP is never returned to the frontend by default.
    mfa_otp_expire_minutes: int = 5
    mfa_max_attempts: int = 5
    mfa_resend_cooldown_seconds: int = 60
    mfa_max_resends: int = 3
    dev_show_otp: bool = False

    # AI anomaly detection settings. Use AI_DATASET_PATH=real_transfer_dataset.csv after exporting enough real logs.
    ai_dataset_path: str = "lab_secure_transfer_dataset.csv"
    ai_contamination: float = 0.15
    ai_min_training_rows: int = 50
    ai_large_file_mb: float = 10.0
    ai_high_risk_file_extensions: str = "exe,bat,cmd,ps1,js,vbs,jar,msi,zip,rar,7z"

    # Demo seed data.
    seed_demo_users: bool = True

    # Frontend / CORS.
    frontend_origin: str = "http://localhost:5173"

    mail_username: str | None = None
    mail_password: str | None = None
    mail_from: str = "no-reply@secureft.com"
    mail_port: int = 465
    mail_server: str | None = None
    mail_from_name: str = "SecureFT Team"
    mail_starttls: bool = False
    mail_ssl_tls: bool = True
    use_credentials: bool = True
    validate_certs: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
