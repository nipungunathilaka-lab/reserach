"""Quickly test the configured AI model against sample normal and risky inputs.

Run from backend folder:
    python -m app.scripts.check_ai_model
"""

from app.services.ai_service import AIService

samples = [
    {"name": "normal office transfer", "file_size_mb": 2.5, "hour_of_day": 10, "transfers_last_hour": 1, "mfa_failed_attempts": 0, "failed_login_attempts": 0, "file_name": "report.pdf"},
    {"name": "large file", "file_size_mb": 180, "hour_of_day": 11, "transfers_last_hour": 1, "mfa_failed_attempts": 0, "failed_login_attempts": 0, "file_name": "backup.zip"},
    {"name": "midnight transfer", "file_size_mb": 4, "hour_of_day": 2, "transfers_last_hour": 1, "mfa_failed_attempts": 0, "failed_login_attempts": 0, "file_name": "notes.docx"},
    {"name": "many transfers after MFA failures", "file_size_mb": 3, "hour_of_day": 14, "transfers_last_hour": 12, "mfa_failed_attempts": 4, "failed_login_attempts": 0, "file_name": "client.xlsx"},
    {"name": "high-risk script", "file_size_mb": 0.2, "hour_of_day": 13, "transfers_last_hour": 1, "mfa_failed_attempts": 0, "failed_login_attempts": 0, "file_name": "payload.ps1"},
    {"name": "archive after failed auth", "file_size_mb": 6, "hour_of_day": 15, "transfers_last_hour": 2, "mfa_failed_attempts": 2, "failed_login_attempts": 2, "file_name": "data.zip"},
]

AIService.train_model()
for sample in samples:
    name = sample.pop("name")
    print(name, "=>", AIService.analyze_transfer(**sample))
