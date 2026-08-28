"""Backend smoke/regression test.

Run from backend folder after installing requirements:
    python smoke_test.py

It uses a temporary SQLite database and checks:
- password + OTP MFA
- repeated wrong MFA code alerting
- admin user management
- encrypted transfer
- AI alert generation
- receiver decrypt/download
- blockchain verification and tamper detection
"""

import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./smoke_test_secure_file_transfer.db"
os.environ["SEED_DEMO_USERS"] = "true"
os.environ["DEV_SHOW_OTP"] = "true"
os.environ["MAX_UPLOAD_SIZE_MB"] = "50"
os.environ["RATE_LIMIT_ENABLED"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from app.database.db import SessionLocal  # noqa: E402
from app.database.models import Transfer  # noqa: E402
from app.main import app  # noqa: E402


def login_with_mfa(client: TestClient, email: str, password: str) -> dict[str, str]:
    login = client.post("/api/auth/login", json={"email": email, "password": password})
    login.raise_for_status()
    login_data = login.json()
    verify = client.post(
        "/api/auth/verify-mfa",
        json={"challenge_id": login_data["challenge_id"], "otp": login_data["dev_otp"]},
    )
    verify.raise_for_status()
    return {"Authorization": f"Bearer {verify.json()['access_token']}"}


def main() -> None:
    db_path = Path("smoke_test_secure_file_transfer.db")
    if db_path.exists():
        db_path.unlink()

    with TestClient(app) as client:
        # MFA failure pattern should create a login/MFA AI alert after repeated wrong codes.
        failed_login = client.post("/api/auth/login", json={"email": "alice@secureft.com", "password": "user12345"})
        failed_login.raise_for_status()
        challenge_id = failed_login.json()["challenge_id"]
        for _ in range(3):
            client.post("/api/auth/verify-mfa", json={"challenge_id": challenge_id, "otp": "000000"})

        admin_headers = login_with_mfa(client, "admin@secureft.com", "admin12345")

        alerts = client.get("/api/logs/ai-alerts", headers=admin_headers)
        alerts.raise_for_status()
        assert any(alert["transfer_id"] is None for alert in alerts.json()), "Expected MFA/login-pattern AI alert"

        create_user = client.post(
            "/api/users",
            json={"full_name": "Smoke Test User", "email": "smoketest@secureft.com", "password": "password12345", "role": "user"},
            headers=admin_headers,
        )
        create_user.raise_for_status()
        receiver_id = create_user.json()["id"]

        # A >10 MB file should trigger the prototype's large-file AI rule but remain below the 50 MB upload limit.
        risky_file = b"A" * (11 * 1024 * 1024)
        send = client.post(
            "/api/files/send",
            data={"receiver_id": str(receiver_id)},
            files={"file": ("large_smoke.bin", risky_file, "application/octet-stream")},
            headers=admin_headers,
        )
        send.raise_for_status()
        transfer_id = send.json()["transfer"]["id"]
        assert send.json()["ai"]["is_anomaly"] is True, "Expected large-file AI anomaly"

        receiver_headers = login_with_mfa(client, "smoketest@secureft.com", "password12345")
        download = client.get(f"/api/files/{transfer_id}/download", headers=receiver_headers)
        download.raise_for_status()
        assert download.content == risky_file, "Downloaded plaintext does not match original file"

        verify_chain = client.get("/api/logs/blockchain/verify", headers=admin_headers)
        verify_chain.raise_for_status()
        assert verify_chain.json()["valid"] is True

        # Tamper detection: change protected transfer data and verify chain fails.
        db = SessionLocal()
        try:
            transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
            transfer.original_hash = "0" * 64
            db.commit()
        finally:
            db.close()

        tampered_chain = client.get("/api/logs/blockchain/verify", headers=admin_headers)
        tampered_chain.raise_for_status()
        assert tampered_chain.json()["valid"] is False, "Expected blockchain verification to catch tampering"

    print("Smoke test passed: MFA + MFA alert + user management + encrypted transfer + AI + download + blockchain/tamper checks worked.")


if __name__ == "__main__":
    main()
