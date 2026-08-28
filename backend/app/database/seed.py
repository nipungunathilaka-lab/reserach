from sqlalchemy.orm import Session
from app.services.auth_service import AuthService
from app.services.ai_service import AIService


def seed_demo_data(db: Session) -> None:
    AuthService.create_user(db, "SecureFT Admin", "admin@secureft.com", "admin12345", "admin")
    AuthService.create_user(db, "Alice Perera", "alice@secureft.com", "user12345", "user")
    AuthService.create_user(db, "Bob Fernando", "bob@secureft.com", "user12345", "user")
    AIService.generate_lab_dataset(600)
