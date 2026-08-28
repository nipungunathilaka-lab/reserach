from app.database.db import SessionLocal, init_db
from app.database.seed import seed_demo_data
from app.services.ai_service import AIService

if __name__ == "__main__":
    init_db()
    db = SessionLocal()
    try:
        seed_demo_data(db)
        AIService.train_model()
        print("Demo users and lab-generated ML dataset are ready.")
    finally:
        db.close()
