import os
from sqlalchemy import inspect
from app.database.db import engine, Base
from app.database import models

def run_migration():
    print("Running PQC Migration...")
    
    # Create all tables (this will create pqc_keys if it doesn't exist)
    Base.metadata.create_all(bind=engine)
    
    # Verify the table exists
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    
    if "pqc_keys" not in tables:
        print("FAIL: pqc_keys table was not created.")
        exit(1)
        
    print("SUCCESS: pqc_keys table exists.")
    
    # Verify columns
    columns = [col['name'] for col in inspector.get_columns("pqc_keys")]
    required_columns = [
        "id", "user_id", "algorithm", "key_version", "public_key", 
        "encrypted_private_key", "private_key_nonce", "is_active"
    ]
    
    for req in required_columns:
        if req not in columns:
            print(f"FAIL: Column {req} is missing in pqc_keys table.")
            exit(1)
            
    print("SUCCESS: All required columns exist.")
    
    print("Migration verification complete.")

if __name__ == "__main__":
    run_migration()
