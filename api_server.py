import uvicorn
import os
import sys

# Ensure the 'backend' directory is in the Python path so 'app' can be imported correctly
backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.append(backend_dir)

if __name__ == "__main__":
    print("Starting full FastAPI Backend...")
    # Run the actual FastAPI app located in backend/app/main.py
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True, app_dir=backend_dir)