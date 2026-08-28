@echo off
echo ====================================================
echo Starting AI-Secure File Transfer System locally
echo ====================================================

echo [1/4] Setting up root dependencies...
call npm install concurrently --no-save >nul 2>&1

echo [2/4] Setting up Node.js Backend...
cd backend-node
if not exist node_modules (
    echo Installing backend-node dependencies...
    call npm install
)
cd ..

echo [3/4] Setting up Python Engine...
cd backend
if not exist venv (
    echo Creating virtual environment and installing dependencies...
    python -m venv venv
    call .\venv\Scripts\pip install -r requirements.txt
)
cd ..

echo [4/4] Setting up Frontend...
cd frontend
if not exist node_modules (
    echo Installing frontend dependencies...
    call npm install
)
cd ..

echo.
echo ====================================================
echo Starting all services (Python AI Engine, Node.js API, Frontend)...
echo ====================================================
call npx concurrently "cd backend-node && node server.js" "cd backend && .\venv\Scripts\uvicorn app.main:app --reload --port 8000" "cd frontend && npm run dev" --kill-others --names "Node-API,Python-AI,Frontend" --prefix-colors "blue,green,magenta"

pause
