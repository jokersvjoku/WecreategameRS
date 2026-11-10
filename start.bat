@echo off
echo ============================================
echo   PATCHPILOT - Starting Services
echo ============================================
echo.

REM Check if frontend node_modules exists
if not exist "frontend\node_modules" (
    echo [!] Frontend dependencies not found. Installing first...
    cd frontend
    call npm install
    cd ..
)

echo Starting backend on http://localhost:8000 ...
start "PATCHPILOT Backend (FastAPI)" cmd /k "cd /d %~dp0backend && venv\Scripts\activate && python -m uvicorn app.main:app --reload --port 8000"

timeout /t 3 /nobreak >nul

echo Starting frontend on http://localhost:3000 ...
start "PATCHPILOT Frontend (Next.js)" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ============================================
echo   PATCHPILOT is launching!
echo.
echo   - App UI:   http://localhost:3000
echo   - API Docs: http://localhost:8000/docs
echo   - Health:   http://localhost:8000/api/health
echo ============================================
echo.
echo Two windows have opened (Backend and Frontend).
echo Leave them open while testing the application.
