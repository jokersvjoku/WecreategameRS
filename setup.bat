@echo off
echo ============================================
echo   PATCHPILOT — Local Development Setup
echo ============================================
echo.

REM --- Backend ---
echo [1/4] Setting up Python virtual environment...
cd backend
python -m venv venv
call venv\Scripts\activate
echo [2/4] Installing backend dependencies...
pip install -r requirements.txt -q
echo Backend dependencies installed.
cd ..

REM --- Frontend ---
echo [3/4] Installing frontend dependencies...
cd frontend
where pnpm >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    pnpm install
) else (
    npm install
)
cd ..

REM --- Env file ---
echo [4/4] Creating .env file from example...
if not exist .env (
    copy .env.example .env
    echo .env created — edit it to add your Gemma 4 credentials.
) else (
    echo .env already exists.
)

echo.
echo ============================================
echo   Setup complete!
echo   Run: start.bat  to launch PATCHPILOT
echo ============================================
