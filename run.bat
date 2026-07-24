@echo off
if not exist .venv (
    echo [ERROR] Virtual environment .venv not found. Please run setup.bat first.
    pause
    exit /b 1
)

echo Starting ThreatArchitect...
.venv\Scripts\python.exe -m app
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error code %errorlevel%.
    pause
)
