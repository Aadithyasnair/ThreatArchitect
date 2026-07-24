@echo off
echo ===================================================
echo ThreatArchitect - Python Virtual Environment Setup
echo ===================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.12+.
    exit /b 1
)

:: Create virtual environment if it doesn't exist
if not exist .venv (
    echo Creating virtual environment in .venv...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
) else (
    echo Virtual environment .venv already exists. Skipping creation.
)

:: Upgrade pip and install requirements
echo.
echo Installing dependencies from requirements.txt...
.venv\Scripts\python.exe -m pip install --default-timeout=100 --upgrade pip
if %errorlevel% neq 0 (
    echo [WARNING] Failed to upgrade pip. Proceeding with dependency installation...
)

.venv\Scripts\pip.exe install --default-timeout=100 -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Check connection and try again.
    exit /b 1
)

echo.
echo ===================================================
echo Setup completed successfully!
echo Use run.bat to start the ThreatArchitect agent.
echo ===================================================
pause
