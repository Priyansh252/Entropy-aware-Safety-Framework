@echo off
REM One-time setup: creates .venv and installs Python dependencies.
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
if not exist .venv (
  echo Creating virtual environment...
  %PY% -m venv .venv || (echo Python 3.11+ is required. Install from python.org and re-run. & exit /b 1)
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip >nul
python -m pip install -r requirements-dev.txt || (echo Dependency installation failed. & exit /b 1)
echo Setup complete.
