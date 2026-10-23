@echo off
REM Starts the backend (which also serves the prebuilt dashboard) and opens the browser.
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat call setup.bat
call .venv\Scripts\activate.bat
if not exist frontend\dist\index.html (
  echo Prebuilt frontend not found. Building it - requires Node.js 18+...
  pushd frontend && call npm install && call npm run build && popd
)
start "" http://127.0.0.1:5000
python backend\app.py
