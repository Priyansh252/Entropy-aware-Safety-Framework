@echo off
REM Development mode: backend on :5000 and Vite dev server on :5173 (hot reload). Requires Node.js 18+.
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat call setup.bat
start "backend" cmd /k ".venv\Scripts\activate.bat && python backend\app.py"
pushd frontend
if not exist node_modules call npm install
start "" http://localhost:5173
call npm run dev
