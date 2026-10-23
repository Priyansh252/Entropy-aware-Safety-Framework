@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\activate.bat call setup.bat
call .venv\Scripts\activate.bat
python -m pytest backend\tests -v
