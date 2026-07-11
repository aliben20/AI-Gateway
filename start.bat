@echo off
cd /d "%~dp0"
echo Installing dependencies...
pip install -r requirements.txt
echo Starting server...
python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
pause
