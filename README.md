# From Weak Randomness to Adaptive Cryptography
### An Entropy-Aware Framework for Preventing ECDSA and RSA Key Compromise

A local, research-oriented project: an entropy-aware **safety layer** that validates cryptographic candidates before use, with real, mathematically correct ECDSA nonce-reuse and RSA shared-prime laboratories, an adaptive configuration selector, reproducible experiments, an SQLite audit trail and a React dashboard.

> Research prototype. Educational key sizes, locally generated test keys only, simulated fault models. Not formally verified or certified. See `docs/LIMITATIONS.md`.

## Requirements
* Windows 10/11 (also works on Linux/macOS), **Python 3.11 or newer** (tested on 3.12), added to PATH
* Node.js 18+ is **optional**: the dashboard is shipped prebuilt in `frontend/dist` and served by the backend. Node is only needed to modify the UI.
* No API keys, accounts or internet access at run time (internet is needed once to install dependencies).

## Run on Windows (simplest)
Double-click, or from a terminal in the project folder:
```
setup.bat          :: one time: creates .venv and installs dependencies
run_project.bat    :: starts the app and opens http://127.0.0.1:5000
run_tests.bat      :: runs the automated test suite
```
Manual equivalent (PowerShell):
```
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python backend\app.py          # open http://127.0.0.1:5000
python -m pytest backend\tests -v
```
Development mode with hot reload (needs Node): `run_dev.bat`, or
```
python backend\app.py                      # terminal 1, port 5000
cd frontend && npm install && npm run dev  # terminal 2, open http://localhost:5173
```
Rebuild the shipped UI after editing it: `cd frontend && npm install && npm run build`.

Linux/macOS: `./run_project.sh`, `./run_tests.sh`.

## Where things are
`PROJECT_GUIDE.md` (full walkthrough, 5-10 minute faculty demo, likely questions), `docs/` (architecture, methodology and mathematics, risk model, limitations, sample report, directory tree), `backend/`, `frontend/`, `config/sample_experiments/`, `scripts/make_report.py`.

## API quick test
```
curl http://127.0.0.1:5000/api/health
curl -X POST http://127.0.0.1:5000/api/entropy/assess -H "Content-Type: application/json" -d "{\"kind\":\"constant\",\"size\":256}"
curl -X POST http://127.0.0.1:5000/api/ecdsa/session
curl -X POST http://127.0.0.1:5000/api/ecdsa/reuse   -H "Content-Type: application/json" -d "{\"session_id\":\"<id>\"}"
curl -X POST http://127.0.0.1:5000/api/ecdsa/recover -H "Content-Type: application/json" -d "{\"session_id\":\"<id>\"}"
curl -X POST http://127.0.0.1:5000/api/safety/defense-demo -H "Content-Type: application/json" -d "{\"target\":\"ecdsa\"}"
curl -X POST http://127.0.0.1:5000/api/experiments/run -H "Content-Type: application/json" -d @config/sample_experiments/quick_demo.json
```
(PowerShell: use `curl.exe` and single-quoted JSON, or `Invoke-RestMethod`.)

## Configuration
`.env.example` lists optional environment variables (`EAF_PORT`, `EAF_DATA_DIR`, `EAF_DB_PATH`). Risk weights and thresholds: `backend/config.py`.
