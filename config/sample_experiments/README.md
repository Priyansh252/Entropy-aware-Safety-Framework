Run a sample configuration against a running backend (PowerShell / curl):

    curl -X POST http://127.0.0.1:5000/api/experiments/run -H "Content-Type: application/json" -d @config/sample_experiments/quick_demo.json

Then poll `/api/experiments/status/<experiment_id>` and download results from `/api/experiments/<id>/export?format=csv|json`.
