"""Flask application factory. Run:  python backend/app.py   (or: python -m backend.app)"""
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, send_from_directory  # noqa: E402
from flask_cors import CORS  # noqa: E402

from backend import config  # noqa: E402
from backend.routes.api import ApiError, bp  # noqa: E402
from backend.storage import db  # noqa: E402

log = logging.getLogger("eaf")
DIST = config.ROOT / "frontend" / "dist"


def create_app():
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
    CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}})
    db.init_db()
    app.register_blueprint(bp)

    @app.errorhandler(ApiError)
    def _api_error(e):
        return jsonify({"ok": False, "error": {"code": e.code, "message": e.message}}), e.status

    @app.errorhandler(404)
    def _nf(_):
        return jsonify({"ok": False, "error": {"code": "not_found", "message": "Resource not found"}}), 404

    @app.errorhandler(405)
    def _mna(_):
        return jsonify({"ok": False, "error": {"code": "method_not_allowed", "message": "Method not allowed"}}), 405

    @app.errorhandler(413)
    def _big(_):
        return jsonify({"ok": False, "error": {"code": "too_large", "message": "Request too large"}}), 413

    @app.errorhandler(Exception)
    def _ex(e):
        log.exception("unhandled error")   # details stay in the server log only
        return jsonify({"ok": False, "error": {"code": "internal_error", "message": "Internal error; the operation failed safely."}}), 500

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def spa(path):
        if path == "api" or path.startswith("api/"):
            return jsonify({"ok": False, "error": {"code": "not_found", "message": "Resource not found"}}), 404
        if DIST.exists():
            f = DIST / path
            if path and f.is_file():
                return send_from_directory(DIST, path)
            return send_from_directory(DIST, "index.html")
        return jsonify({"ok": True, "data": {"message": "API running. Frontend build not found; run the Vite dev server (npm run dev) or build it (npm run build)."}})
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("EAF_PORT", "5000"))
    print(f"Entropy-Aware Safety Framework API on http://127.0.0.1:{port}")
    create_app().run(host="127.0.0.1", port=port, debug=False, threaded=True)
