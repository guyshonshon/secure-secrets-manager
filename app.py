"""Flask application factory.

Run directly with ``python app.py`` for a quick local server, or import
``create_app`` from elsewhere (e.g. ``flask --app app run``, Gunicorn,
pytest fixtures).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

from config import get_config
from models import db
from routes import auth_bp, secrets_bp, share_bp
from utils.errors import register_error_handlers
from utils.rate_limit import limiter

migrate = Migrate()
jwt = JWTManager()


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)
    config_cls = get_config(config_name)
    app.config.from_object(config_cls)

    # Ensure the instance folder (for SQLite) and secret storage dir exist.
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["SECRET_STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)

    # Structured logging at INFO; never log request bodies.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    if app.config.get("RATELIMIT_ENABLED", True) is False:
        # Tests opt out of global limits via config; honour that.
        limiter.enabled = False
    limiter.init_app(app)

    # Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(secrets_bp)
    app.register_blueprint(share_bp)

    register_error_handlers(app)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    return app


# Convenience entrypoint: `python app.py`
if __name__ == "__main__":  # pragma: no cover
    application = create_app()
    # Bind to localhost only by default; do NOT expose to 0.0.0.0 without TLS.
    application.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
