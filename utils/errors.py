"""JSON error handlers.

Every public endpoint returns JSON. We install global handlers so an unhandled
exception, a missing route, or a malformed request body all surface as
consistent ``{"error": "..."}`` payloads — and so that stack traces are never
leaked to the client in production.
"""

from __future__ import annotations

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def _bad_request(err):  # pragma: no cover - thin wrapper
        return jsonify({"error": getattr(err, "description", "Bad request")}), 400

    @app.errorhandler(401)
    def _unauthorized(err):  # pragma: no cover
        return jsonify({"error": "Unauthorized"}), 401

    @app.errorhandler(403)
    def _forbidden(err):  # pragma: no cover
        return jsonify({"error": "Forbidden"}), 403

    @app.errorhandler(404)
    def _not_found(err):  # pragma: no cover
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def _method_not_allowed(err):  # pragma: no cover
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(413)
    def _too_large(err):  # pragma: no cover
        return jsonify({"error": "Request body too large"}), 413

    @app.errorhandler(429)
    def _rate_limited(err):
        # Flask-Limiter raises a 429 HTTPException with a description like
        # "5 per 1 minute"; surface a generic message and don't leak details.
        return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429

    @app.errorhandler(HTTPException)
    def _http_exc(err):
        return jsonify({"error": err.description or err.name}), err.code or 500

    @app.errorhandler(Exception)
    def _unhandled(err):
        # Log internally (without the request body) and return a generic message.
        logger.exception("Unhandled exception")
        return jsonify({"error": "Internal server error"}), 500
