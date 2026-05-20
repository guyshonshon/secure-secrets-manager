"""Anonymous share-token redemption.

A single GET endpoint that exchanges a raw token for the decrypted secret,
exactly once. Expired or already-used tokens return a generic 404 so the
caller cannot distinguish "wrong token" from "expired token" from "missing
secret" — that's the OWASP-friendly behaviour.
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

from models import ShareToken, db
from utils import audit
from utils.encryption import EncryptionError, load_and_decrypt
from utils.rate_limit import limiter

share_bp = Blueprint("share", __name__)


@share_bp.get("/share/<string:token>")
@limiter.limit("10 per minute; 60 per hour")
def access_share(token: str):
    # Hash first so we never run a query by raw token (and timing of failure
    # paths is comparable).
    token_hash = ShareToken.hash_token(token or "")
    row = ShareToken.query.filter_by(token_hash=token_hash).first()

    if row is None or row.is_used() or row.is_expired():
        audit.record_event(
            audit.EVENT_SHARE_EXPIRED_OR_INVALID,
            secret_id=(row.secret_id if row else None),
        )
        return jsonify({"error": "Share link is invalid or has expired"}), 404

    try:
        plaintext = load_and_decrypt(row.secret_id)
    except EncryptionError as exc:
        current_app.logger.error("Share decryption failed: %s", exc)
        return jsonify({"error": "Share link is invalid or has expired"}), 404

    # Mark used *before* returning so a crash mid-response still burns the token.
    row.used_at = datetime.now(timezone.utc)
    db.session.commit()

    audit.record_event(audit.EVENT_SHARE_ACCESSED, secret_id=row.secret_id)
    return (
        jsonify(
            {
                "name": row.secret.name,
                "description": row.secret.description,
                "value": plaintext,
            }
        ),
        200,
    )
