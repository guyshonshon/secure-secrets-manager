"""Secrets CRUD + share-link creation.

Every endpoint in this module requires a valid JWT, and every read/write
enforces ownership: a user can only see or mutate their own secrets. The
encrypted value lives in a file on disk; we never persist plaintext to the DB.
"""

from __future__ import annotations

import secrets as pysecrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, url_for

from models import Secret, ShareToken, db
from utils import audit
from utils.auth import auth_required
from utils.encryption import (
    EncryptionError,
    delete_ciphertext,
    encrypt_and_store,
    load_and_decrypt,
)
from utils.rate_limit import limiter
from utils.validation import (
    require_json,
    validate_description,
    validate_name,
    validate_secret_value,
    validate_tags,
)

secrets_bp = Blueprint("secrets", __name__)


def _owned_secret_or_404(user_id: str, secret_id: str) -> Secret | None:
    """Lookup a secret if and only if it belongs to ``user_id``.

    Returning ``None`` for both "not found" and "wrong owner" avoids leaking
    existence of other users' secret ids.
    """
    return Secret.query.filter_by(id=secret_id, user_id=user_id).first()


@secrets_bp.post("/secrets")
@limiter.limit("60 per minute")
@auth_required
def create_secret(current_user):
    body, err = require_json(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    name, err = validate_name(body.get("name"))
    if err:
        return jsonify({"error": err}), 400
    value, err = validate_secret_value(body.get("value"))
    if err:
        return jsonify({"error": err}), 400
    description, err = validate_description(body.get("description"))
    if err:
        return jsonify({"error": err}), 400
    tags, err = validate_tags(body.get("tags"))
    if err:
        return jsonify({"error": err}), 400

    secret = Secret(
        user_id=current_user.id,
        name=name,
        description=description,
        ciphertext_path="",  # filled in once we know the id
    )
    secret.tags = tags
    db.session.add(secret)
    db.session.flush()  # assigns secret.id without committing

    try:
        secret.ciphertext_path = encrypt_and_store(secret.id, value)
    except EncryptionError as exc:
        db.session.rollback()
        current_app.logger.error("Encryption failed: %s", exc)
        return jsonify({"error": "Could not store secret"}), 500

    db.session.commit()
    audit.record_event(
        audit.EVENT_SECRET_CREATED, user_id=current_user.id, secret_id=secret.id
    )
    return jsonify(secret.to_metadata()), 201


@secrets_bp.get("/secrets")
@limiter.limit("120 per minute")
@auth_required
def list_secrets(current_user):
    rows = (
        Secret.query.filter_by(user_id=current_user.id)
        .order_by(Secret.created_at.desc())
        .all()
    )
    audit.record_event(audit.EVENT_SECRET_LISTED, user_id=current_user.id)
    return jsonify({"secrets": [s.to_metadata() for s in rows]}), 200


@secrets_bp.get("/secrets/<string:secret_id>")
@limiter.limit("60 per minute")
@auth_required
def get_secret(current_user, secret_id: str):
    secret = _owned_secret_or_404(current_user.id, secret_id)
    if secret is None:
        return jsonify({"error": "Not found"}), 404

    try:
        plaintext = load_and_decrypt(secret.id)
    except EncryptionError as exc:
        current_app.logger.error("Decryption failed for secret %s: %s", secret.id, exc)
        return jsonify({"error": "Could not retrieve secret"}), 500

    audit.record_event(
        audit.EVENT_SECRET_RETRIEVED, user_id=current_user.id, secret_id=secret.id
    )
    payload = secret.to_metadata()
    payload["value"] = plaintext
    return jsonify(payload), 200


@secrets_bp.put("/secrets/<string:secret_id>")
@limiter.limit("60 per minute")
@auth_required
def update_secret(current_user, secret_id: str):
    """Update *metadata only*. The encrypted value is intentionally immutable
    through this endpoint — rotating the value would require a different
    operation with its own audit semantics.
    """
    secret = _owned_secret_or_404(current_user.id, secret_id)
    if secret is None:
        return jsonify({"error": "Not found"}), 404

    body, err = require_json(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    if "name" in body:
        name, err = validate_name(body["name"])
        if err:
            return jsonify({"error": err}), 400
        secret.name = name
    if "description" in body:
        description, err = validate_description(body["description"])
        if err:
            return jsonify({"error": err}), 400
        secret.description = description
    if "tags" in body:
        tags, err = validate_tags(body["tags"])
        if err:
            return jsonify({"error": err}), 400
        secret.tags = tags

    db.session.commit()
    audit.record_event(
        audit.EVENT_SECRET_UPDATED, user_id=current_user.id, secret_id=secret.id
    )
    return jsonify(secret.to_metadata()), 200


@secrets_bp.delete("/secrets/<string:secret_id>")
@limiter.limit("60 per minute")
@auth_required
def delete_secret(current_user, secret_id: str):
    secret = _owned_secret_or_404(current_user.id, secret_id)
    if secret is None:
        return jsonify({"error": "Not found"}), 404

    db.session.delete(secret)
    db.session.commit()
    delete_ciphertext(secret_id)  # best-effort; missing file is fine

    audit.record_event(
        audit.EVENT_SECRET_DELETED, user_id=current_user.id, secret_id=secret_id
    )
    return jsonify({"message": "Secret deleted"}), 200


@secrets_bp.post("/secrets/<string:secret_id>/share")
@limiter.limit("10 per minute; 100 per hour")
@auth_required
def share_secret(current_user, secret_id: str):
    secret = _owned_secret_or_404(current_user.id, secret_id)
    if secret is None:
        return jsonify({"error": "Not found"}), 404

    ttl = current_app.config.get("SHARE_TOKEN_TTL_SECONDS", 3600)
    raw_token = pysecrets.token_urlsafe(48)  # cryptographically random
    token = ShareToken(
        secret_id=secret.id,
        token_hash=ShareToken.hash_token(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
    )
    db.session.add(token)
    db.session.commit()

    audit.record_event(
        audit.EVENT_SHARE_CREATED, user_id=current_user.id, secret_id=secret.id
    )

    # We return the raw token exactly once. The DB only stores the hash.
    share_url = url_for("share.access_share", token=raw_token, _external=True)
    return (
        jsonify(
            {
                "share_url": share_url,
                "token": raw_token,
                "expires_at": token.expires_at.replace(tzinfo=timezone.utc).isoformat(),
            }
        ),
        201,
    )
