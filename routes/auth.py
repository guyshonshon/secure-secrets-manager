"""Authentication routes: /register and /login.

Both endpoints are tightly rate-limited because they are the most common
brute-force targets. Login failures and successes are audited. Passwords are
hashed by the User model — they never reach this module's logs.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token

from models import User, db
from utils import audit
from utils.rate_limit import limiter
from utils.validation import require_json, validate_email, validate_password

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/register")
@limiter.limit("5 per minute; 20 per hour")
def register():
    body, err = require_json(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    email, err = validate_email(body.get("email"))
    if err:
        return jsonify({"error": err}), 400
    password, err = validate_password(body.get("password"))
    if err:
        return jsonify({"error": err}), 400

    if User.query.filter_by(email=email).first() is not None:
        # Generic message to avoid user-enumeration.
        return jsonify({"error": "Registration failed"}), 409

    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    audit.record_event(audit.EVENT_USER_REGISTERED, user_id=user.id)
    return jsonify({"message": "User registered successfully", "id": user.id}), 201


@auth_bp.post("/login")
@limiter.limit("10 per minute; 100 per hour")
def login():
    body, err = require_json(request.get_json(silent=True))
    if err:
        return jsonify({"error": err}), 400

    email, err = validate_email(body.get("email"))
    if err:
        # Same generic error as a bad password to prevent enumeration.
        audit.record_event(audit.EVENT_LOGIN_FAILED, detail="invalid_email_format")
        return jsonify({"error": "Invalid credentials"}), 401

    password = body.get("password")
    if not isinstance(password, str):
        audit.record_event(audit.EVENT_LOGIN_FAILED, detail="missing_password")
        return jsonify({"error": "Invalid credentials"}), 401

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        audit.record_event(
            audit.EVENT_LOGIN_FAILED,
            user_id=(user.id if user else None),
            detail="bad_credentials",
        )
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_access_token(identity=user.id)
    audit.record_event(audit.EVENT_LOGIN_SUCCESS, user_id=user.id)
    return jsonify({"access_token": token}), 200
