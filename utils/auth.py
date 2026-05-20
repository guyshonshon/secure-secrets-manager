"""Authentication helpers built on Flask-JWT-Extended.

We deliberately wrap ``jwt_required`` so route modules don't need to know which
JWT library backs auth — swapping it later (e.g. for sessions) only touches
this file.
"""

from __future__ import annotations

from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required

from models import User, db


def auth_required(fn):
    """Require a valid JWT and inject the matching User as kwarg ``current_user``.

    Returns a 401 if the JWT is valid but the user has since been deleted.
    """

    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity()
        user = db.session.get(User, identity) if identity else None
        if user is None:
            # Use a generic message — do not leak whether the identity is a known id.
            return jsonify({"error": "Unauthorized"}), 401
        kwargs["current_user"] = user
        return fn(*args, **kwargs)

    return wrapper
