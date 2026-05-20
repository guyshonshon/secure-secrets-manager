"""User model.

Stores a unique email and a Werkzeug-hashed password. Plaintext passwords are
never persisted; helper methods wrap the hashing so callers do not touch the
hash directly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .db import db


class User(db.Model):
    __tablename__ = "users"

    # Public-facing id is a UUID so we never expose incremental row numbers.
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    secrets = db.relationship(
        "Secret", back_populates="owner", cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        # pbkdf2:sha256 is Werkzeug's strong default; explicit for clarity.
        self.password_hash = generate_password_hash(password, method="pbkdf2:sha256:600000")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        return {"id": self.id, "email": self.email}
