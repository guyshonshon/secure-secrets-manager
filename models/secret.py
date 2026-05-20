"""Secret metadata model.

The encrypted ciphertext lives in a file on disk (see utils.encryption).
The DB only stores metadata: a UUID id, owner, name, description, tags, and
the path to the ciphertext file. The plaintext value is *never* persisted in
the database.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from .db import db


class Secret(db.Model):
    __tablename__ = "secrets"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(
        db.String(36), db.ForeignKey("users.id"), nullable=False, index=True
    )

    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    # Tags stored as a JSON-serialised list to stay portable across SQLite/Postgres.
    tags_json = db.Column(db.String(500), nullable=False, default="[]")

    # Path to the ciphertext file on disk. Filename is derived from the UUID id
    # so untrusted user input never participates in the path.
    ciphertext_path = db.Column(db.String(500), nullable=False)

    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    owner = db.relationship("User", back_populates="secrets")
    share_tokens = db.relationship(
        "ShareToken", back_populates="secret", cascade="all, delete-orphan"
    )

    @property
    def tags(self) -> list[str]:
        try:
            value = json.loads(self.tags_json or "[]")
            return value if isinstance(value, list) else []
        except (ValueError, TypeError):
            return []

    @tags.setter
    def tags(self, values: list[str] | None) -> None:
        self.tags_json = json.dumps(list(values or []))

    def to_metadata(self) -> dict:
        """Serialise for API responses. Never includes the secret value."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
