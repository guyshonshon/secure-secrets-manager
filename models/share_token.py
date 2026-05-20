"""One-time, expiring share tokens for secrets.

Only the SHA-256 hash of the token is stored in the database. The raw token is
returned to the caller exactly once at creation time. On redemption we hash the
provided token and compare; we then mark the row used so it cannot be reused.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from .db import db


class ShareToken(db.Model):
    __tablename__ = "share_tokens"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_id = db.Column(
        db.String(36), db.ForeignKey("secrets.id"), nullable=False, index=True
    )

    # SHA-256 of the raw token. 64 hex chars. Indexed for redemption lookups.
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)

    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    secret = db.relationship("Secret", back_populates="share_tokens")

    @staticmethod
    def hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        # SQLite returns naive datetimes; treat them as UTC.
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now >= expiry

    def is_used(self) -> bool:
        return self.used_at is not None
