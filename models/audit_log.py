"""Append-only audit log.

Stores who did what, when, and from where. Never stores secret values, raw
share tokens, JWTs, or passwords. The ``event`` column is a short stable
identifier — see utils.audit for the canonical list.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .db import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event = db.Column(db.String(64), nullable=False, index=True)
    user_id = db.Column(db.String(36), nullable=True, index=True)
    secret_id = db.Column(db.String(36), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    # Optional structured detail. Must never contain sensitive material.
    detail = db.Column(db.String(500), nullable=True)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
