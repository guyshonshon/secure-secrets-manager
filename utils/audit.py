"""Audit helper.

Single entry point ``record_event`` writes a row to the ``audit_logs`` table.
Callers pass only non-sensitive metadata; this module never inspects the
request body, never reads the secret value, and never sees raw tokens.
"""

from __future__ import annotations

import logging

from flask import has_request_context, request

from models import AuditLog, db

logger = logging.getLogger(__name__)


# Canonical event names. Kept here so typos in routes show up as test failures.
EVENT_USER_REGISTERED = "user_registered"
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILED = "login_failed"
EVENT_SECRET_CREATED = "secret_created"
EVENT_SECRET_RETRIEVED = "secret_retrieved"
EVENT_SECRET_LISTED = "secret_listed"
EVENT_SECRET_UPDATED = "secret_updated"
EVENT_SECRET_DELETED = "secret_deleted"
EVENT_SHARE_CREATED = "share_created"
EVENT_SHARE_ACCESSED = "share_accessed"
EVENT_SHARE_EXPIRED_OR_INVALID = "share_expired_or_invalid"


def record_event(
    event: str,
    *,
    user_id: str | None = None,
    secret_id: str | None = None,
    detail: str | None = None,
) -> None:
    """Insert one audit row. Failures are logged but never raised — auditing
    must not block the request path.
    """
    ip = ua = None
    if has_request_context():
        ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "")[:64]
        ua = (request.headers.get("User-Agent") or "")[:255]

    try:
        entry = AuditLog(
            event=event,
            user_id=user_id,
            secret_id=secret_id,
            ip_address=ip or None,
            user_agent=ua or None,
            detail=(detail or None) if detail is None or len(detail) <= 500 else detail[:500],
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to write audit log entry for event=%s", event)
        db.session.rollback()
