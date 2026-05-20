"""Tiny, dependency-free JSON validators.

We intentionally don't pull in pydantic/marshmallow for a project of this size.
Each validator returns ``(value, None)`` on success or ``(None, error_message)``
on failure. Errors never echo the offending value back — that matters
especially for secret values and passwords.
"""

from __future__ import annotations

import re
from typing import Any

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

MAX_EMAIL_LEN = 254
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256
MAX_NAME_LEN = 120
MAX_DESCRIPTION_LEN = 500
MAX_TAG_LEN = 32
MAX_TAGS = 16
MAX_SECRET_VALUE_LEN = 64 * 1024  # 64 KB of plaintext per secret


def require_json(body: Any) -> tuple[dict | None, str | None]:
    """Ensure the request body is a JSON object."""
    if not isinstance(body, dict):
        return None, "Request body must be a JSON object"
    return body, None


def validate_email(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "email must be a string"
    value = value.strip().lower()
    if not value or len(value) > MAX_EMAIL_LEN or not EMAIL_RE.match(value):
        return None, "email is not a valid address"
    return value, None


def validate_password(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "password must be a string"
    if not (MIN_PASSWORD_LEN <= len(value) <= MAX_PASSWORD_LEN):
        return None, (
            f"password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
        )
    return value, None


def validate_name(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "name must be a string"
    value = value.strip()
    if not value or len(value) > MAX_NAME_LEN:
        return None, f"name must be 1-{MAX_NAME_LEN} characters"
    return value, None


def validate_description(value: Any) -> tuple[str | None, str | None]:
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, "description must be a string"
    if len(value) > MAX_DESCRIPTION_LEN:
        return None, f"description must be at most {MAX_DESCRIPTION_LEN} characters"
    return value, None


def validate_tags(value: Any) -> tuple[list[str] | None, str | None]:
    if value is None:
        return [], None
    if not isinstance(value, list) or len(value) > MAX_TAGS:
        return None, f"tags must be a list of at most {MAX_TAGS} strings"
    cleaned: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > MAX_TAG_LEN:
            return None, f"each tag must be a string of 1-{MAX_TAG_LEN} characters"
        cleaned.append(item.strip())
    return cleaned, None


def validate_secret_value(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        # Note: do NOT echo the value back, even if it's the wrong type.
        return None, "value must be a string"
    if not value:
        return None, "value must not be empty"
    if len(value) > MAX_SECRET_VALUE_LEN:
        return None, "value is too large"
    return value, None
