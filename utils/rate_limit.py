"""Flask-Limiter wiring.

A single ``limiter`` instance is shared by all blueprints. Defaults are
intentionally modest; auth and share endpoints get tighter per-route limits
applied in the route modules themselves.
"""

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour", "60 per minute"],
    headers_enabled=True,
)
