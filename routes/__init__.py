"""Blueprints aggregated for the app factory."""

from .auth import auth_bp
from .secrets import secrets_bp
from .share import share_bp

__all__ = ["auth_bp", "secrets_bp", "share_bp"]
