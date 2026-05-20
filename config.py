"""Application configuration.

Three profiles are exposed: development, testing, production. The active profile
is selected by ``FLASK_ENV``. Sensitive values are sourced from environment
variables; missing critical values cause a fail-fast error in production rather
than silently weakening the security posture.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env once, early, so every config class sees the same environment.
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class BaseConfig:
    """Settings shared by all environments."""

    # JSON-only API: do not pretty-print, do not sort keys (saves CPU).
    JSON_SORT_KEYS = False
    PROPAGATE_EXCEPTIONS = True

    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'app.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT — Flask-JWT-Extended
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # one hour
    JWT_ERROR_MESSAGE_KEY = "error"

    # Encryption
    SECRET_ENCRYPTION_KEY = os.environ.get("SECRET_ENCRYPTION_KEY")
    SECRET_STORAGE_DIR = os.environ.get(
        "SECRET_STORAGE_DIR", str(BASE_DIR / "data" / "secrets")
    )

    # Share tokens
    SHARE_TOKEN_TTL_SECONDS = int(os.environ.get("SHARE_TOKEN_TTL_SECONDS", "3600"))

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Generic
    MAX_CONTENT_LENGTH = 256 * 1024  # 256 KB request bodies max


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False
    # Dev convenience: allow a default JWT key so a fresh clone runs, but warn.
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-jwt-secret-change-me")


class TestingConfig(BaseConfig):
    DEBUG = False
    TESTING = True
    # Tests inject their own DB URI, storage dir, and Fernet key via fixtures.
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # Length kept above 32 bytes to satisfy pyjwt's SHA-256 key-length recommendation.
    JWT_SECRET_KEY = "test-jwt-secret-do-not-use-outside-tests-padding-bytes"
    RATELIMIT_ENABLED = False  # disable global limits in tests; re-enable per-test
    SHARE_TOKEN_TTL_SECONDS = 3600


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False

    @classmethod
    def validate(cls) -> None:
        """Fail fast if production is missing required secrets."""
        missing = [
            name
            for name in ("JWT_SECRET_KEY", "SECRET_ENCRYPTION_KEY")
            if not os.environ.get(name)
        ]
        if missing:
            raise RuntimeError(
                f"Production config missing required env vars: {', '.join(missing)}"
            )


CONFIG_BY_NAME = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None):
    """Resolve a config class from a string name, defaulting to development."""
    name = (name or os.environ.get("FLASK_ENV") or "development").lower()
    cfg = CONFIG_BY_NAME.get(name, DevelopmentConfig)
    if cfg is ProductionConfig:
        cfg.validate()
    return cfg
