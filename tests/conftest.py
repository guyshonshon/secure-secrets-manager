"""Shared pytest fixtures.

Every test gets a fresh in-memory SQLite DB, a fresh tmp ciphertext directory,
a real Fernet key, and rate-limiting disabled by default. Rate-limit tests
re-enable it on demand.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

# Make project root importable for `from app import create_app`.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def app(tmp_path, monkeypatch):
    # Configure environment *before* importing the factory so config picks it up.
    storage_dir = tmp_path / "secrets"
    storage_dir.mkdir()
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv(
        "JWT_SECRET_KEY", "test-jwt-secret-do-not-use-outside-tests-padding-bytes"
    )
    monkeypatch.setenv("SECRET_STORAGE_DIR", str(storage_dir))

    # Import here so each test re-creates the factory with fresh env vars.
    from app import create_app
    from models import db

    application = create_app("testing")
    # Override storage dir to the tmp path; testing config uses in-memory DB.
    application.config["SECRET_STORAGE_DIR"] = str(storage_dir)

    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def storage_dir(app):
    return Path(app.config["SECRET_STORAGE_DIR"])


def _register(client, email="alice@example.com", password="StrongPassword123!"):
    return client.post("/register", json={"email": email, "password": password})


def _login(client, email="alice@example.com", password="StrongPassword123!"):
    r = client.post("/login", json={"email": email, "password": password})
    return r.get_json()["access_token"], r


@pytest.fixture()
def auth_token(client):
    _register(client)
    token, _ = _login(client)
    return token


@pytest.fixture()
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture()
def second_user_headers(client):
    _register(client, email="bob@example.com", password="OtherPassword456!")
    token, _ = _login(client, email="bob@example.com", password="OtherPassword456!")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def make_secret(client, auth_headers):
    def _make(name="GitHub Token", value="ghp_supersecret", description=None, tags=None):
        body = {"name": name, "value": value}
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        r = client.post("/secrets", json=body, headers=auth_headers)
        assert r.status_code == 201, r.get_json()
        return r.get_json()

    return _make
