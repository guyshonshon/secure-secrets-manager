"""Cross-cutting security checks: auditing, rate limiting, secret hygiene."""

from __future__ import annotations

from models import AuditLog


def test_audit_events_recorded_without_secret_values(app, client, auth_headers, make_secret):
    meta = make_secret(name="audited", value="should-not-appear")
    client.get(f"/secrets/{meta['id']}", headers=auth_headers)
    client.delete(f"/secrets/{meta['id']}", headers=auth_headers)

    with app.app_context():
        events = [row.event for row in AuditLog.query.all()]
        # Order doesn't matter, but all five should be present at minimum.
        for required in (
            "user_registered",
            "login_success",
            "secret_created",
            "secret_retrieved",
            "secret_deleted",
        ):
            assert required in events

        # Sweep every column of every row — no plaintext, no passwords, no tokens.
        for row in AuditLog.query.all():
            blob = " ".join(
                str(v or "")
                for v in (row.event, row.detail, row.user_id, row.secret_id, row.user_agent)
            )
            assert "should-not-appear" not in blob
            assert "StrongPassword123!" not in blob


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_rate_limiting_triggers_when_enabled(tmp_path, monkeypatch):
    """Sanity check: when the limiter is enabled, /login starts returning 429.

    We build a brand-new app with rate limiting enabled from the start so the
    limiter wires its in-memory storage correctly (toggling ``enabled`` after
    ``init_app`` doesn't always re-arm storage in Flask-Limiter).
    """
    from cryptography.fernet import Fernet

    storage_dir = tmp_path / "secrets"
    storage_dir.mkdir()
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-32bytes-or-more-padding")
    monkeypatch.setenv("SECRET_STORAGE_DIR", str(storage_dir))

    # Flask-Limiter only registers route limits if RATELIMIT_ENABLED is true
    # at ``init_app`` time, so we patch the testing config *before* the factory.
    import config as cfg
    monkeypatch.setattr(cfg.TestingConfig, "RATELIMIT_ENABLED", True, raising=False)

    from app import create_app
    from models import db
    from utils.rate_limit import limiter

    application = create_app("testing")
    limiter.enabled = True
    try:
        with application.app_context():
            db.create_all()
            client = application.test_client()

            client.post(
                "/register",
                json={"email": "rl@example.com", "password": "StrongPassword123!"},
            )
            # /login is capped at "10 per minute" — fire past the limit.
            statuses = [
                client.post(
                    "/login",
                    json={"email": "rl@example.com", "password": "WrongPassword!"},
                ).status_code
                for _ in range(25)
            ]
            assert 429 in statuses, f"expected at least one 429, got {statuses}"
            db.drop_all()
    finally:
        limiter.enabled = False
        try:
            limiter.reset()
        except Exception:
            pass


def test_rate_limit_decorators_are_registered():
    """Verify each sensitive endpoint actually carries a Flask-Limiter rule."""
    from routes.auth import register, login
    from routes.share import access_share
    from routes.secrets import share_secret

    for fn in (register, login, access_share, share_secret):
        # Flask-Limiter attaches limits as attributes on the wrapped function.
        attrs = [a for a in dir(fn) if "limit" in a.lower()]
        assert attrs, f"{fn.__name__} has no rate-limit decorator attributes"


def test_method_not_allowed_returns_json(client):
    r = client.patch("/secrets")
    assert r.status_code in (401, 405)
    assert "error" in r.get_json()


def test_jwt_required_returns_json_401(client):
    r = client.get("/secrets/anything", headers={"Authorization": "Bearer bogus"})
    assert r.status_code in (401, 422)
    assert "error" in r.get_json() or "msg" in r.get_json()


def test_missing_jwt_secret_existence_does_not_leak_across_users(
    client, auth_headers, second_user_headers, make_secret
):
    """Bob asking for a non-existent secret and Bob asking for Alice's secret
    must look identical from the outside."""
    meta = make_secret(value="alices")
    r_alice = client.get(f"/secrets/{meta['id']}", headers=second_user_headers)
    r_missing = client.get("/secrets/00000000-0000-0000-0000-000000000000", headers=second_user_headers)
    assert r_alice.status_code == r_missing.status_code == 404
    assert r_alice.get_json() == r_missing.get_json()
