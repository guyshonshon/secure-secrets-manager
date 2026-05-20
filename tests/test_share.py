"""Share-link generation and one-time redemption."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from models import ShareToken, db


def _create_share(client, auth_headers, secret_id):
    return client.post(f"/secrets/{secret_id}/share", headers=auth_headers)


def test_share_returns_token_and_url(client, auth_headers, make_secret):
    meta = make_secret(value="payload")
    r = _create_share(client, auth_headers, meta["id"])
    assert r.status_code == 201
    body = r.get_json()
    assert body["token"]
    assert body["share_url"].endswith(body["token"])
    assert "expires_at" in body


def test_share_token_is_hashed_in_db(app, client, auth_headers, make_secret):
    meta = make_secret(value="payload")
    body = _create_share(client, auth_headers, meta["id"]).get_json()
    raw = body["token"]
    with app.app_context():
        rows = ShareToken.query.all()
        assert len(rows) == 1
        # Raw token must NOT appear directly in any column.
        assert rows[0].token_hash != raw
        assert rows[0].token_hash == ShareToken.hash_token(raw)


def test_share_can_be_redeemed_exactly_once(client, auth_headers, make_secret):
    meta = make_secret(value="one-time-payload")
    body = _create_share(client, auth_headers, meta["id"]).get_json()
    raw = body["token"]

    r1 = client.get(f"/share/{raw}")
    assert r1.status_code == 200
    assert r1.get_json()["value"] == "one-time-payload"

    r2 = client.get(f"/share/{raw}")
    assert r2.status_code == 404
    # Generic error — does not reveal "used" vs "invalid".
    assert r2.get_json()["error"] == "Share link is invalid or has expired"


def test_expired_share_token_rejected(app, client, auth_headers, make_secret):
    meta = make_secret(value="payload")
    body = _create_share(client, auth_headers, meta["id"]).get_json()
    raw = body["token"]

    # Force the row's expiry into the past.
    with app.app_context():
        row = ShareToken.query.first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

    r = client.get(f"/share/{raw}")
    assert r.status_code == 404


def test_invalid_share_token_returns_same_error(client):
    r = client.get("/share/totally-bogus-token")
    assert r.status_code == 404
    assert r.get_json()["error"] == "Share link is invalid or has expired"


def test_share_requires_ownership(client, auth_headers, second_user_headers, make_secret):
    meta = make_secret(value="payload")
    # Bob tries to create a share for Alice's secret.
    r = client.post(f"/secrets/{meta['id']}/share", headers=second_user_headers)
    assert r.status_code == 404
