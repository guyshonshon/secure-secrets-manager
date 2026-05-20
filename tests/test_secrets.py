"""CRUD on /secrets plus ciphertext-on-disk verification."""

from __future__ import annotations


def test_protected_routes_require_auth(client):
    assert client.get("/secrets").status_code == 401
    assert client.post("/secrets", json={"name": "x", "value": "y"}).status_code == 401


def test_create_secret_stores_ciphertext_file_not_plaintext(
    client, auth_headers, storage_dir, make_secret
):
    meta = make_secret(name="API Key", value="plaintext-value-XYZ", tags=["api"])
    assert "value" not in meta  # response must not echo plaintext

    files = list(storage_dir.glob("*.enc"))
    assert len(files) == 1
    raw = files[0].read_bytes()
    assert b"plaintext-value-XYZ" not in raw  # ciphertext, not plaintext
    # Fernet tokens are base64-url encoded and start with "gAAAA".
    assert raw.startswith(b"gAAAA")


def test_get_secret_returns_plaintext_to_owner(client, auth_headers, make_secret):
    meta = make_secret(value="hunter2-extra")
    r = client.get(f"/secrets/{meta['id']}", headers=auth_headers)
    assert r.status_code == 200
    assert r.get_json()["value"] == "hunter2-extra"


def test_list_secrets_omits_value(client, auth_headers, make_secret):
    make_secret(name="A", value="va")
    make_secret(name="B", value="vb")
    r = client.get("/secrets", headers=auth_headers)
    assert r.status_code == 200
    items = r.get_json()["secrets"]
    assert len(items) == 2
    for item in items:
        assert "value" not in item


def test_update_metadata_does_not_touch_value(
    client, auth_headers, storage_dir, make_secret
):
    meta = make_secret(name="Old", value="immutable-value")
    file_bytes_before = next(storage_dir.glob("*.enc")).read_bytes()

    r = client.put(
        f"/secrets/{meta['id']}",
        json={"name": "New", "description": "changed", "tags": ["t"]},
        headers=auth_headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["name"] == "New"
    assert body["description"] == "changed"
    assert body["tags"] == ["t"]
    assert "value" not in body

    file_bytes_after = next(storage_dir.glob("*.enc")).read_bytes()
    assert file_bytes_before == file_bytes_after

    # And the plaintext still decrypts to the original value.
    r = client.get(f"/secrets/{meta['id']}", headers=auth_headers)
    assert r.get_json()["value"] == "immutable-value"


def test_delete_removes_db_row_and_ciphertext(
    client, auth_headers, storage_dir, make_secret
):
    meta = make_secret(value="bye")
    assert list(storage_dir.glob("*.enc"))
    r = client.delete(f"/secrets/{meta['id']}", headers=auth_headers)
    assert r.status_code == 200
    assert client.get(f"/secrets/{meta['id']}", headers=auth_headers).status_code == 404
    assert not list(storage_dir.glob("*.enc"))


def test_another_user_cannot_access_or_mutate(
    client, auth_headers, second_user_headers, make_secret
):
    meta = make_secret(value="alices-secret")
    sid = meta["id"]

    assert client.get(f"/secrets/{sid}", headers=second_user_headers).status_code == 404
    assert client.put(
        f"/secrets/{sid}", json={"name": "x"}, headers=second_user_headers
    ).status_code == 404
    assert client.delete(f"/secrets/{sid}", headers=second_user_headers).status_code == 404
    assert client.post(
        f"/secrets/{sid}/share", headers=second_user_headers
    ).status_code == 404


def test_list_only_returns_own_secrets(
    client, auth_headers, second_user_headers, make_secret
):
    make_secret(name="alice-1", value="va")
    # Bob makes one too.
    r = client.post(
        "/secrets",
        json={"name": "bob-1", "value": "vb"},
        headers=second_user_headers,
    )
    assert r.status_code == 201

    r = client.get("/secrets", headers=auth_headers)
    names = [s["name"] for s in r.get_json()["secrets"]]
    assert names == ["alice-1"]


def test_invalid_json_returns_safe_400(client, auth_headers):
    r = client.post(
        "/secrets",
        data="<<not json>>",
        content_type="application/json",
        headers=auth_headers,
    )
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_oversize_value_rejected(client, auth_headers):
    big = "x" * (64 * 1024 + 1)
    r = client.post(
        "/secrets", json={"name": "big", "value": big}, headers=auth_headers
    )
    assert r.status_code == 400
