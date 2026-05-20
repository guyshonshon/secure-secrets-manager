"""Registration and login behaviour."""

from __future__ import annotations


def test_register_creates_user(client):
    r = client.post(
        "/register",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    )
    assert r.status_code == 201
    body = r.get_json()
    assert body["message"] == "User registered successfully"
    assert "id" in body


def test_register_duplicate_rejected(client):
    payload = {"email": "alice@example.com", "password": "StrongPassword123!"}
    assert client.post("/register", json=payload).status_code == 201
    r = client.post("/register", json=payload)
    assert r.status_code == 409
    # Generic message — no user enumeration.
    assert "Registration failed" in r.get_json()["error"]


def test_register_validates_email_and_password(client):
    r = client.post("/register", json={"email": "nope", "password": "StrongPassword123!"})
    assert r.status_code == 400
    r = client.post("/register", json={"email": "a@b.co", "password": "short"})
    assert r.status_code == 400


def test_login_success_returns_token(client):
    client.post(
        "/register",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    )
    r = client.post(
        "/login",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    )
    assert r.status_code == 200
    assert "access_token" in r.get_json()


def test_login_invalid_password_fails_safely(client):
    client.post(
        "/register",
        json={"email": "alice@example.com", "password": "StrongPassword123!"},
    )
    r = client.post(
        "/login", json={"email": "alice@example.com", "password": "WrongPassword!"}
    )
    assert r.status_code == 401
    assert r.get_json()["error"] == "Invalid credentials"


def test_login_unknown_user_returns_same_error(client):
    r = client.post(
        "/login", json={"email": "nobody@example.com", "password": "WhatEver123!"}
    )
    assert r.status_code == 401
    assert r.get_json()["error"] == "Invalid credentials"


def test_missing_json_returns_400(client):
    r = client.post("/register", data="not-json", content_type="application/json")
    assert r.status_code == 400
    assert "error" in r.get_json()
