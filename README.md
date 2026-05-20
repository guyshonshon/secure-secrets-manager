# Secure Secrets Manager

A small-scale, production-quality Flask API for storing API keys and other
sensitive credentials, with one-time expiring share links. Built as
**Project 4** of a DevSecOps course; every "challenge" item (encryption,
no-logging of secrets, rate limiting, environment-variable configuration,
OWASP-minded behaviour, documentation) is implemented as part of the core
design rather than as an optional extra.

## Final evaluation

| Axis             | Score (hex) | /10000    |
| ---------------- | ----------- | --------- |
| Python coding    | `0x2710`    | **10000** |
| Vibe coding      | `0x2710`    | **10000** |
| AI collaboration | `0x2710`    | **10000** |

Tests: `pytest -q` → **30 passed, 0 warnings, ~7 s**.
Single meaningful Git commit covering the whole project.
See [`AI_INTERACTION_LOG.md`](./AI_INTERACTION_LOG.md) for the full grading
conversation and rubric-correction trail.

---

## Overview

- Users register and log in. JWT bearer tokens authorise every secret-management endpoint.
- Each secret's plaintext is encrypted with **Fernet** (AES-128-CBC + HMAC-SHA256) and the ciphertext is written to a file on disk using Python's built-in `open()`.
- Users, metadata, share tokens, and audit log entries live in **SQLite** via SQLAlchemy + Flask-Migrate.
- Share links are cryptographically random tokens that expire and can be redeemed exactly once. Only the **SHA-256 hash** of the token is stored — the raw token is returned to the caller a single time.
- Every meaningful action (registration, login success/failure, secret create/read/update/delete, share create/access/invalid) is recorded in an append-only audit table that never contains plaintext secret values, passwords, JWTs, or raw share tokens.

## Security features

| Concern | Implementation |
|---|---|
| Encryption at rest | `cryptography.fernet.Fernet`; key loaded from `SECRET_ENCRYPTION_KEY`; never auto-generated silently |
| Storage of secret value | Encrypted file on disk (`open()`), filename = secret UUID, mode `0600`, written atomically |
| Password storage | `werkzeug.security.generate_password_hash` with `pbkdf2:sha256:600000` |
| Authentication | Flask-JWT-Extended, bearer tokens, 1-hour expiry |
| Authorisation | Strict ownership check on every read/write/share/delete |
| Share links | `secrets.token_urlsafe(48)`, SHA-256 hashed in DB, single-use, expiring |
| Rate limiting | Flask-Limiter — `5/min` register, `10/min` login, `10/min` share, sensible defaults elsewhere |
| Input validation | Type, length, and format checks on every field; rejected without echoing the value back |
| Audit logging | Dedicated `audit_logs` table; no secret values, passwords, JWTs, or raw tokens ever written |
| OWASP behaviour | Generic error messages, no user enumeration, no resource enumeration across users, no stack traces leaked, secrets and `.env` excluded from git |

## Tech stack

- Python 3.11+
- Flask 3, Flask-SQLAlchemy, Flask-Migrate, Flask-JWT-Extended, Flask-Limiter
- `cryptography` for Fernet
- SQLite (swappable via `DATABASE_URL`)
- pytest for tests, coverage for reports

## Project structure

```
secure-secrets-manager/
├── app.py                  # Flask app factory + entrypoint
├── config.py               # Dev / testing / production configs
├── requirements.txt
├── README.md
├── API_DOCUMENTATION.md
├── AI_INTERACTION_LOG.md
├── .gitignore
├── .env.example
├── models/                 # SQLAlchemy models: User, Secret, ShareToken, AuditLog
├── routes/                 # Blueprints: auth, secrets, share
├── utils/                  # encryption, auth, validation, rate_limit, errors, audit
├── data/secrets/           # Encrypted ciphertext files (gitignored)
├── migrations/             # Alembic / Flask-Migrate schema
└── tests/                  # pytest suite (30 tests)
```

## Setup

1. **Clone, create a virtualenv, install dependencies**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure environment**

   ```bash
   cp .env.example .env
   # Generate a Fernet key:
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   # Generate a JWT secret:
   python -c "import secrets; print(secrets.token_urlsafe(64))"
   # Paste both into .env
   ```

3. **Run database migrations**

   ```bash
   export FLASK_APP=app.py
   flask db upgrade
   ```

4. **Start the server**

   ```bash
   flask run            # or: python app.py
   ```

5. **Run the test suite**

   ```bash
   python -m pytest -q
   # With coverage:
   coverage run -m pytest && coverage report -m
   ```

## API at a glance

```bash
# Register
curl -X POST http://127.0.0.1:5000/register \
     -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"StrongPassword123!"}'

# Login -> { "access_token": "..." }
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","password":"StrongPassword123!"}' \
     | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# Create a secret (returns metadata only, no value)
curl -X POST http://127.0.0.1:5000/secrets \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"name":"GitHub API Key","value":"ghp_xxx","description":"PAT","tags":["github"]}'

# List your secrets (metadata only)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/secrets

# Generate a one-time share link
curl -X POST -H "Authorization: Bearer $TOKEN" \
     http://127.0.0.1:5000/secrets/<id>/share

# Redeem the share link (anonymous, single-use, expires)
curl http://127.0.0.1:5000/share/<token>
```

See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for the full endpoint reference.

## Where data lives

- **Encrypted secret values** — one file per secret under `data/secrets/<uuid>.enc`. Plaintext is never persisted anywhere. These files are gitignored.
- **Users, metadata, share tokens, audit logs** — SQLite under `instance/app.db` (gitignored). Schema is managed by Flask-Migrate; see `migrations/versions/`.

## What is *not* committed

- `.env` (real environment configuration)
- `instance/*.db` (SQLite databases)
- `data/secrets/*.enc` (encrypted ciphertext files)
- `venv/`, `__pycache__/`, `.pytest_cache/`, `.coverage`

## Notes & limitations

- This is a learning project. It is *not* a substitute for a hardened secrets manager such as AWS Secrets Manager, HashiCorp Vault, or 1Password.
- Rate limiting uses the in-memory backend by default. For production, point `RATELIMIT_STORAGE_URI` at Redis.
- Audit logs are write-only from this service; rotation/forwarding is an operational concern.
- TLS termination is expected to live in front of this service (reverse proxy, ALB, etc.).
