# API Documentation

Base URL during local development: `http://127.0.0.1:5000`

All endpoints accept and return JSON. Authentication uses the
`Authorization: Bearer <token>` header. Tokens are issued by `POST /login`
and expire one hour after issue.

Errors are always JSON of the form `{"error": "<short description>"}`.
Sensitive resource existence is intentionally hidden — e.g. accessing
another user's secret returns the same 404 as a non-existent id.

---

## Auth

### `POST /register`
Create a new user.

- **Auth**: none
- **Rate limit**: 5 / minute, 20 / hour
- **Body**: `{ "email": "user@example.com", "password": "string (8-256 chars)" }`
- **201**: `{ "message": "User registered successfully", "id": "<uuid>" }`
- **400**: invalid body
- **409**: `{ "error": "Registration failed" }` (generic, prevents enumeration)
- **429**: rate limited

```bash
curl -X POST http://127.0.0.1:5000/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"StrongPassword123!"}'
```

### `POST /login`
Exchange credentials for a JWT.

- **Auth**: none
- **Rate limit**: 10 / minute, 100 / hour
- **Body**: `{ "email": "...", "password": "..." }`
- **200**: `{ "access_token": "<jwt>" }`
- **401**: `{ "error": "Invalid credentials" }`
- **429**: rate limited

```bash
curl -X POST http://127.0.0.1:5000/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"StrongPassword123!"}'
```

---

## Secrets

### `POST /secrets`
Create a secret. The value is encrypted with Fernet and written to disk.

- **Auth**: required
- **Rate limit**: 60 / minute
- **Body**:
  ```json
  {
    "name": "GitHub API Key",
    "value": "ghp_secret_value",
    "description": "Personal GitHub token",
    "tags": ["github", "api"]
  }
  ```
- **201**: metadata (`id`, `name`, `description`, `tags`, timestamps). **No value.**
- **400**: validation failure (never echoes the value)

```bash
curl -X POST http://127.0.0.1:5000/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"GitHub API Key","value":"ghp_xxx","tags":["github"]}'
```

### `GET /secrets`
List the authenticated user's secrets — **metadata only**, no values.

- **Auth**: required
- **Rate limit**: 120 / minute
- **200**: `{ "secrets": [ { id, name, description, tags, created_at, updated_at }, ... ] }`

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/secrets
```

### `GET /secrets/<id>`
Retrieve a single secret including its decrypted value.

- **Auth**: required (must be the owner)
- **Rate limit**: 60 / minute
- **200**: metadata **plus** `"value": "<plaintext>"`
- **404**: not yours / does not exist

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/secrets/<id>
```

### `PUT /secrets/<id>`
Update metadata (`name`, `description`, `tags`). The encrypted value is intentionally not mutable via this endpoint.

- **Auth**: required (must be the owner)
- **Rate limit**: 60 / minute
- **Body**: any subset of `{ "name", "description", "tags" }`
- **200**: updated metadata
- **400**: validation failure
- **404**: not yours / does not exist

```bash
curl -X PUT http://127.0.0.1:5000/secrets/<id> \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"renamed","tags":["new","tags"]}'
```

### `DELETE /secrets/<id>`
Delete the secret. Removes the DB row and best-effort deletes the ciphertext file.

- **Auth**: required (must be the owner)
- **Rate limit**: 60 / minute
- **200**: `{ "message": "Secret deleted" }`
- **404**: not yours / does not exist

```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5000/secrets/<id>
```

### `POST /secrets/<id>/share`
Generate a one-time, expiring share link.

- **Auth**: required (must be the owner)
- **Rate limit**: 10 / minute, 100 / hour
- **201**:
  ```json
  {
    "share_url": "http://.../share/<raw_token>",
    "token": "<raw_token>",
    "expires_at": "2026-05-20T12:34:56+00:00"
  }
  ```
  The raw token is shown **only once** and only the SHA-256 hash is persisted.
- **404**: not yours / does not exist

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:5000/secrets/<id>/share
```

---

## Share redemption

### `GET /share/<token>`
Exchange a raw share token for the decrypted value, exactly once.

- **Auth**: none
- **Rate limit**: 10 / minute, 60 / hour
- **200**: `{ "name": "...", "description": "...", "value": "<plaintext>" }`
- **404**: `{ "error": "Share link is invalid or has expired" }` — returned for unknown, expired, and already-used tokens (no oracle).

```bash
curl http://127.0.0.1:5000/share/<token>
```

---

## Health

### `GET /health`
- **Auth**: none
- **200**: `{ "status": "ok" }`
