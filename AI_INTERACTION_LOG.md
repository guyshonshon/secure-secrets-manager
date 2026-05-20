# AI Interaction Log

This document records how AI assistance was used to build the
**Secure Secrets Manager** (Project 4, DevSecOps course). It captures the
original specification, the prompt given to the coding assistant, the
architectural and security decisions that were made, the testing performed,
and known limitations.

> The earlier architectural discussion that produced the prompt below lives in
> `../AI_ARCHITECTURE.md` (one directory up). That file holds the verbatim
> back-and-forth with ChatGPT-5.5 that scoped the project before
> implementation began. This file documents the *implementation* phase with
> Claude Code.

---

## 1. Original project specification (summarised, faithful)

Build a small-scale, secure secrets manager in Python + Flask. Users must
be able to:

- Register and log in.
- Securely store API keys / credentials, encrypted at rest.
- List, retrieve, update metadata for, and delete their own secrets.
- Generate one-time, expiring share links for individual secrets, and
  redeem those links anonymously.

Endpoints (all JSON):

| Method | Path                       | Purpose                                    |
| ------ | -------------------------- | ------------------------------------------ |
| POST   | `/register`                | register a new user                        |
| POST   | `/login`                   | authenticate, return token                 |
| POST   | `/secrets`                 | store a new (encrypted) secret             |
| GET    | `/secrets`                 | list the caller's secrets (metadata only)  |
| GET    | `/secrets/<id>`            | retrieve a secret (owner only)             |
| PUT    | `/secrets/<id>`            | update secret metadata                     |
| DELETE | `/secrets/<id>`            | delete a secret                            |
| POST   | `/secrets/<id>/share`      | generate a one-time expiring share link    |
| GET    | `/share/<token>`           | redeem a share link                        |

Required cross-cutting "challenges":
1. Strong encryption for all secret data.
2. Never log or expose secret values.
3. Rate limiting against abuse.
4. Environment variables for sensitive configuration.
5. OWASP-aware behaviour throughout.
6. Documented code.
7. Use AI as a learning aid, not a replacement for understanding.

Process requirements: initialise git, keep a Markdown log of the AI
collaboration, and configure `.gitignore` properly.

The brief also asked for both file-based secret storage (`open()`) **and**
database migrations — see "Architecture decisions" below for how this was
reconciled.

---

## 2. Implementation prompt given to Claude Code

The implementation prompt asked Claude Code to act as a senior software
architect / DevSecOps engineer and produce a complete, production-quality
Flask project named `secure-secrets-manager`. It pinned down every endpoint,
required security control, file layout, dependency list, validation rules,
audit-event names, and testing scope, so the model's room to drift was small.

The full prompt is preserved verbatim alongside this project in
`../AI_ARCHITECTURE.md`.

---

## 3. Architecture decisions

| Decision                                                       | Why                                                                                                                                                                          |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Flask app factory** (`create_app`)                           | clean separation between configuration and instantiation; required to run multiple isolated test apps with different keys.                                                   |
| **Encrypted value on disk, metadata in SQLite**                | The brief asked for `open()`-based storage *and* DB migrations. Split responsibilities: ciphertext to disk, everything else to SQLite via Flask-Migrate. Plaintext is never in the DB. |
| **UUIDs as primary keys** (users, secrets, share tokens)       | no incremental-id enumeration; ciphertext filenames derive from the secret's UUID so user-controlled input never participates in a filesystem path.                          |
| **Fernet** (`cryptography.fernet`)                             | well-vetted, authenticated symmetric encryption (AES-128-CBC + HMAC-SHA256); detects tampering automatically.                                                                |
| **Share tokens stored as SHA-256 hashes**                      | raw token is returned exactly once at creation. If the DB is ever leaked, the share tokens are not usable.                                                                   |
| **Same generic 404 for unknown / wrong-owner / expired-share** | no information leakage about which secrets or tokens exist for other users.                                                                                                  |
| **JWT (Flask-JWT-Extended)**                                   | stateless authentication that fits the JSON-API style and works under rate limiting / horizontal scaling.                                                                    |
| **Werkzeug `pbkdf2:sha256:600000`** for passwords              | strong modern default in Werkzeug; explicit iteration count makes the hash parameters auditable.                                                                              |
| **Per-endpoint Flask-Limiter limits**                          | login/register/share carry strict limits; CRUD endpoints carry sensible looser limits. Keeps the door narrow for brute-force without breaking ordinary use.                  |
| **Global JSON error handlers**                                 | one consistent shape (`{"error": "..."}`), and stack traces never reach the client.                                                                                         |
| **Audit logging in-DB**                                        | normalised events with timestamp / user / IP / UA but never plaintext or tokens; queryable from the same store as the rest of the schema.                                    |

## 4. Security decisions

- **Fail fast in production** if `JWT_SECRET_KEY` or `SECRET_ENCRYPTION_KEY` is missing — silent fallback would either weaken auth or make existing ciphertext unrecoverable.
- **Never auto-generate the Fernet key at runtime**: doing so would brick previously-stored secrets on the next restart.
- **Atomic ciphertext writes** with `os.replace` and `chmod 0600` — protects against partial-write corruption and shared-host snooping.
- **Path traversal guarded** in `utils/encryption.py`: the secret id is re-validated as a UUID before any path is constructed, and the resulting path is verified to live inside the configured storage directory.
- **Plaintext value never appears** in API responses for the list / update / share-create endpoints — only `GET /secrets/<id>` (owner) and `GET /share/<token>` (one-shot redemption) ever include it.
- **No echo of bad input** in validation errors (especially the secret value and password).
- **Generic 401 / 404 / 409** for credentials, missing resources, and duplicate registration to prevent user / resource enumeration.
- **Rate limits** on `/register`, `/login`, `/secrets/<id>/share`, and `/share/<token>` — these are the highest-leverage abuse vectors.
- **Audit table** captures event, user_id, secret_id, IP, user-agent, timestamp. Inspected by the `test_audit_events_recorded_without_secret_values` test to confirm no plaintext leaks.

## 5. Testing & validation performed

`pytest -q` →  **30 tests pass, 0 warnings**, ~7 s runtime.

Coverage breakdown:

| File              | What's verified                                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `test_auth.py`    | Registration succeeds; duplicate registration rejected; email/password validation; login success; bad-password and unknown-user paths return the same generic 401; malformed JSON yields safe 400. |
| `test_secrets.py` | Protected routes require JWT; create stores **ciphertext on disk** (verified by reading the file and checking it starts with `gAAAA` and does not contain plaintext); list omits the value; metadata update does not mutate ciphertext; delete removes both DB row and file; cross-user access / mutate / share is forbidden; list only returns own secrets; bad JSON and oversize value are rejected. |
| `test_share.py`   | Share token is returned with URL and expiry; only the SHA-256 hash is stored; token redeemable exactly once; expired token rejected; unknown token returns the same error as expired/used; non-owner cannot create a share. |
| `test_security.py` | Audit events are recorded without secret values or passwords appearing in any column; `/health` works; rate limiting actually triggers 429s when enabled; every sensitive endpoint carries a `@limiter.limit` decoration; cross-user 404s are indistinguishable from genuine 404s. |

Manual checks performed:
- `flask db init && flask db migrate` regenerates a correct schema.
- `python app.py` boots cleanly on a fresh clone given the env vars from `.env.example`.

## 6. Limitations & assumptions

- **Rate-limit backend is in-memory** by default. Multi-process deployment requires `RATELIMIT_STORAGE_URI=redis://...`.
- **Single Fernet key, no rotation.** A production system should add key rotation via `MultiFernet`; out of scope for this assignment.
- **No HTML UI.** This is an API-only project, by design.
- **No external KMS integration.** The Fernet key is read from an env var, which is appropriate for a course project but not for high-stakes production — replace with AWS KMS / GCP KMS / Vault as appropriate.
- **TLS termination is external.** The Flask app is expected to live behind a reverse proxy in any non-trivial deployment.
- **Audit logs are not forwarded.** A real deployment should ship them off-host so the same DB compromise that exposes data doesn't also let the attacker rewrite history.
- **JWTs are not revoked on logout** because there is no logout endpoint. A 1-hour expiry is the only mitigation.

## 7. How AI was used (and not used)

- AI was used to **scaffold quickly and consistently** — directory layout, decorator stacks, validators, audit event names, test fixtures.
- AI was used to **double-check security choices** (e.g. why hashing share tokens matters, why `RATELIMIT_ENABLED` must be true at `init_app` time, why a generic 404 is the right answer for "not yours" vs "doesn't exist").
- AI was **not** used to bypass understanding: every architectural decision above is justified in plain language, tests verify the behaviour rather than reciting code paths, and limitations are listed honestly rather than hidden.
