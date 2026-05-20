"""Encryption helpers built on cryptography.fernet.

Design choices:

* Symmetric encryption with Fernet (AES-128-CBC + HMAC-SHA256). The key is
  loaded from ``SECRET_ENCRYPTION_KEY`` and is *never* generated silently at
  runtime — silent generation would make previously-stored ciphertext
  unrecoverable on the next restart.
* Ciphertext is stored on the filesystem (one file per secret) using the
  built-in ``open()`` call, as required by the assignment.
* Filenames are derived from the secret UUID so no user-controlled input ever
  participates in the path. We also guard against path traversal explicitly.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


class EncryptionError(RuntimeError):
    """Raised when encryption or decryption fails for any reason."""


def _fernet() -> Fernet:
    key = current_app.config.get("SECRET_ENCRYPTION_KEY")
    if not key:
        # Fail loudly: silent fallback to a generated key would brick existing data.
        raise EncryptionError("SECRET_ENCRYPTION_KEY is not configured")
    if isinstance(key, str):
        key = key.encode("utf-8")
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise EncryptionError("SECRET_ENCRYPTION_KEY is not a valid Fernet key") from exc


def _storage_dir() -> Path:
    storage = Path(current_app.config["SECRET_STORAGE_DIR"]).resolve()
    storage.mkdir(parents=True, exist_ok=True)
    return storage


def _safe_path_for(secret_id: str) -> Path:
    """Return the absolute path for a secret's ciphertext file.

    ``secret_id`` is expected to be a UUID we generated. We re-validate it here
    so a corrupted or tampered DB row can never produce a path outside the
    storage directory.
    """
    try:
        uuid.UUID(secret_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise EncryptionError("Invalid secret identifier") from exc

    storage = _storage_dir()
    path = (storage / f"{secret_id}.enc").resolve()
    if storage not in path.parents:
        raise EncryptionError("Refusing to operate on path outside storage dir")
    return path


def encrypt_and_store(secret_id: str, plaintext: str) -> str:
    """Encrypt ``plaintext`` and write the ciphertext to disk.

    Returns the absolute path of the ciphertext file so the caller can persist
    it on the DB row.
    """
    if not isinstance(plaintext, str):
        raise EncryptionError("Plaintext must be a string")

    token = _fernet().encrypt(plaintext.encode("utf-8"))
    path = _safe_path_for(secret_id)
    # Write atomically: write to a temp file then rename. Set 0600 perms so the
    # ciphertext is not world-readable on shared hosts.
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "wb") as fh:
        fh.write(token)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)
    return str(path)


def load_and_decrypt(secret_id: str) -> str:
    """Read the ciphertext file for ``secret_id`` and return its plaintext."""
    path = _safe_path_for(secret_id)
    if not path.exists():
        raise EncryptionError("Ciphertext file is missing")
    with open(path, "rb") as fh:
        token = fh.read()
    try:
        return _fernet().decrypt(token).decode("utf-8")
    except InvalidToken as exc:
        raise EncryptionError("Ciphertext failed authentication") from exc


def delete_ciphertext(secret_id: str) -> bool:
    """Best-effort delete of the ciphertext file. Returns True if it was removed."""
    try:
        path = _safe_path_for(secret_id)
    except EncryptionError:
        return False
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
