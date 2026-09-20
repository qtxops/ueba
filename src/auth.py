"""Password, bearer-token, user, and audit helpers for the API."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pwdlib import PasswordHash


PASSWORD_HASH = PasswordHash.recommended()
ALGORITHM = "HS256"


def create_user(connection: sqlite3.Connection, username: str, password: str, role: str) -> None:
    if role not in {"admin", "analyst"}:
        raise ValueError("Role must be admin or analyst")
    if len(username.strip()) < 3:
        raise ValueError("Username must contain at least three characters")
    if len(password) < 10:
        raise ValueError("Password must contain at least ten characters")
    connection.execute(
        """INSERT INTO users (username, password_hash, role, disabled, created_at)
           VALUES (?, ?, ?, 0, ?)
           ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash,
               role = excluded.role, disabled = 0""",
        (username.strip(), PASSWORD_HASH.hash(password), role, datetime.now(timezone.utc).isoformat()),
    )
    connection.commit()


def authenticate_user(connection: sqlite3.Connection, username: str, password: str) -> dict[str, Any] | None:
    row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or int(row["disabled"]) or not PASSWORD_HASH.verify(password, row["password_hash"]):
        return None
    return dict(row)


def create_access_token(username: str, role: str, secret_key: str, minutes: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": username, "role": role, "iat": now, "exp": now + timedelta(minutes=minutes)},
        secret_key,
        algorithm=ALGORITHM,
    )


def decode_access_token(token: str, secret_key: str) -> dict[str, Any]:
    return jwt.decode(token, secret_key, algorithms=[ALGORITHM])


def write_audit(
    connection: sqlite3.Connection,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | int,
    details: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        """INSERT INTO audit_log (actor, action, target_type, target_id, details_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            actor, action, target_type, str(target_id), json.dumps(details or {}, default=str),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    connection.commit()
