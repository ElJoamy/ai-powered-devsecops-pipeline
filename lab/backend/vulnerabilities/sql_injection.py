"""Intentionally unsafe educational fixture. Never use in production."""

import sqlite3


def vulnerable_sql_lookup(
    connection: sqlite3.Connection, username: str
) -> list[tuple[object, ...]]:
    """CWE-89: interpolate untrusted input instead of binding SQL parameters."""
    return connection.execute(
        f"SELECT id, username FROM users WHERE username = '{username}'"
    ).fetchall()
