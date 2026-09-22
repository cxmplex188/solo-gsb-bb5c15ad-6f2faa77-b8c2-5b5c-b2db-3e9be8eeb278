"""SQLite storage for consumed one-time nonces.

Only nonces of *one-time* tokens need to be remembered server side: the
signature and expiry of every other claim are verified statelessly.

Nonce consumption is atomic (``INSERT`` + primary-key uniqueness inside an
``IMMEDIATE`` transaction), so concurrent requests presenting the same token
cannot both succeed.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_consumed_nonces_expires_at
    ON consumed_nonces (expires_at);
"""


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        # Initialise the schema eagerly so first request never blocks on it.
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            yield conn
        finally:
            conn.close()

    def is_nonce_consumed(self, nonce: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM consumed_nonces WHERE nonce = ?", (nonce,)
            ).fetchone()
        return row is not None

    def consume_nonce(self, nonce: str, expires_at: int) -> bool:
        """Atomically record a nonce as consumed.

        Returns ``True`` when *this* call performed the insertion, ``False``
        if the nonce had already been consumed (a replay). The database-level
        unique constraint serialises concurrent attempts.
        """
        with self.connect() as conn:
            try:
                # IMMEDIATE acquires a RESERVED lock immediately, turning two
                # racing inserts into a clean UNIQUE failure for the loser.
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO consumed_nonces (nonce, expires_at) VALUES (?, ?)",
                    (nonce, expires_at),
                )
                inserted = cursor.rowcount == 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return inserted

    def purge_expired(self, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "DELETE FROM consumed_nonces WHERE expires_at < ?", (now,)
                )
                removed = cursor.rowcount
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return removed
