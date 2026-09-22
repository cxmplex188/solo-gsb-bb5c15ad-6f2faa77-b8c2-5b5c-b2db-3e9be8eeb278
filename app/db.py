"""SQLite storage for consumed one-time nonces and subject revocations.

Only nonces of *one-time* tokens need to be remembered server side: the
signature and expiry of every other claim are verified statelessly. Subject
revocations are the other stateful piece: each row pins a ``cutoff`` timestamp
to a subject, and any token of that subject issued at or before the cutoff is
rejected.

Both checks run inside a single ``IMMEDIATE`` transaction at verify time, so
a revocation can never race a nonce consumption: a revoked subject's token is
rejected *without* burning its nonce, and the primary-key uniqueness on
consumed nonces serialises concurrent replays.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_consumed_nonces_expires_at
    ON consumed_nonces (expires_at);

CREATE TABLE IF NOT EXISTS subject_revocations (
    subject     TEXT PRIMARY KEY,
    cutoff      INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    purge_after INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_subject_revocations_purge_after
    ON subject_revocations (purge_after);
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

    def check_revocation_and_consume(
        self,
        *,
        subject: str | None,
        issued_at: int,
        nonce: str | None,
        nonce_expires_at: int | None,
    ) -> str:
        """Apply the stateful verification steps in one atomic transaction.

        Inside a single ``BEGIN IMMEDIATE`` transaction:

        * if *subject* has a revocation row and ``issued_at <= cutoff`` the
          token is rejected as ``"subject_revoked"`` and the nonce is
          deliberately *not* consumed (a later restore keeps it usable);
        * if *nonce* is given, it is consumed; an already-present nonce means
          a replay (``"nonce_replayed"``). The database-level unique
          constraint serialises concurrent attempts.

        Returns ``"ok"`` when the token may proceed.
        """
        with self.connect() as conn:
            try:
                # IMMEDIATE acquires a RESERVED lock immediately, so the
                # revocation read and the nonce insert see one consistent
                # snapshot and racing writers serialise cleanly.
                conn.execute("BEGIN IMMEDIATE")
                if subject is not None:
                    row = conn.execute(
                        "SELECT cutoff FROM subject_revocations WHERE subject = ?",
                        (subject,),
                    ).fetchone()
                    if row is not None and issued_at <= row["cutoff"]:
                        conn.rollback()
                        return "subject_revoked"
                if nonce is not None:
                    cursor = conn.execute(
                        "INSERT OR IGNORE INTO consumed_nonces (nonce, expires_at) VALUES (?, ?)",
                        (nonce, nonce_expires_at),
                    )
                    if cursor.rowcount != 1:
                        conn.rollback()
                        return "nonce_replayed"
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return "ok"

    def revoke_subject(
        self,
        subject: str,
        *,
        cutoff: int,
        purge_after: int,
        now: int | None = None,
    ) -> None:
        """Record (or overwrite) a revocation cutoff for *subject*.

        ``purge_after`` is precomputed by the caller as ``cutoff + max_ttl``:
        every token the cutoff can reject expires by then, so the row becomes
        dead weight afterwards and is removed by :meth:`purge_expired`.
        """
        now = int(time.time()) if now is None else now
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO subject_revocations (subject, cutoff, created_at, purge_after)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(subject) DO UPDATE SET
                        cutoff      = excluded.cutoff,
                        created_at  = excluded.created_at,
                        purge_after = excluded.purge_after
                    """,
                    (subject, cutoff, now, purge_after),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def restore_subject(self, subject: str) -> bool:
        """Delete a subject's revocation row. Returns True when one existed."""
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "DELETE FROM subject_revocations WHERE subject = ?", (subject,)
                )
                removed = cursor.rowcount == 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return removed

    def list_revocations(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT subject, cutoff, created_at, purge_after "
                "FROM subject_revocations ORDER BY subject"
            ).fetchall()
        return [dict(row) for row in rows]

    def purge_expired(self, now: int | None = None) -> tuple[int, int]:
        """Delete dead rows; returns (nonce rows, revocation rows) removed.

        A revocation with cutoff ``T`` can only reject tokens with
        ``iat <= T``, and every such token has ``exp <= T + max_ttl``. Once
        ``now >= purge_after`` no live token can hit the row, so it is safe
        to drop.
        """
        now = int(time.time()) if now is None else now
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                nonces = conn.execute(
                    "DELETE FROM consumed_nonces WHERE expires_at < ?", (now,)
                ).rowcount
                revocations = conn.execute(
                    "DELETE FROM subject_revocations WHERE purge_after <= ?", (now,)
                ).rowcount
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return nonces, revocations
