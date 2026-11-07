"""SQLite access: schema, connection and the transaction helper.

All state-changing work happens inside `tx()`, which opens BEGIN IMMEDIATE.
That takes SQLite's write lock up front, so an authorisation decision, the
change it permits and its audit record are one atomic unit, and a concurrent
revocation either happens entirely before or entirely after it.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name           TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
    pw_hash        TEXT NOT NULL,
    active         INTEGER NOT NULL DEFAULT 1,
    must_change_pw INTEGER NOT NULL DEFAULT 0,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,
    created_at     TEXT NOT NULL
);

-- Only a SHA-256 of the session token is stored: a database leak does not
-- hand out live sessions. A session carries no permissions; rights are
-- recomputed from the database on every request.
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    csrf       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    ip         TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL REFERENCES users(id),
    name            TEXT NOT NULL,
    category        TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    deleted_at      TEXT,
    deleted_by      TEXT,
    purged_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS versions (
    id                TEXT PRIMARY KEY,
    document_id       TEXT NOT NULL REFERENCES documents(id),
    version           INTEGER NOT NULL,
    blob_id           TEXT UNIQUE,          -- NULL after purge
    wrapped_key       BLOB,                 -- NULL after purge (crypto-shred)
    size              INTEGER NOT NULL,
    sha256            TEXT NOT NULL,
    mime              TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    uploaded_by       TEXT NOT NULL REFERENCES users(id),
    created_at        TEXT NOT NULL,
    UNIQUE (document_id, version)
);

CREATE TABLE IF NOT EXISTS grants (
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    level       TEXT NOT NULL CHECK (level IN ('read','edit')),
    granted_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT,
    PRIMARY KEY (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);

-- Append-only, hash-chained. See audit.py and the triggers below.
CREATE TABLE IF NOT EXISTS audit_log (
    seq            INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    actor_id       TEXT,
    actor_email    TEXT,
    action         TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('allowed','denied')),
    doc_id         TEXT,
    target_user_id TEXT,
    detail         TEXT NOT NULL,
    ip             TEXT,
    prev_hash      TEXT NOT NULL,
    hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc    ON audit_log(doc_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor_id, ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, ts);
CREATE INDEX IF NOT EXISTS idx_audit_ip     ON audit_log(ip, ts);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- Rule-based sharing suggestions. A suggestion never grants anything.
CREATE TABLE IF NOT EXISTS suggestions (
    id          TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id),
    user_id     TEXT NOT NULL REFERENCES users(id),
    level       TEXT NOT NULL CHECK (level IN ('read')),
    reason      TEXT NOT NULL,
    provider    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','accepted','dismissed')),
    created_at  TEXT NOT NULL,
    decided_by  TEXT,
    decided_at  TEXT
);
"""


def connect(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_db(path: Path | str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.umask(0o077)  # new files (db, -wal, -shm) are owner-only
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()
    if os.name != "nt":
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(path) + suffix)
            if p.exists():
                os.chmod(p, 0o600)  # tighten files that already exist


@contextlib.contextmanager
def tx(conn: sqlite3.Connection):
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception."""
    if conn.in_transaction:
        raise RuntimeError("nested transaction")
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")