"""Tamper-evident audit trail.

Each row stores prev_hash and hash = HMAC-SHA256(audit_key, prev_hash || canonical(row)).
Three layers stop the trail being quietly altered:

1. The application has no code path that updates or deletes audit rows.
2. SQLite triggers abort any UPDATE or DELETE on the table.
3. Someone with raw database-file access can drop the triggers, but cannot
   re-compute the chain without the audit key, which is not in the database.
   `verify()` finds any edited, removed-from-the-middle or re-ordered row.

Known limit (see THREATS.md): deleting the *tail* of the chain leaves a valid
shorter chain. Defeating that needs the head hash anchored somewhere the
attacker cannot write; `head()` is provided for exactly that.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3

from . import clock
from .config import Config

GENESIS = "0" * 64
_FIELDS = ("seq", "ts", "actor_id", "actor_email", "action", "outcome",
           "doc_id", "target_user_id", "detail", "ip")


def _digest(key: bytes, prev_hash: str, row: dict) -> str:
    canonical = json.dumps({k: row[k] for k in _FIELDS}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, (prev_hash + canonical).encode(), hashlib.sha256).hexdigest()


def append(db: sqlite3.Connection, cfg: Config, *, actor, action: str, outcome: str,
           doc_id: str | None = None, target_user_id: str | None = None,
           detail: dict | None = None, ip: str | None = None,
           actor_email: str | None = None) -> int:
    """Add one record. Must run inside db.tx() so the record commits (or rolls
    back) together with the change it describes."""
    if not db.in_transaction:
        raise RuntimeError("audit.append must be called inside a transaction")
    last = db.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    seq = (last["seq"] + 1) if last else 1
    prev = last["hash"] if last else GENESIS
    row = {
        "seq": seq,
        "ts": clock.now(),
        "actor_id": actor["id"] if actor else None,
        "actor_email": (actor["email"] if actor else actor_email),
        "action": action,
        "outcome": outcome,
        "doc_id": doc_id,
        "target_user_id": target_user_id,
        "detail": json.dumps(detail or {}, sort_keys=True, separators=(",", ":")),
        "ip": ip,
    }
    row["prev_hash"] = prev
    row["hash"] = _digest(cfg.audit_key, prev, row)
    db.execute(
        "INSERT INTO audit_log (seq, ts, actor_id, actor_email, action, outcome, doc_id,"
        " target_user_id, detail, ip, prev_hash, hash) VALUES"
        " (:seq,:ts,:actor_id,:actor_email,:action,:outcome,:doc_id,:target_user_id,"
        ":detail,:ip,:prev_hash,:hash)", row)
    return seq


def record(db: sqlite3.Connection, cfg: Config, **kwargs) -> int:
    """Append in its own transaction (for events with no accompanying change,
    such as a refused request)."""
    from .db import tx
    with tx(db):
        return append(db, cfg, **kwargs)


def verify(db: sqlite3.Connection, cfg: Config) -> dict:
    prev = GENESIS
    expected_seq = 1
    count = 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
        row = dict(r)
        problem = None
        if row["seq"] != expected_seq:
            problem = "sequence gap or reorder"
        elif row["prev_hash"] != prev:
            problem = "broken link to previous record"
        elif not hmac.compare_digest(row["hash"], _digest(cfg.audit_key, prev, row)):
            problem = "record content does not match its hash"
        if problem:
            return {"ok": False, "first_bad_seq": row["seq"], "problem": problem,
                    "records_checked": count, "head": None}
        prev = row["hash"]
        expected_seq += 1
        count += 1
    return {"ok": True, "first_bad_seq": None, "problem": None,
            "records_checked": count, "head": prev}


def head(db: sqlite3.Connection) -> dict:
    last = db.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    return {"seq": last["seq"], "hash": last["hash"]} if last else {"seq": 0, "hash": GENESIS}
