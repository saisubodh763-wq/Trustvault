"""Tamper-evident audit trail.

Each row stores prev_hash and hash = HMAC-SHA256(audit_key, prev_hash || canonical(row)).
Three layers stop the trail being quietly altered:

1. The application has no code path that updates or deletes audit rows.
2. SQLite triggers abort any UPDATE or DELETE on the table.
3. Someone with raw database-file access can drop the triggers, but cannot
   re-compute the chain without the audit key, which is not in the database.
   `verify()` finds any edited, removed-from-the-middle or re-ordered row.

Deleting the *tail* of the chain leaves a valid shorter chain, so the chain
alone cannot detect it. Anchors close that gap: `flask audit-anchor` appends
"seq hash timestamp mac" to a file kept OUTSIDE the data directory (ideally on
append-only or separate storage, or mailed/shipped off the box). `verify_anchors`
then requires every anchored record to still exist with the same hash. Anchors
are MAC'd with the audit key, so an invented line is rejected too.

What this still cannot detect: records written *after* the newest anchor and then
removed. Anchor often (cron) to shrink that window; the window is the interval.
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


# ----------------------------------------------------------------- anchors

def _anchor_mac(key: bytes, seq: int, hash_: str, ts: str) -> str:
    return hmac.new(key, f"anchor|{seq}|{hash_}|{ts}".encode(), hashlib.sha256).hexdigest()


def make_anchor(db: sqlite3.Connection, cfg: Config) -> str:
    """One line describing the current chain head, signed with the audit key."""
    h = head(db)
    ts = clock.now()
    return f"{h['seq']} {h['hash']} {ts} {_anchor_mac(cfg.audit_key, h['seq'], h['hash'], ts)}"


def write_anchor(db: sqlite3.Connection, cfg: Config) -> str:
    """Append an anchor to the configured file (and return the line so the
    operator can also ship it elsewhere: email, ticket, object store)."""
    if cfg.anchor_file is None:
        raise RuntimeError("TRUSTVAULT_ANCHOR_FILE is not set")
    verified = verify(db, cfg)
    if not verified["ok"]:
        raise RuntimeError("refusing to anchor a chain that fails verification")
    line = make_anchor(db, cfg)
    cfg.anchor_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg.anchor_file, "a", encoding="ascii") as fh:
        fh.write(line + "\n")
        fh.flush()
        import os
        os.fsync(fh.fileno())
    return line


def verify_anchors(db: sqlite3.Connection, cfg: Config) -> dict:
    """Every anchored (seq, hash) must still be in the chain, unchanged."""
    if cfg.anchor_file is None:
        return {"configured": False, "ok": None, "anchors_checked": 0, "problem": None}
    try:
        lines = [ln for ln in cfg.anchor_file.read_text(encoding="ascii").splitlines() if ln.strip()]
    except FileNotFoundError:
        return {"configured": True, "ok": None, "anchors_checked": 0,
                "problem": "no anchors written yet"}
    except (OSError, UnicodeDecodeError):
        return {"configured": True, "ok": False, "anchors_checked": 0,
                "problem": "anchor file is unreadable"}
    checked = 0
    for n, line in enumerate(lines, 1):
        parts = line.split(" ")
        try:
            seq, hash_, ts, mac = int(parts[0]), parts[1], parts[2], parts[3]
            if len(parts) != 4:
                raise ValueError
        except (ValueError, IndexError):
            return {"configured": True, "ok": False, "anchors_checked": checked,
                    "problem": f"anchor line {n} is malformed"}
        if not hmac.compare_digest(mac, _anchor_mac(cfg.audit_key, seq, hash_, ts)):
            return {"configured": True, "ok": False, "anchors_checked": checked,
                    "problem": f"anchor line {n} has an invalid signature"}
        row = db.execute("SELECT hash FROM audit_log WHERE seq = ?", (seq,)).fetchone()
        if row is None:
            return {"configured": True, "ok": False, "anchors_checked": checked,
                    "problem": f"record {seq} was anchored at {ts} but is missing "
                               f"(log truncated or rows deleted)"}
        if not hmac.compare_digest(row["hash"], hash_):
            return {"configured": True, "ok": False, "anchors_checked": checked,
                    "problem": f"record {seq} no longer matches its anchor from {ts}"}
        checked += 1
    return {"configured": True, "ok": True, "anchors_checked": checked, "problem": None}
