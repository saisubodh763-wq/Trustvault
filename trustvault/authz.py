"""THE authorisation decision. Every route that touches a document, directly or
through a list/search, gets its answer from this module and nowhere else.

Permission model
----------------
* Roles:   admin | owner | viewer.
* Rights on one document are one of: owner > edit > read > nothing.
* A document's owner (who must currently hold the `owner` role) has `owner`.
* Anyone else needs a per-document grant (read or edit), unexpired.
* Role caps apply at decision time, not only at grant time: a `viewer` can never
  exceed `read`, whatever grant rows say, so demoting someone takes effect
  immediately.
* `admin` accounts have NO content rights, ever. They manage people and read the
  audit trail; they cannot read, download, edit or share documents, and cannot
  be granted access. (Separation of duties; see THREATS.md for the trade-off.)
* Deleted or purged documents are invisible to everyone except the owner, who
  may only restore or inspect them.
* Unknown actions raise KeyError: the system fails closed.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import clock

RANK = {"read": 1, "edit": 2, "owner": 3}

# action -> minimum right required
ACTION_NEEDS = {
    "read": "read",
    "download": "read",
    "edit": "edit",
    "new_version": "edit",
    "delete": "owner",
    "restore": "owner",
    "share": "owner",
    "view_grants": "owner",
    "view_audit": "owner",
}
# The only actions an owner may perform on a deleted (not purged) document.
DELETED_OK = {"restore", "view_grants", "view_audit"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    level: str | None = None        # effective right the user holds, if any
    can_read: bool = False          # user holds at least read (drives 403 vs 404)


def effective_level(db: sqlite3.Connection, user, doc) -> str | None:
    """Turn database rows into one right. The only place that does so."""
    if not user["active"] or user["must_change_pw"]:
        return None
    if user["role"] == "admin":
        return None
    if user["role"] == "owner" and doc["owner_id"] == user["id"]:
        return "owner"
    grant = db.execute(
        "SELECT level FROM grants WHERE document_id = ? AND user_id = ?"
        " AND (expires_at IS NULL OR expires_at > ?)",
        (doc["id"], user["id"], clock.now()),
    ).fetchone()
    if grant is None:
        return None
    level = grant["level"]
    if user["role"] == "viewer":
        level = "read"                       # role cap
    return level


def authorize(db: sqlite3.Connection, user, doc_id: str, action: str):
    """Return (Decision, doc-row-or-None). The row is returned only on allow."""
    needed = ACTION_NEEDS[action]            # KeyError => fail closed
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:
        return Decision(False, "not_found"), None
    if doc["purged_at"] is not None:
        return Decision(False, "purged"), None
    level = effective_level(db, user, doc)
    if level is None:
        return Decision(False, "no_access"), None
    if doc["deleted_at"] is not None and action not in DELETED_OK:
        return Decision(False, "deleted", level=level), None
    if RANK[level] < RANK[needed]:
        return Decision(False, "insufficient_level", level=level, can_read=True), None
    return Decision(True, "ok", level=level, can_read=True), doc


def visible_clause(user) -> tuple[str, list]:
    """SQL fragment (alias `d` = documents) selecting live documents `user` may
    read. Used by list/search. A test asserts it agrees with authorize() for
    every user and document, so the two cannot drift apart unnoticed."""
    if not user["active"] or user["must_change_pw"] or user["role"] == "admin":
        return "0", []
    grant = ("EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id"
             " AND g.user_id = ? AND (g.expires_at IS NULL OR g.expires_at > ?))")
    if user["role"] == "owner":
        return f"(d.owner_id = ? OR {grant})", [user["id"], user["id"], clock.now()]
    return grant, [user["id"], clock.now()]


def access_label(db: sqlite3.Connection, user, doc) -> str | None:
    return effective_level(db, user, doc)
