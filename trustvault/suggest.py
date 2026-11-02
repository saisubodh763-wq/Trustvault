"""Sharing suggestions.

This is where AI belongs in the product, and it is deliberately boxed in:

* A suggestion is advice stored for the owner. It grants nothing.
* The only way to widen access is the grant endpoint, called by the owner.
* Suggestions can only ever propose `read`, never `edit`.
* Generation, acceptance and dismissal are all audit events, so the record shows
  both what the machine proposed and what the person decided.
* A provider sees metadata only (category, who already shares what). It is never
  given document contents.

The shipped provider is a transparent rule ("rules-v1"): people who already
hold access to other live documents the same owner filed in the same category.
It has the same interface a language-model provider would use; swapping one in
changes nothing about the guarantees above, because nothing here can grant.
"""
from __future__ import annotations

import sqlite3
import uuid

from . import clock

PROVIDER = "rules-v1"


def generate(db: sqlite3.Connection, doc) -> list[dict]:
    rows = db.execute(
        """
        SELECT u.id AS user_id, u.email, u.name, COUNT(DISTINCT d2.id) AS shared_docs
        FROM documents d2
        JOIN grants g ON g.document_id = d2.id AND (g.expires_at IS NULL OR g.expires_at > ?)
        JOIN users u  ON u.id = g.user_id AND u.active = 1 AND u.role <> 'admin'
        WHERE d2.owner_id = ? AND d2.id <> ? AND d2.deleted_at IS NULL AND d2.purged_at IS NULL
          AND lower(d2.category) = lower(?)
          AND u.id <> ?
          AND NOT EXISTS (SELECT 1 FROM grants gx WHERE gx.document_id = ? AND gx.user_id = u.id)
        GROUP BY u.id ORDER BY shared_docs DESC, u.email LIMIT 5
        """,
        (clock.now(), doc["owner_id"], doc["id"], doc["category"], doc["owner_id"], doc["id"]),
    ).fetchall()
    out = []
    for r in rows:
        s = {
            "id": str(uuid.uuid4()), "document_id": doc["id"], "user_id": r["user_id"],
            "email": r["email"], "name": r["name"], "level": "read",
            "reason": f"already has access to {r['shared_docs']} other '{doc['category']}' "
                      f"document(s) you own",
        }
        db.execute(
            "INSERT INTO suggestions (id,document_id,user_id,level,reason,provider,created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (s["id"], doc["id"], r["user_id"], "read", s["reason"], PROVIDER, clock.now()))
        out.append(s)
    return out
