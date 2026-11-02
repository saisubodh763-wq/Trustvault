"""Administrator endpoints. Admins manage people and watch activity; they hold no
content rights (see authz.py), so nothing here reads, downloads or edits a file.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from . import audit, clock
from . import validation as val
from .security import hash_password, password_problem, temp_password
from .web import ApiError, authed, cfg, client_ip, get_db, json_body

bp = Blueprint("admin", __name__, url_prefix="/api/admin")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$")
ROLES = ("admin", "owner", "viewer")


def _user_json(u) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "active": bool(u["active"]), "must_change_pw": bool(u["must_change_pw"]),
            "locked_until": u["locked_until"], "created_at": u["created_at"]}


def _revoke_sessions(db, user_id: str) -> int:
    cur = db.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                     (clock.now(), user_id))
    return cur.rowcount


def _owns_live_documents(db, user_id: str) -> bool:
    return db.execute("SELECT 1 FROM documents WHERE owner_id=? AND purged_at IS NULL LIMIT 1",
                      (user_id,)).fetchone() is not None


# ---------------------------------------------------------------- users

@bp.get("/users")
@authed(role="admin")
def list_users():
    rows = get_db().execute("SELECT * FROM users ORDER BY email").fetchall()
    return jsonify({"items": [_user_json(r) for r in rows]})


@bp.post("/users")
@authed(role="admin", write=True)
def create_user():
    db = get_db()
    body = json_body()
    email = str(body.get("email", "")).strip().lower()
    role = body.get("role")
    try:
        name = val.clean_text(body.get("name"), "name", 100)
    except val.ValidationError as exc:
        raise ApiError(422, str(exc))
    if not EMAIL_RE.match(email):
        raise ApiError(422, "a valid email is required")
    if role not in ROLES:
        raise ApiError(422, "role must be admin, owner or viewer")
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        raise ApiError(409, "a user with that email already exists")
    temp = temp_password()
    uid = str(uuid.uuid4())
    db.execute("INSERT INTO users (id,email,name,role,pw_hash,must_change_pw,created_at)"
               " VALUES (?,?,?,?,?,1,?)", (uid, email, name, role, hash_password(temp), clock.now()))
    audit.append(db, cfg(), actor=g.user, action="user.create", outcome="allowed",
                 target_user_id=uid, detail={"email": email, "role": role}, ip=client_ip())
    return jsonify({"id": uid, "email": email, "temporary_password": temp,
                    "note": "Shown once. The user must change it at first login."}), 201


@bp.patch("/users/<user_id>")
@authed(role="admin", write=True)
def update_user(user_id):
    db = get_db()
    body = json_body()
    unknown = set(body) - {"role", "active"}
    if unknown:
        raise ApiError(400, f"cannot change: {', '.join(sorted(unknown))}")
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise ApiError(404, "user not found")
    if target["id"] == g.user["id"]:
        raise ApiError(409, "you cannot change your own role or status")
    changes = {}
    if "role" in body:
        if body["role"] not in ROLES:
            raise ApiError(422, "role must be admin, owner or viewer")
        if body["role"] != target["role"]:
            if target["role"] == "owner" and _owns_live_documents(db, target["id"]):
                raise ApiError(409, "this user owns documents; changing their role would orphan them")
            changes["role"] = body["role"]
    if "active" in body:
        if not isinstance(body["active"], bool):
            raise ApiError(422, "active must be true or false")
        if body["active"] != bool(target["active"]):
            changes["active"] = int(body["active"])
    if not changes:
        raise ApiError(400, "nothing to change")
    db.execute("UPDATE users SET " + ", ".join(f"{k}=?" for k in changes) + " WHERE id=?",
               [*changes.values(), target["id"]])
    revoked = _revoke_sessions(db, target["id"])      # takes effect on the very next request
    action = "user.disable" if changes.get("active") == 0 else "user.update"
    audit.append(db, cfg(), actor=g.user, action=action, outcome="allowed",
                 target_user_id=target["id"],
                 detail={"email": target["email"], "changes": changes,
                         "sessions_revoked": revoked}, ip=client_ip())
    return jsonify({"ok": True, "sessions_revoked": revoked})


@bp.post("/users/<user_id>/reset-password")
@authed(role="admin", write=True)
def reset_password(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise ApiError(404, "user not found")
    if target["id"] == g.user["id"]:
        raise ApiError(409, "use change-password for your own account")
    temp = temp_password()
    db.execute("UPDATE users SET pw_hash=?, must_change_pw=1, failed_logins=0, locked_until=NULL"
               " WHERE id=?", (hash_password(temp), target["id"]))
    revoked = _revoke_sessions(db, target["id"])
    audit.append(db, cfg(), actor=g.user, action="user.password_reset", outcome="allowed",
                 target_user_id=target["id"],
                 detail={"email": target["email"], "sessions_revoked": revoked}, ip=client_ip())
    return jsonify({"temporary_password": temp,
                    "note": "Shown once. The account is unusable until the password is changed."})


@bp.post("/users/<user_id>/revoke-sessions")
@authed(role="admin", write=True)
def revoke_sessions(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if target is None:
        raise ApiError(404, "user not found")
    revoked = _revoke_sessions(db, target["id"])
    audit.append(db, cfg(), actor=g.user, action="session.revoke", outcome="allowed",
                 target_user_id=target["id"], detail={"email": target["email"], "revoked": revoked},
                 ip=client_ip())
    return jsonify({"revoked": revoked})


# ---------------------------------------------------------------- document activity (metadata only)

@bp.get("/documents")
@authed(role="admin")
def all_documents():
    """Metadata for every document, so activity can be understood. No names of
    files' contents, no download path: admins cannot read documents."""
    rows = get_db().execute(
        "SELECT d.id, d.name, d.category, d.created_at, d.updated_at, d.deleted_at, d.purged_at,"
        " d.current_version, u.email AS owner_email,"
        " (SELECT COUNT(*) FROM grants g WHERE g.document_id=d.id) AS grant_count,"
        " (SELECT COUNT(*) FROM audit_log a WHERE a.doc_id=d.id AND a.action='document.download'"
        "  AND a.outcome='allowed') AS downloads,"
        " (SELECT COUNT(*) FROM audit_log a WHERE a.doc_id=d.id AND a.outcome='denied') AS refused"
        " FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.updated_at DESC").fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


# ---------------------------------------------------------------- audit

@bp.get("/audit")
@authed(role="admin")
def audit_list():
    q = request.args
    where, args = [], []
    for column, key in (("action", "action"), ("outcome", "outcome"), ("doc_id", "doc_id"),
                        ("actor_id", "actor_id"), ("target_user_id", "target_user_id")):
        if q.get(key):
            where.append(f"{column} = ?"); args.append(q[key][:64])
    if q.get("actor"):
        where.append("lower(actor_email) = lower(?)"); args.append(q["actor"][:254])
    if q.get("from"):
        where.append("ts >= ?"); args.append(q["from"][:30])
    if q.get("to"):
        where.append("ts <= ?"); args.append(q["to"][:30])
    try:
        limit = max(1, min(int(q.get("limit", 100)), 500))
        offset = max(0, int(q.get("offset", 0)))
    except ValueError:
        raise ApiError(400, "limit and offset must be integers")
    sql_where = (" WHERE " + " AND ".join(where)) if where else ""
    db = get_db()
    total = db.execute("SELECT COUNT(*) c FROM audit_log" + sql_where, args).fetchone()["c"]
    rows = db.execute("SELECT seq,ts,actor_id,actor_email,action,outcome,doc_id,target_user_id,"
                      "detail,ip FROM audit_log" + sql_where + " ORDER BY seq DESC LIMIT ? OFFSET ?",
                      args + [limit, offset]).fetchall()
    return jsonify({"total": total,
                    "items": [dict(r, detail=json.loads(r["detail"])) for r in rows]})


@bp.get("/audit/verify")
@authed(role="admin")
def audit_verify():
    return jsonify(audit.verify(get_db(), cfg()))


@bp.get("/alerts")
@authed(role="admin")
def alerts():
    """What is worth noticing. Each rule is a plain query over the audit trail."""
    db = get_db()
    now = clock.now_dt()
    day = clock.fmt(now - timedelta(hours=24))
    hour = clock.fmt(now - timedelta(hours=1))
    out = []

    def add(severity, kind, summary, **extra):
        out.append({"severity": severity, "kind": kind, "summary": summary, **extra})

    check = audit.verify(db, cfg())
    if not check["ok"]:
        add("critical", "audit_chain_broken",
            f"Audit trail fails verification at record {check['first_bad_seq']}: {check['problem']}")

    for r in db.execute(
            "SELECT actor_email, COUNT(*) c FROM audit_log WHERE action='document.access_denied'"
            " AND ts > ? GROUP BY actor_email HAVING c >= 3 ORDER BY c DESC", (day,)):
        add("high", "repeated_refusals",
            f"{r['actor_email']} was refused access to documents {r['c']} times in 24h", count=r["c"])

    for r in db.execute(
            "SELECT actor_email, COUNT(*) c FROM audit_log WHERE action='document.download'"
            " AND outcome='allowed' AND ts > ? GROUP BY actor_email HAVING c >= 10"
            " ORDER BY c DESC", (hour,)):
        add("high", "bulk_download", f"{r['actor_email']} downloaded {r['c']} files in the last hour",
            count=r["c"])

    for r in db.execute(
            "SELECT actor_email, COUNT(*) c FROM audit_log WHERE action='auth.login'"
            " AND outcome='denied' AND ts > ? GROUP BY actor_email HAVING c >= 5 ORDER BY c DESC",
            (hour,)):
        add("medium", "failed_logins", f"{r['actor_email']}: {r['c']} failed logins in the last hour",
            count=r["c"])

    for r in db.execute(
            "SELECT a.target_user_id, u.email, a.ts FROM audit_log a JOIN users u ON u.id=a.target_user_id"
            " WHERE a.action='user.password_reset' AND a.ts > ? ORDER BY a.ts DESC", (day,)):
        later = db.execute("SELECT COUNT(*) c FROM audit_log WHERE action='auth.login' AND outcome='allowed'"
                           " AND actor_id=? AND ts >= ?", (r["target_user_id"], r["ts"])).fetchone()["c"]
        add("high" if later else "medium", "password_reset",
            f"Password for {r['email']} was reset by an administrator at {r['ts']}"
            + ("; the account has logged in since" if later else ""))

    for r in db.execute(
            "SELECT a.ts, a.actor_email, a.detail, a.doc_id FROM audit_log a WHERE a.action IN"
            " ('grant.add','grant.change') AND a.ts > ? ORDER BY a.ts DESC LIMIT 50", (day,)):
        d = json.loads(r["detail"])
        if d.get("level") == "edit":
            add("low", "edit_grant", f"{r['actor_email']} gave edit access to {d.get('target')}",
                doc_id=r["doc_id"])

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out.sort(key=lambda a: rank[a["severity"]])
    return jsonify({"generated_at": clock.now(), "items": out})
