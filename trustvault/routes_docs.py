"""Document endpoints. Every route with a <doc_id> is wrapped by @doc_route,
which makes the authorisation decision (authz.authorize) before the handler runs
and hands the handler the authorised row. Handlers never fetch a document by an
id taken from the request themselves."""
from __future__ import annotations

import json
import re
import uuid
from datetime import date, timedelta
from urllib.parse import quote

from flask import Blueprint, Response, g, jsonify, request

from . import audit, authz, clock, storage, suggest
from . import validation as val
from .web import ApiError, authed, cfg, client_ip, doc_route, get_db, json_body

bp = Blueprint("docs", __name__, url_prefix="/api")


# ---------------------------------------------------------------- helpers

def _upload_from_request():
    f = request.files.get("file")
    if f is None or not f.filename:
        raise ApiError(400, "a file is required (multipart field 'file')")
    data = f.read()
    # MAX_CONTENT_LENGTH is only the transport guard (it includes multipart
    # overhead); the file's own size limit is enforced here, exactly.
    if len(data) > cfg().max_upload_bytes:
        raise ApiError(413, f"file exceeds the {cfg().max_upload_bytes // (1024 * 1024) or 1} MB limit"
                       if cfg().max_upload_bytes >= 1024 * 1024 else "file is too large")
    try:
        name, ext, mime = val.validate_upload(f.filename, data)
    except val.ValidationError as exc:
        raise ApiError(422, str(exc))
    return data, name, mime


def _check_quota(db, owner_id: str, incoming: int):
    used = db.execute(
        "SELECT COALESCE(SUM(v.size),0) s FROM versions v JOIN documents d ON d.id=v.document_id"
        " WHERE d.owner_id=? AND v.blob_id IS NOT NULL", (owner_id,)).fetchone()["s"]
    if used + incoming > cfg().owner_quota_bytes:
        raise ApiError(413, "storage quota exceeded")


def _store_version(db, doc_id: str, version: int, data: bytes, name: str, mime: str, user):
    import hashlib
    blob_id, wrapped = storage.put(cfg(), data, doc_id, version)
    sha = hashlib.sha256(data).hexdigest()
    try:
        db.execute(
            "INSERT INTO versions (id,document_id,version,blob_id,wrapped_key,size,sha256,mime,"
            "original_filename,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), doc_id, version, blob_id, wrapped, len(data), sha, mime, name,
             user["id"], clock.now()))
    except Exception:
        storage.remove(cfg(), blob_id)
        raise
    return blob_id, sha


def _doc_json(db, user, d) -> dict:
    return {
        "id": d["id"], "name": d["name"], "category": d["category"],
        "description": d["description"], "created_at": d["created_at"],
        "updated_at": d["updated_at"], "current_version": d["current_version"],
        "owner_email": d["owner_email"], "owner_name": d["owner_name"],
        "size": d["size"], "mime": d["mime"], "filename": d["original_filename"],
        "my_access": authz.effective_level(db, user, d),
    }


_SELECT = ("SELECT d.*, u.email AS owner_email, u.name AS owner_name, v.size, v.mime,"
           " v.original_filename FROM documents d JOIN users u ON u.id=d.owner_id"
           " JOIN versions v ON v.document_id=d.id AND v.version=d.current_version")


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _parse_day(value: str, field: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ApiError(400, f"{field} must be YYYY-MM-DD")


# ---------------------------------------------------------------- create / list

@bp.post("/documents")
@authed(role="owner", write=True)
def upload():
    db, user = get_db(), g.user
    data, fname, mime = _upload_from_request()
    try:
        name = val.clean_text(request.form.get("name") or fname, "name", 200)
        category = val.clean_category(request.form.get("category"))
        description = val.clean_text(request.form.get("description"), "description", 1000,
                                     required=False)
    except val.ValidationError as exc:
        raise ApiError(422, str(exc))
    _check_quota(db, user["id"], len(data))
    doc_id, now = str(uuid.uuid4()), clock.now()
    db.execute("INSERT INTO documents (id,owner_id,name,category,description,created_at,"
               "updated_at,current_version) VALUES (?,?,?,?,?,?,?,1)",
               (doc_id, user["id"], name, category, description, now, now))
    _blob, sha = _store_version(db, doc_id, 1, data, fname, mime, user)
    audit.append(db, cfg(), actor=user, action="document.upload", outcome="allowed",
                 doc_id=doc_id, detail={"name": name, "category": category, "size": len(data),
                                        "sha256": sha, "version": 1}, ip=client_ip())
    return jsonify({"id": doc_id, "name": name, "version": 1}), 201


@bp.get("/documents")
@authed()
def list_documents():
    db, user = get_db(), g.user
    clause, params = authz.visible_clause(user)
    where, args = ["d.deleted_at IS NULL", "d.purged_at IS NULL", clause], list(params)
    q = request.args
    if q.get("q"):
        where.append("d.name LIKE ? ESCAPE '\\'"); args.append(_like(q["q"][:100]))
    if q.get("owner"):
        where.append("(lower(u.email)=lower(?) OR u.name LIKE ? ESCAPE '\\')")
        args += [q["owner"][:254], _like(q["owner"][:100])]
    if q.get("category"):
        where.append("lower(d.category)=lower(?)"); args.append(q["category"][:50])
    if q.get("from"):
        where.append("d.created_at >= ?"); args.append(_parse_day(q["from"], "from").isoformat())
    if q.get("to"):
        end = _parse_day(q["to"], "to") + timedelta(days=1)
        where.append("d.created_at < ?"); args.append(end.isoformat())
    try:
        limit = max(1, min(int(q.get("limit", 50)), 100))
        offset = max(0, int(q.get("offset", 0)))
    except ValueError:
        raise ApiError(400, "limit and offset must be integers")
    sql_where = " WHERE " + " AND ".join(where)       # fragments are constants; values are bound
    total = db.execute("SELECT COUNT(*) c FROM documents d JOIN users u ON u.id=d.owner_id"
                       + sql_where, args).fetchone()["c"]
    rows = db.execute(_SELECT + sql_where + " ORDER BY d.updated_at DESC, d.id LIMIT ? OFFSET ?",
                      args + [limit, offset]).fetchall()
    return jsonify({"total": total, "items": [_doc_json(db, user, r) for r in rows]})


@bp.get("/categories")
@authed()
def categories():
    db = get_db()
    clause, params = authz.visible_clause(g.user)
    rows = db.execute("SELECT DISTINCT d.category FROM documents d WHERE d.deleted_at IS NULL"
                      " AND d.purged_at IS NULL AND " + clause + " ORDER BY 1", params).fetchall()
    return jsonify({"items": [r["category"] for r in rows]})


@bp.get("/trash")
@authed(role="owner")
def trash():
    db = get_db()
    rows = db.execute(_SELECT + " WHERE d.owner_id=? AND d.deleted_at IS NOT NULL"
                      " AND d.purged_at IS NULL ORDER BY d.deleted_at DESC",
                      (g.user["id"],)).fetchall()
    return jsonify({"items": [dict(_doc_json(db, g.user, r), deleted_at=r["deleted_at"])
                              for r in rows], "purge_after_days": cfg().purge_after_days})


# ---------------------------------------------------------------- one document

@bp.get("/documents/<doc_id>")
@doc_route("read")
def detail(doc):
    db = get_db()
    row = db.execute(_SELECT + " WHERE d.id=?", (doc["id"],)).fetchone()
    versions = db.execute(
        "SELECT v.version, v.size, v.sha256, v.original_filename, v.created_at, u.email AS uploaded_by"
        " FROM versions v JOIN users u ON u.id=v.uploaded_by WHERE v.document_id=?"
        " AND v.blob_id IS NOT NULL ORDER BY v.version DESC", (doc["id"],)).fetchall()
    out = _doc_json(db, g.user, row)
    out["versions"] = [dict(v) for v in versions]
    return jsonify(out)


@bp.patch("/documents/<doc_id>")
@doc_route("edit")
def update(doc):
    db = get_db()
    body = json_body()
    allowed = {"name", "category", "description"}       # owner_id etc. can never be set here
    unknown = set(body) - allowed
    if unknown:
        raise ApiError(400, f"cannot change: {', '.join(sorted(unknown))}")
    changes = {}
    try:
        if "name" in body:
            changes["name"] = val.clean_text(body["name"], "name", 200)
        if "category" in body:
            changes["category"] = val.clean_category(body["category"])
        if "description" in body:
            changes["description"] = val.clean_text(body["description"], "description", 1000,
                                                    required=False)
    except val.ValidationError as exc:
        raise ApiError(422, str(exc))
    if not changes:
        raise ApiError(400, "nothing to change")
    before = {k: doc[k] for k in changes}
    db.execute("UPDATE documents SET " + ", ".join(f"{k}=?" for k in changes)
               + ", updated_at=? WHERE id=?", [*changes.values(), clock.now(), doc["id"]])
    audit.append(db, cfg(), actor=g.user, action="document.update", outcome="allowed",
                 doc_id=doc["id"], detail={"before": before, "after": changes}, ip=client_ip())
    return jsonify({"ok": True})


@bp.get("/documents/<doc_id>/download")
@doc_route("download")
def download(doc):
    db = get_db()
    try:
        version = int(request.args.get("version", doc["current_version"]))
    except ValueError:
        raise ApiError(400, "version must be an integer")
    v = db.execute("SELECT * FROM versions WHERE document_id=? AND version=? AND blob_id IS NOT NULL",
                   (doc["id"], version)).fetchone()
    if v is None:
        raise ApiError(404, "version not found")
    # No audit record, no bytes: if this append fails the transaction aborts.
    audit.append(db, cfg(), actor=g.user, action="document.download", outcome="allowed",
                 doc_id=doc["id"], detail={"version": version, "sha256": v["sha256"],
                                           "size": v["size"]}, ip=client_ip())
    try:
        content = storage.get(cfg(), v["blob_id"], v["wrapped_key"], doc["id"], v["version"])
    except storage.StorageError:
        raise ApiError(500, "stored file could not be verified")
    ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", v["original_filename"])
    resp = Response(content, mimetype=v["mime"])
    resp.headers["Content-Disposition"] = (
        f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(v['original_filename'])}")
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/documents/<doc_id>/versions")
@doc_route("new_version")
def new_version(doc):
    db = get_db()
    data, fname, mime = _upload_from_request()
    _check_quota(db, doc["owner_id"], len(data))
    number = doc["current_version"] + 1
    _blob, sha = _store_version(db, doc["id"], number, data, fname, mime, g.user)
    db.execute("UPDATE documents SET current_version=?, updated_at=? WHERE id=?",
               (number, clock.now(), doc["id"]))
    audit.append(db, cfg(), actor=g.user, action="document.version", outcome="allowed",
                 doc_id=doc["id"], detail={"version": number, "size": len(data), "sha256": sha},
                 ip=client_ip())
    return jsonify({"version": number}), 201


@bp.delete("/documents/<doc_id>")
@doc_route("delete")
def delete(doc):
    db = get_db()
    db.execute("UPDATE documents SET deleted_at=?, deleted_by=? WHERE id=?",
               (clock.now(), g.user["id"], doc["id"]))
    audit.append(db, cfg(), actor=g.user, action="document.delete", outcome="allowed",
                 doc_id=doc["id"], detail={"name": doc["name"]}, ip=client_ip())
    return jsonify({"ok": True, "recoverable_for_days": cfg().purge_after_days})


@bp.post("/documents/<doc_id>/restore")
@doc_route("restore")
def restore(doc):
    db = get_db()
    if doc["deleted_at"] is None:
        raise ApiError(409, "document is not deleted")
    db.execute("UPDATE documents SET deleted_at=NULL, deleted_by=NULL, updated_at=? WHERE id=?",
               (clock.now(), doc["id"]))
    audit.append(db, cfg(), actor=g.user, action="document.restore", outcome="allowed",
                 doc_id=doc["id"], detail={}, ip=client_ip())
    return jsonify({"ok": True})


@bp.get("/documents/<doc_id>/audit")
@doc_route("view_audit")
def document_audit(doc):
    rows = get_db().execute(
        "SELECT seq, ts, actor_email, action, outcome, target_user_id, detail, ip FROM audit_log"
        " WHERE doc_id=? ORDER BY seq DESC LIMIT 200", (doc["id"],)).fetchall()
    return jsonify({"items": [dict(r, detail=json.loads(r["detail"])) for r in rows]})


# ---------------------------------------------------------------- sharing

def _grant_json(r) -> dict:
    return {"user_id": r["user_id"], "email": r["email"], "name": r["name"], "role": r["role"],
            "level": r["level"], "granted_by": r["granted_by_email"],
            "created_at": r["created_at"], "expires_at": r["expires_at"],
            "expired": bool(r["expires_at"] and r["expires_at"] <= clock.now())}


@bp.get("/documents/<doc_id>/grants")
@doc_route("view_grants")
def list_grants(doc):
    rows = get_db().execute(
        "SELECT g.*, u.email, u.name, u.role, b.email AS granted_by_email FROM grants g"
        " JOIN users u ON u.id=g.user_id JOIN users b ON b.id=g.granted_by"
        " WHERE g.document_id=? ORDER BY u.email", (doc["id"],)).fetchall()
    return jsonify({"items": [_grant_json(r) for r in rows]})


@bp.post("/documents/<doc_id>/grants")
@doc_route("share")
def add_grant(doc):
    db, user = get_db(), g.user
    body = json_body()
    email = str(body.get("email", "")).strip().lower()[:254]
    level = body.get("level")
    if level not in ("read", "edit"):
        raise ApiError(400, "level must be 'read' or 'edit'")
    target = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
    if target is None:
        raise ApiError(404, "no active user with that email")
    if target["id"] == user["id"]:
        raise ApiError(400, "you already own this document")
    if target["role"] == "admin":
        raise ApiError(422, "administrator accounts cannot be given document access")
    if target["role"] == "viewer" and level == "edit":
        raise ApiError(422, "viewers can only be given read access")
    expires = None
    if body.get("expires_at"):
        try:
            exp = clock.parse(str(body["expires_at"]))
        except ValueError:
            raise ApiError(400, "expires_at must be an ISO date or time")
        if exp <= clock.now_dt():
            raise ApiError(400, "expires_at must be in the future")
        if exp > clock.now_dt() + timedelta(days=365):
            raise ApiError(400, "expires_at may be at most one year ahead")
        expires = clock.fmt(exp)

    suggestion = None
    if body.get("suggestion_id"):
        suggestion = db.execute(
            "SELECT * FROM suggestions WHERE id=? AND document_id=? AND user_id=?"
            " AND status='pending'", (str(body["suggestion_id"])[:64], doc["id"], target["id"])
        ).fetchone()
        if suggestion is None:
            raise ApiError(404, "no pending suggestion matches")

    existing = db.execute("SELECT level FROM grants WHERE document_id=? AND user_id=?",
                          (doc["id"], target["id"])).fetchone()
    db.execute(
        "INSERT INTO grants (document_id,user_id,level,granted_by,created_at,expires_at)"
        " VALUES (?,?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET level=excluded.level,"
        " granted_by=excluded.granted_by, created_at=excluded.created_at,"
        " expires_at=excluded.expires_at",
        (doc["id"], target["id"], level, user["id"], clock.now(), expires))
    detail = {"level": level, "expires_at": expires, "target": target["email"]}
    if existing:
        detail["previous_level"] = existing["level"]
    if suggestion:
        db.execute("UPDATE suggestions SET status='accepted', decided_by=?, decided_at=? WHERE id=?",
                   (user["id"], clock.now(), suggestion["id"]))
        detail["suggestion"] = {"id": suggestion["id"], "provider": suggestion["provider"],
                                "suggested_level": suggestion["level"],
                                "reason": suggestion["reason"],
                                "followed_exactly": suggestion["level"] == level}
    audit.append(db, cfg(), actor=user, action="grant.change" if existing else "grant.add",
                 outcome="allowed", doc_id=doc["id"], target_user_id=target["id"],
                 detail=detail, ip=client_ip())
    return jsonify({"ok": True, "email": target["email"], "level": level}), 201


@bp.delete("/documents/<doc_id>/grants/<user_id>")
@doc_route("share")
def revoke_grant(doc, user_id):
    db = get_db()
    row = db.execute("SELECT g.level, u.email FROM grants g JOIN users u ON u.id=g.user_id"
                     " WHERE g.document_id=? AND g.user_id=?", (doc["id"], user_id)).fetchone()
    if row is None:
        raise ApiError(404, "no such grant")
    db.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc["id"], user_id))
    audit.append(db, cfg(), actor=g.user, action="grant.revoke", outcome="allowed",
                 doc_id=doc["id"], target_user_id=user_id,
                 detail={"target": row["email"], "revoked_level": row["level"]}, ip=client_ip())
    return jsonify({"ok": True})


@bp.post("/documents/<doc_id>/suggestions")
@doc_route("share")
def make_suggestions(doc):
    db = get_db()
    items = suggest.generate(db, doc)
    audit.append(db, cfg(), actor=g.user, action="suggestion.generated", outcome="allowed",
                 doc_id=doc["id"],
                 detail={"provider": suggest.PROVIDER,
                         "suggested": [{"id": s["id"], "email": s["email"], "level": s["level"],
                                        "reason": s["reason"]} for s in items]},
                 ip=client_ip())
    return jsonify({"provider": suggest.PROVIDER, "items": items,
                    "note": "Suggestions grant nothing. Access changes only when you add a grant."})


@bp.post("/documents/<doc_id>/suggestions/<suggestion_id>/dismiss")
@doc_route("share")
def dismiss_suggestion(doc, suggestion_id):
    db = get_db()
    row = db.execute("SELECT * FROM suggestions WHERE id=? AND document_id=? AND status='pending'",
                     (suggestion_id[:64], doc["id"])).fetchone()
    if row is None:
        raise ApiError(404, "no pending suggestion matches")
    db.execute("UPDATE suggestions SET status='dismissed', decided_by=?, decided_at=? WHERE id=?",
               (g.user["id"], clock.now(), row["id"]))
    audit.append(db, cfg(), actor=g.user, action="suggestion.dismissed", outcome="allowed",
                 doc_id=doc["id"], target_user_id=row["user_id"],
                 detail={"suggestion": row["id"], "provider": row["provider"]}, ip=client_ip())
    return jsonify({"ok": True})
