"""Authentication endpoints."""
from __future__ import annotations

import secrets
from datetime import timedelta

from flask import Blueprint, g, jsonify, make_response, request

from . import audit, clock
from .db import tx
from .security import (DUMMY_HASH, hash_password, new_session_token, password_problem,
                       token_hash, verify_password)
from .web import COOKIE, ApiError, authed, cfg, client_ip, get_db, json_body, public

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

GENERIC_FAILURE = "invalid credentials, or the account is locked or disabled"


def _public_user(u) -> dict:
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "must_change_pw": bool(u["must_change_pw"])}


@bp.post("/login")
@public
def login():
    db, conf = get_db(), cfg()
    data = json_body()
    email = str(data.get("email", "")).strip().lower()[:254]
    password = str(data.get("password", ""))[:256]
    ip = client_ip()

    window = clock.fmt(clock.now_dt() - timedelta(minutes=10))
    recent = db.execute(
        "SELECT COUNT(*) c FROM audit_log WHERE action='auth.login' AND outcome='denied'"
        " AND ip = ? AND ts > ?", (ip, window)).fetchone()["c"]
    if recent >= conf.ip_failure_limit:
        raise ApiError(429, "too many failed attempts from this address; try later")

    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    now = clock.now()
    ok, reason = False, "bad_password"
    if user is None:
        verify_password(DUMMY_HASH, password)          # equalise timing
        reason = "unknown_user"
    elif user["locked_until"] and user["locked_until"] > now:
        verify_password(user["pw_hash"], password)     # same cost, result ignored
        reason = "locked"
    elif not user["active"]:
        verify_password(user["pw_hash"], password)
        reason = "disabled"
    else:
        ok = verify_password(user["pw_hash"], password)

    if not ok:
        with tx(db):
            if user is not None and reason == "bad_password":
                fails = user["failed_logins"] + 1
                locked = None
                if fails >= conf.lockout_threshold:
                    locked = clock.fmt(clock.now_dt() + timedelta(minutes=conf.lockout_minutes))
                    fails = 0
                db.execute("UPDATE users SET failed_logins=?, locked_until=COALESCE(?, locked_until)"
                           " WHERE id=?", (fails, locked, user["id"]))
                if locked:
                    audit.append(db, conf, actor=None, actor_email=email, action="auth.lockout",
                                 outcome="denied", target_user_id=user["id"],
                                 detail={"until": locked}, ip=ip)
            audit.append(db, conf, actor=None, actor_email=email, action="auth.login",
                         outcome="denied", target_user_id=user["id"] if user else None,
                         detail={"reason": reason}, ip=ip)
        raise ApiError(401, GENERIC_FAILURE)

    token, hashed = new_session_token()
    csrf = secrets.token_urlsafe(24)
    expires = clock.fmt(clock.now_dt() + timedelta(hours=conf.session_absolute_hours))
    with tx(db):
        db.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (user["id"],))
        db.execute("INSERT INTO sessions (id,user_id,csrf,created_at,last_seen,expires_at,ip)"
                   " VALUES (?,?,?,?,?,?,?)", (hashed, user["id"], csrf, now, now, expires, ip))
        audit.append(db, conf, actor=user, action="auth.login", outcome="allowed",
                     detail={"must_change_pw": bool(user["must_change_pw"])}, ip=ip)
    resp = make_response(jsonify({"user": _public_user(user), "csrf": csrf}))
    resp.set_cookie(COOKIE, token, httponly=True, secure=conf.secure_cookies,
                    samesite="Strict", max_age=conf.session_absolute_hours * 3600, path="/")
    return resp


@bp.post("/logout")
@authed(write=True)
def logout():
    db = get_db()
    db.execute("UPDATE sessions SET revoked_at=? WHERE id=?", (clock.now(), g.session["id"]))
    audit.append(db, cfg(), actor=g.user, action="auth.logout", outcome="allowed", ip=client_ip())
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(COOKIE, path="/")
    return resp


@bp.get("/me")
@authed()
def me():
    return jsonify({"user": _public_user(g.user), "csrf": g.session["csrf"]})


@bp.post("/change-password")
@authed()
def change_password():
    db = get_db()
    data = json_body()
    current, new = str(data.get("current", "")), str(data.get("new", ""))
    if not verify_password(g.user["pw_hash"], current):
        audit.record(db, cfg(), actor=g.user, action="auth.password_change", outcome="denied",
                     detail={"reason": "wrong_current_password"}, ip=client_ip())
        raise ApiError(403, "current password is incorrect")
    problem = password_problem(new, g.user["email"])
    if problem:
        raise ApiError(400, problem)
    if verify_password(g.user["pw_hash"], new):
        raise ApiError(400, "new password must differ from the current one")
    with tx(db):
        db.execute("UPDATE users SET pw_hash=?, must_change_pw=0, failed_logins=0,"
                   " locked_until=NULL WHERE id=?", (hash_password(new), g.user["id"]))
        # Every other session ends now; only the one making the change survives.
        db.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND id<>?"
                   " AND revoked_at IS NULL", (clock.now(), g.user["id"], g.session["id"]))
        audit.append(db, cfg(), actor=g.user, action="auth.password_change",
                     outcome="allowed", detail={"other_sessions_revoked": True},
                     ip=client_ip())
    return jsonify({"ok": True})
