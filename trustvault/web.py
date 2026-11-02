"""Request plumbing: authentication, CSRF, and the route guards.

Default deny: a before_request hook refuses any endpoint whose view function
does not carry an `_auth` marker. A route added without a guard therefore fails
closed, and a test fails the build if it appears.

Markers: public | user | admin | doc
"""
from __future__ import annotations

import functools
import sqlite3

from flask import current_app, g, jsonify, request

from . import audit, authz, clock
from .db import connect, tx
from .security import token_hash

COOKIE = "tv_session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


class _Denied(Exception):
    def __init__(self, decision):
        self.decision = decision


def cfg():
    return current_app.config["TV"]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(cfg().db_path)
    return g.db


def client_ip() -> str | None:
    return request.remote_addr


def json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "JSON object body required")
    return data


def authenticate() -> dict:
    """Resolve the session cookie to a live user, or raise 401/403.

    Nothing about rights is read from the cookie: it is an opaque random token
    whose SHA-256 is looked up here on every request. Disabling a user, killing
    a session, or changing a role is therefore effective on the next request.
    """
    db = get_db()
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 200:
        raise ApiError(401, "authentication required")
    sess = db.execute("SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL",
                      (token_hash(token),)).fetchone()
    now = clock.now_dt()
    if sess is None or clock.parse(sess["expires_at"]) <= now:
        raise ApiError(401, "authentication required")
    idle_limit = clock.parse(sess["last_seen"]).timestamp() + cfg().session_idle_minutes * 60
    if now.timestamp() > idle_limit:
        raise ApiError(401, "session expired")
    user = db.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
    if user is None or not user["active"]:
        raise ApiError(401, "authentication required")

    if request.method in UNSAFE:
        sent = request.headers.get("X-CSRF-Token", "")
        import hmac
        if not hmac.compare_digest(sent, sess["csrf"]):
            raise ApiError(403, "missing or invalid CSRF token")
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            raise ApiError(403, "cross-origin request refused")

    if clock.fmt(now) > sess["last_seen"]:
        db.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (clock.fmt(now), sess["id"]))

    if user["must_change_pw"] and request.endpoint not in (
            "auth.change_password", "auth.logout", "auth.me"):
        raise ApiError(403, "password change required before using the system")

    g.user = dict(user)
    g.session = dict(sess)
    return g.user


def public(fn):
    fn._auth = "public"
    return fn


def authed(role: str | None = None, write: bool = False):
    """Require a logged-in user, optionally of one role. `write=True` runs the
    handler inside a BEGIN IMMEDIATE transaction."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            user = authenticate()
            if role and user["role"] != role:
                audit.record(get_db(), cfg(), actor=user, action="route.denied",
                             outcome="denied",
                             detail={"path": request.path, "method": request.method,
                                     "needed_role": role}, ip=client_ip())
                raise ApiError(403, "forbidden")
            if write:
                with tx(get_db()):
                    return fn(*args, **kwargs)
            return fn(*args, **kwargs)
        wrapper._auth = "admin" if role == "admin" else "user"
        return wrapper
    return deco


def doc_route(action: str):
    """Guard for every route that takes a <doc_id>. The authorisation decision,
    the handler's change and its audit record share one transaction. The handler
    receives the already-authorised document row, never an id to re-fetch."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            doc_id = kwargs.pop("doc_id")
            user = authenticate()
            db = get_db()
            denied = None
            try:
                with tx(db):
                    decision, doc = authz.authorize(db, user, doc_id, action)
                    if not decision.allowed:
                        raise _Denied(decision)
                    g.decision = decision
                    return fn(doc, *args, **kwargs)
            except _Denied as d:
                denied = d.decision
            audit.record(db, cfg(), actor=user, action="document.access_denied",
                         outcome="denied", doc_id=str(doc_id)[:64],
                         detail={"attempted": action, "reason": denied.reason,
                                 "path": request.path}, ip=client_ip())
            if denied.can_read:
                raise ApiError(403, "you do not have permission to do that")
            raise ApiError(404, "document not found")
        wrapper._auth = "doc"
        wrapper._doc_action = action
        return wrapper
    return deco


def install(app):
    @app.before_request
    def default_deny():
        endpoint = request.endpoint
        if endpoint is None:
            return None
        fn = app.view_functions.get(endpoint)
        if getattr(fn, "_auth", None) not in ("public", "user", "admin", "doc"):
            raise ApiError(403, "forbidden")
        return None

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            "img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
        if cfg().secure_cookies:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.errorhandler(ApiError)
    def api_error(err):
        body = {"error": err.message}
        body.update(err.extra)
        return jsonify(body), err.status

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def bad_method(_e):
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(413)
    def too_big(_e):
        return jsonify({"error": "request too large"}), 413

    @app.errorhandler(Exception)
    def unexpected(exc):
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return jsonify({"error": exc.name.lower()}), exc.code
        current_app.logger.exception("unhandled error")
        return jsonify({"error": "internal error"}), 500
