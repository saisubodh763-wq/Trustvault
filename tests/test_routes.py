"""The 'routes you did not think of' tests: structure, not behaviour."""
import re

from flask import Flask

from conftest import ACME, Api, build_app, doc_ids

PUBLIC_ENDPOINTS = {"auth.login", "healthz", "index", "ui_asset"}


def test_every_route_declares_who_may_call_it(app):
    markers = {}
    for rule in app.url_map.iter_rules():
        fn = app.view_functions[rule.endpoint]
        markers[rule.endpoint] = getattr(fn, "_auth", None)
    assert None not in markers.values(), {k: v for k, v in markers.items() if v is None}
    public = {ep for ep, m in markers.items() if m == "public"}
    assert public == PUBLIC_ENDPOINTS              # adding a public route must be a conscious edit here


def test_every_route_with_a_document_id_goes_through_the_document_guard(app):
    for rule in app.url_map.iter_rules():
        if "doc_id" in rule.arguments:
            fn = app.view_functions[rule.endpoint]
            assert fn._auth == "doc" and fn._doc_action, rule.rule


def test_every_admin_path_requires_the_admin_role(app):
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith("/api/admin/"):
            assert app.view_functions[rule.endpoint]._auth == "admin", rule.rule


def test_no_route_can_serve_files_from_disk_outside_the_ui_folder(app):
    rules = [r.rule for r in app.url_map.iter_rules()]
    assert not any(re.search(r"(blob|upload|file|static|data)", r) and not r.startswith("/ui/")
                   for r in rules if "/api/documents/<doc_id>" not in r), rules
    client = app.test_client()
    for path in ("/ui/../data/trustvault.db", "/ui/..%2fdata%2ftrustvault.db", "/static/x",
                 "/data/trustvault.db", "/blobs/aa/bb", "/trustvault.db", "/.git/config"):
        assert client.get(path).status_code in (404, 400), path


def test_a_route_added_without_a_guard_fails_closed(tmp_path):
    app = build_app(tmp_path)

    @app.get("/api/forgot-the-decorator")
    def forgot():
        return "secret"

    r = app.test_client().get("/api/forgot-the-decorator")
    assert r.status_code == 403 and b"secret" not in r.data


def test_every_api_route_rejects_anonymous_callers(app):
    client = app.test_client()
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/") or rule.endpoint == "auth.login":
            continue
        url = re.sub(r"<[^>]+>", "x", rule.rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            r = client.open(url, method=method)
            assert r.status_code == 401, (method, rule.rule, r.status_code)


def test_csrf_and_cross_origin_are_enforced(app):
    alice = Api(app, "alice")
    acme = doc_ids(app)[ACME]
    no_header = alice.c.patch(f"/api/documents/{acme}", json={"description": "x"})
    assert no_header.status_code == 403
    wrong = alice.c.patch(f"/api/documents/{acme}", json={"description": "x"},
                          headers={"X-CSRF-Token": "not-the-token"})
    assert wrong.status_code == 403
    cross = alice.c.patch(f"/api/documents/{acme}", json={"description": "x"},
                          headers={"X-CSRF-Token": alice.csrf, "Origin": "https://evil.example"})
    assert cross.status_code == 403
    ok = alice.c.patch(f"/api/documents/{acme}", json={"description": "x"},
                       headers={"X-CSRF-Token": alice.csrf})
    assert ok.status_code == 200


def test_security_headers_and_cookie_flags(app):
    c = app.test_client()
    r = c.post("/api/auth/login", json={"email": "carol@trustvault.test",
                                         "password": "Demo-Passw0rd-2026"})
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    h = c.get("/api/auth/me").headers
    assert h["Cache-Control"] == "no-store" and h["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    index = c.get("/")
    assert index.status_code == 200 and b"<script>" not in index.data     # no inline script


def test_errors_do_not_leak_internals(app):
    c = Api(app, "carol")
    r = c.post("/api/documents", data="not multipart", content_type="text/plain")
    assert r.status_code in (400, 403, 415)
    r = c.post("/api/auth/change-password", data="{not json", content_type="application/json")
    assert r.status_code == 400 and "Traceback" not in r.get_data(as_text=True)
    assert Api(app).c.get("/api/nope").get_json() == {"error": "not found"}
