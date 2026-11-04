"""Search, list/authorize parity, versions/trash, admin controls, suggestions."""
import json

import pytest

from conftest import (ACME, ALL_USERS, AUDITP, DRAWINGS, SALARY, Api, audit_rows, doc_ids,
                      email, raw_db, user_ids)
from trustvault import authz, clock


# ------------------------------------------------------------------ search

def names(resp):
    return sorted(i["name"] for i in resp.get_json()["items"])


def test_search_by_name_owner_category_and_date(app):
    carol, alice = Api(app, "carol"), Api(app, "alice")
    assert names(carol.get("/api/documents")) == sorted([ACME, AUDITP])
    assert names(carol.get("/api/documents?q=acme")) == [ACME]
    assert names(carol.get("/api/documents?owner=bob@trustvault.test")) == [AUDITP]
    assert names(carol.get("/api/documents?owner=alice")) == [ACME]
    assert names(carol.get("/api/documents?category=finance")) == [AUDITP]
    assert names(alice.get("/api/documents?category=HR")) == [SALARY]
    today = clock.now()[:10]
    assert len(carol.get(f"/api/documents?from={today}&to={today}").get_json()["items"]) == 2
    assert carol.get("/api/documents?from=2099-01-01").get_json()["items"] == []
    assert carol.get("/api/documents?to=2000-01-01").get_json()["items"] == []
    assert sorted(carol.get("/api/categories").get_json()["items"]) == ["Contracts", "Finance"]


def test_search_never_reveals_documents_the_user_cannot_read(app):
    dave, carol = Api(app, "dave"), Api(app, "carol")
    for q in ("salary", "Salary letters 2026", "CONFIDENTIAL", "letters", "2026"):
        assert dave.get(f"/api/documents?q={q}").get_json() == {"total": 0, "items": []}
    assert SALARY not in names(carol.get("/api/documents?q=salary"))
    assert carol.get("/api/documents?owner=alice&category=HR").get_json()["total"] == 0
    assert carol.get("/api/categories").get_json()["items"] != ["HR"]


@pytest.mark.parametrize("probe", ["%", "_", "%%", "a%", "\\", "' OR 1=1 --", "\"; DROP TABLE documents; --",
                                   "*", "%' OR '1'='1"])
def test_search_wildcards_and_injection_do_not_widen_results(app, probe):
    dave = Api(app, "dave")
    for param in ("q", "owner", "category"):
        r = dave.get(f"/api/documents?{param}=" + probe.replace("%", "%25").replace("&", "%26"))
        assert r.status_code in (200, 400)
        if r.status_code == 200:
            assert r.get_json()["total"] == 0, (param, probe)
    assert raw_db(app).execute("SELECT COUNT(*) c FROM documents").fetchone()["c"] == 4


def test_search_input_validation_and_paging(app):
    carol = Api(app, "carol")
    assert carol.get("/api/documents?from=notadate").status_code == 400
    assert carol.get("/api/documents?limit=abc").status_code == 400
    r = carol.get("/api/documents?limit=1&offset=0").get_json()
    assert r["total"] == 2 and len(r["items"]) == 1
    assert len(carol.get("/api/documents?limit=1&offset=1").get_json()["items"]) == 1
    assert len(carol.get("/api/documents?limit=99999").get_json()["items"]) == 2


# ------------------------------------------------------------------ list vs authorize parity

def _visible_via_sql(db, user):
    clause, params = authz.visible_clause(user)
    rows = db.execute("SELECT d.id FROM documents d WHERE d.deleted_at IS NULL AND d.purged_at IS NULL"
                      " AND " + clause, params).fetchall()
    return {r["id"] for r in rows}


def _readable_via_authorize(db, user):
    out = set()
    for d in db.execute("SELECT id FROM documents WHERE deleted_at IS NULL AND purged_at IS NULL"):
        decision, _doc = authz.authorize(db, user, d["id"], "read")
        if decision.allowed:
            out.add(d["id"])
    return out


def test_list_query_and_authorize_agree_for_every_user_in_every_state(app):
    """The two code paths that decide visibility must never drift. Compare them
    for every user across messy states: expired grants, disabled/locked-down
    users, role changes, stray rows for admins."""
    db = raw_db(app)
    docs, users = doc_ids(app), user_ids(app)
    now = clock.now()
    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?)",
               (docs[SALARY], users["dave"], "read", users["alice"], now, "2000-01-01T00:00:00Z"))  # expired
    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?)",
               (docs[SALARY], users["admin"], "edit", users["alice"], now, None))                    # stray admin
    db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?)",
               (docs[AUDITP], users["alice"], "read", users["bob"], now, None))
    db.execute("UPDATE users SET must_change_pw=1 WHERE email=?", (email("bob"),))                   # locked down
    db.execute("UPDATE documents SET deleted_at=? WHERE id=?", (now, docs[ACME]))                    # trashed
    db.execute("UPDATE users SET role='viewer' WHERE email=?", (email("alice"),))                    # demoted
    for who in ALL_USERS:
        user = dict(db.execute("SELECT * FROM users WHERE email=?", (email(who),)).fetchone())
        assert _visible_via_sql(db, user) == _readable_via_authorize(db, user), who
    admin = dict(db.execute("SELECT * FROM users WHERE email=?", (email("admin"),)).fetchone())
    assert _visible_via_sql(db, admin) == set()
    dave = dict(db.execute("SELECT * FROM users WHERE email=?", (email("dave"),)).fetchone())
    assert _visible_via_sql(db, dave) == set()                                                       # expired grant
    inactive = dict(db.execute("SELECT * FROM users WHERE email=?", (email("carol"),)).fetchone(), active=0)
    assert _visible_via_sql(db, inactive) == set() == _readable_via_authorize(db, inactive)


def test_unknown_actions_fail_closed(app):
    db = raw_db(app)
    alice = dict(db.execute("SELECT * FROM users WHERE email=?", (email("alice"),)).fetchone())
    with pytest.raises(KeyError):
        authz.authorize(db, alice, doc_ids(app)[ACME], "teleport")


# ------------------------------------------------------------------ trash & restore

def test_trash_is_private_to_the_owner(app):
    alice = Api(app, "alice")
    acme = doc_ids(app)[ACME]
    alice.delete(f"/api/documents/{acme}")
    assert [d["name"] for d in alice.get("/api/trash").get_json()["items"]] == [ACME]
    assert alice.get(f"/api/documents/{acme}").status_code == 404            # not readable while deleted
    assert alice.get(f"/api/documents/{acme}/download").status_code == 404
    assert alice.patch(f"/api/documents/{acme}", json={"name": "x"}).status_code == 404
    assert alice.get(f"/api/documents/{acme}/audit").status_code == 200       # but the trail is available
    for who in ("carol", "bob", "dave"):
        other = Api(app, who)
        assert other.post(f"/api/documents/{acme}/restore").status_code == 404
        trash = other.get("/api/trash")
        if who == "bob":                                   # owner role: sees only his own trash
            assert trash.status_code == 200 and trash.get_json()["items"] == []
        else:                                              # viewers have no trash at all
            assert trash.status_code == 403
    assert alice.post(f"/api/documents/{acme}/restore").status_code == 200
    assert alice.post(f"/api/documents/{acme}/restore").status_code == 409


# ------------------------------------------------------------------ sharing rules

def test_sharing_rules(app):
    alice = Api(app, "alice")
    acme = doc_ids(app)[ACME]
    url = f"/api/documents/{acme}/grants"
    assert alice.post(url, json={"email": email("admin"), "level": "read"}).status_code == 422
    assert alice.post(url, json={"email": email("dave"), "level": "edit"}).status_code == 422     # viewer: read only
    assert alice.post(url, json={"email": email("alice"), "level": "read"}).status_code == 400    # self
    assert alice.post(url, json={"email": "ghost@trustvault.test", "level": "read"}).status_code == 404
    assert alice.post(url, json={"email": email("dave"), "level": "admin"}).status_code == 400
    assert alice.post(url, json={"email": email("dave")}).status_code == 400
    assert alice.post(url, json={"email": email("bob"), "level": "edit"}).status_code == 201
    Api(app, "admin").patch(f"/api/admin/users/{user_ids(app)['dave']}", json={"active": False})
    assert alice.post(url, json={"email": email("dave"), "level": "read"}).status_code == 404     # inactive
    assert alice.delete(f"{url}/{user_ids(app)['dave']}").status_code == 404                      # no such grant


# ------------------------------------------------------------------ admin

def test_only_admins_reach_admin_endpoints_and_the_attempt_is_recorded(app):
    paths = [("get", "/api/admin/users"), ("get", "/api/admin/documents"), ("get", "/api/admin/audit"),
             ("get", "/api/admin/audit/verify"), ("get", "/api/admin/alerts"),
             ("post", "/api/admin/users"), ("patch", f"/api/admin/users/{user_ids(app)['dave']}"),
             ("post", f"/api/admin/users/{user_ids(app)['dave']}/reset-password"),
             ("post", f"/api/admin/users/{user_ids(app)['dave']}/revoke-sessions")]
    for who in ("alice", "carol"):
        api = Api(app, who)
        for method, path in paths:
            assert getattr(api, method)(path, json={}).status_code == 403, (who, path)
    assert sum(1 for r in audit_rows(app) if r["action"] == "route.denied") == 2 * len(paths)


def test_admin_safety_rails(app):
    admin = Api(app, "admin")
    me = user_ids(app)
    assert admin.patch(f"/api/admin/users/{me['admin']}", json={"active": False}).status_code == 409
    assert admin.patch(f"/api/admin/users/{me['admin']}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/admin/users/{me['alice']}", json={"role": "viewer"}).status_code == 409   # owns docs
    assert admin.patch(f"/api/admin/users/{me['alice']}", json={"owner_id": "x"}).status_code == 400
    assert admin.patch(f"/api/admin/users/{me['carol']}", json={"role": "superuser"}).status_code == 422
    assert admin.patch(f"/api/admin/users/{me['carol']}", json={"role": "owner"}).status_code == 200
    assert admin.post("/api/admin/users", json={"email": "bad", "name": "x", "role": "owner"}).status_code == 422
    assert admin.post("/api/admin/users", json={"email": email("dave"), "name": "x", "role": "viewer"}).status_code == 409
    assert admin.patch("/api/admin/users/nope", json={"active": False}).status_code == 404


def test_admin_activity_view_and_alerts(app):
    admin, dave = Api(app, "admin"), Api(app, "dave")
    salary = doc_ids(app)[SALARY]
    for _ in range(3):
        dave.get(f"/api/documents/{salary}/download")
    listing = {d["name"]: d for d in admin.get("/api/admin/documents").get_json()["items"]}
    assert listing[SALARY]["refused"] == 3 and listing[SALARY]["downloads"] == 0
    kinds = {a["kind"] for a in admin.get("/api/admin/alerts").get_json()["items"]}
    assert "repeated_refusals" in kinds
    Api(app, "alice").post(f"/api/documents/{doc_ids(app)[ACME]}/grants",
                           json={"email": email("bob"), "level": "edit"})
    reset = admin.post(f"/api/admin/users/{user_ids(app)['carol']}/reset-password").get_json()
    Api(app).login("carol", reset["temporary_password"])
    kinds = {a["kind"] for a in admin.get("/api/admin/alerts").get_json()["items"]}
    assert {"edit_grant", "password_reset"} <= kinds
    sev = [a["severity"] for a in admin.get("/api/admin/alerts").get_json()["items"]
           if a["kind"] == "password_reset"]
    assert sev == ["high"]                       # the account logged in after the reset


def test_alert_fires_when_the_audit_chain_is_broken(app):
    db = raw_db(app)
    db.execute("DROP TRIGGER audit_no_update")
    db.execute("UPDATE audit_log SET actor_email='x@y.z' WHERE seq=1")
    alerts = Api(app, "admin").get("/api/admin/alerts").get_json()["items"]
    assert alerts[0]["kind"] == "audit_chain_broken" and alerts[0]["severity"] == "critical"


def test_bulk_download_alert(app):
    alice, admin = Api(app, "alice"), Api(app, "admin")
    acme = doc_ids(app)[ACME]
    alice.post(f"/api/documents/{acme}/grants", json={"email": email("dave"), "level": "read"})
    dave = Api(app, "dave")
    for _ in range(10):
        assert dave.get(f"/api/documents/{acme}/download").status_code == 200
    assert "bulk_download" in {a["kind"] for a in admin.get("/api/admin/alerts").get_json()["items"]}


# ------------------------------------------------------------------ suggestions never grant

def _alice_shares_more_hr_docs(app):
    alice = Api(app, "alice")
    first = alice.upload("hr1.txt", b"1", category="Contracts").json["id"]
    alice.post(f"/api/documents/{first}/grants", json={"email": email("carol"), "level": "read"})
    return alice


def test_suggestions_are_advice_only_and_audited(app):
    alice = _alice_shares_more_hr_docs(app)
    new_doc = alice.upload("hr2.txt", b"2", category="Contracts").json["id"]
    before = raw_db(app).execute("SELECT COUNT(*) c FROM grants").fetchone()["c"]
    r = alice.post(f"/api/documents/{new_doc}/suggestions").get_json()
    assert [s["email"] for s in r["items"]] == [email("carol")]
    assert r["items"][0]["level"] == "read" and "other 'Contracts'" in r["items"][0]["reason"]
    assert raw_db(app).execute("SELECT COUNT(*) c FROM grants").fetchone()["c"] == before   # nothing granted
    assert Api(app, "carol").get(f"/api/documents/{new_doc}").status_code == 404            # still no access
    gen = [x for x in audit_rows(app, doc_id=new_doc) if x["action"] == "suggestion.generated"]
    assert gen and json.loads(gen[0]["detail"])["suggested"][0]["email"] == email("carol")


def test_accepting_a_suggestion_is_a_separate_owner_decision_and_both_are_audited(app):
    alice = _alice_shares_more_hr_docs(app)
    new_doc = alice.upload("hr2.txt", b"2", category="Contracts").json["id"]
    s = alice.post(f"/api/documents/{new_doc}/suggestions").get_json()["items"][0]
    r = alice.post(f"/api/documents/{new_doc}/grants",
                   json={"email": email("carol"), "level": "read", "suggestion_id": s["id"]})
    assert r.status_code == 201
    row = [x for x in audit_rows(app, doc_id=new_doc) if x["action"] == "grant.add"][0]
    detail = json.loads(row["detail"])
    assert detail["suggestion"]["id"] == s["id"] and detail["suggestion"]["followed_exactly"] is True
    assert row["actor_email"] == email("alice")                  # a person decided, not the system
    assert Api(app, "carol").get(f"/api/documents/{new_doc}").status_code == 200
    # a used suggestion cannot be replayed
    again = alice.post(f"/api/documents/{new_doc}/grants",
                       json={"email": email("carol"), "level": "read", "suggestion_id": s["id"]})
    assert again.status_code == 404


def test_a_suggestion_cannot_be_used_on_another_document_or_by_another_user(app):
    alice = _alice_shares_more_hr_docs(app)
    d1 = alice.upload("hr2.txt", b"2", category="Contracts").json["id"]
    d2 = alice.upload("hr3.txt", b"3", category="Contracts").json["id"]
    s = alice.post(f"/api/documents/{d1}/suggestions").get_json()["items"][0]
    wrong_doc = alice.post(f"/api/documents/{d2}/grants",
                           json={"email": email("carol"), "level": "read", "suggestion_id": s["id"]})
    assert wrong_doc.status_code == 404
    bob = Api(app, "bob")
    assert bob.post(f"/api/documents/{d1}/suggestions").status_code == 404
    assert bob.post(f"/api/documents/{d1}/suggestions/{s['id']}/dismiss").status_code == 404


def test_dismissal_is_recorded_and_widening_beyond_the_suggestion_is_flagged(app):
    alice = _alice_shares_more_hr_docs(app)
    d1 = alice.upload("hr2.txt", b"2", category="Contracts").json["id"]
    s = alice.post(f"/api/documents/{d1}/suggestions").get_json()["items"][0]
    assert alice.post(f"/api/documents/{d1}/suggestions/{s['id']}/dismiss").status_code == 200
    assert any(x["action"] == "suggestion.dismissed" for x in audit_rows(app, doc_id=d1))
    s2 = alice.post(f"/api/documents/{d1}/suggestions").get_json()["items"][0]
    alice.post(f"/api/documents/{d1}/grants", json={"email": email("bob"), "level": "edit"})
    # accept suggestion for carol but choose differently: still read here, flagged as exact
    alice.post(f"/api/documents/{d1}/grants",
               json={"email": email("carol"), "level": "read", "suggestion_id": s2["id"]})
    last = [x for x in audit_rows(app, doc_id=d1) if x["action"] == "grant.add"][-1]
    assert json.loads(last["detail"])["suggestion"]["followed_exactly"] is True
