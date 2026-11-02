"""Standard #1: a document is reachable only by someone who was granted it.

Every user x every document x every document action, against an expectation
written out by hand (not derived from the code under test)."""
import pytest

from conftest import (ACME, ALL_USERS, AUDITP, DRAWINGS, SALARY, Api, audit_rows, doc_ids,
                      email, raw_db, user_ids)

# Who holds what on each seeded document (written by hand from the seed data).
LEVEL = {
    "admin": {SALARY: None, ACME: None, DRAWINGS: None, AUDITP: None},
    "alice": {SALARY: "owner", ACME: "owner", DRAWINGS: "edit", AUDITP: None},
    "bob":   {SALARY: None, ACME: None, DRAWINGS: "owner", AUDITP: "owner"},
    "carol": {SALARY: None, ACME: "read", DRAWINGS: None, AUDITP: "read"},
    "dave":  {SALARY: None, ACME: None, DRAWINGS: None, AUDITP: None},
}
RANK = {None: 0, "read": 1, "edit": 2, "owner": 3}

# action -> (level needed, request builder)
ACTIONS = {
    "read":     ("read",  lambda a, d, u: a.get(f"/api/documents/{d}")),
    "download": ("read",  lambda a, d, u: a.get(f"/api/documents/{d}/download")),
    "grants":   ("owner", lambda a, d, u: a.get(f"/api/documents/{d}/grants")),
    "audit":    ("owner", lambda a, d, u: a.get(f"/api/documents/{d}/audit")),
    "edit":     ("edit",  lambda a, d, u: a.patch(f"/api/documents/{d}", json={"name": "pwned"})),
    "version":  ("edit",  lambda a, d, u: a.upload("x.txt", b"x", url=f"/api/documents/{d}/versions")),
    "share":    ("owner", lambda a, d, u: a.post(f"/api/documents/{d}/grants",
                                                 json={"email": email("dave"), "level": "read"})),
    "revoke":   ("owner", lambda a, d, u: a.delete(f"/api/documents/{d}/grants/{u['carol']}")),
    "suggest":  ("owner", lambda a, d, u: a.post(f"/api/documents/{d}/suggestions")),
    "delete":   ("owner", lambda a, d, u: a.delete(f"/api/documents/{d}")),
    "restore":  ("owner", lambda a, d, u: a.post(f"/api/documents/{d}/restore")),
}
READ_ONLY = {"read", "download", "grants", "audit"}


@pytest.fixture(scope="module")
def world(shared_app):
    return {
        "app": shared_app,
        "apis": {u: Api(shared_app, u) for u in ALL_USERS},
        "docs": doc_ids(shared_app),
        "users": user_ids(shared_app),
    }


@pytest.mark.parametrize("action", sorted(ACTIONS))
@pytest.mark.parametrize("who", ALL_USERS)
def test_every_user_every_document_every_action(world, who, action):
    needed, call = ACTIONS[action]
    for doc_name, doc_id in world["docs"].items():
        held = LEVEL[who][doc_name]
        permitted = RANK[held] >= RANK[needed]
        if permitted and action not in READ_ONLY:
            continue            # state-changing allowed paths are covered in test_features
        r = call(world["apis"][who], doc_id, world["users"])
        if permitted:
            assert r.status_code == 200, (who, action, doc_name, r.get_data(as_text=True))
        elif held is None:
            assert r.status_code == 404, (who, action, doc_name, r.status_code)
        else:
            assert r.status_code == 403, (who, action, doc_name, r.status_code)
        if not permitted:
            body = r.get_data(as_text=True)
            assert "CONFIDENTIAL" not in body and "A-100" not in body


def test_nothing_changed_by_the_attacks(world):
    db = raw_db(world["app"])
    names = sorted(r["name"] for r in db.execute("SELECT name FROM documents"))
    assert names == sorted([SALARY, ACME, DRAWINGS, AUDITP])
    assert db.execute("SELECT COUNT(*) c FROM documents WHERE deleted_at IS NOT NULL").fetchone()["c"] == 0
    assert db.execute("SELECT COUNT(*) c FROM grants").fetchone()["c"] == 3
    assert db.execute("SELECT COUNT(*) c FROM versions").fetchone()["c"] == 4


def test_every_refused_attempt_is_in_the_audit_trail(world):
    """Refused attempts are evidence too. Count what the matrix did vs. what was recorded."""
    expected = 0
    for who in ALL_USERS:
        for doc_name in world["docs"]:
            for action, (needed, _c) in ACTIONS.items():
                permitted = RANK[LEVEL[who][doc_name]] >= RANK[needed]
                if not permitted:
                    expected += 1
    logged = [r for r in audit_rows(world["app"]) if r["action"] == "document.access_denied"]
    assert len(logged) == expected
    assert all(r["outcome"] == "denied" and r["actor_email"] for r in logged)


def test_unauthenticated_gets_nothing(world):
    anon = Api(world["app"])
    for doc_id in world["docs"].values():
        for path in ("", "/download", "/grants", "/audit"):
            assert anon.get(f"/api/documents/{doc_id}{path}").status_code == 401
    assert anon.get("/api/documents").status_code == 401


def test_bad_ids_cannot_probe_or_inject(world):
    carol = world["apis"]["carol"]
    for bad in ("1", "0", "-1", "../etc/passwd", "%2e%2e%2fetc", "' OR '1'='1", "x" * 500,
                "00000000-0000-0000-0000-000000000000", "None", "null"):
        r = carol.get(f"/api/documents/{bad}")
        assert r.status_code == 404, bad
        assert carol.get(f"/api/documents/{bad}/download").status_code == 404


def test_response_for_missing_and_forbidden_documents_is_identical(world):
    dave = world["apis"]["dave"]
    forbidden = dave.get(f"/api/documents/{world['docs'][SALARY]}")
    missing = dave.get("/api/documents/00000000-0000-0000-0000-000000000000")
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.get_json() == missing.get_json()          # existence is not an oracle


def test_old_versions_are_protected_like_the_document(world):
    dave, doc = world["apis"]["dave"], world["docs"][SALARY]
    for v in (0, 1, 2, 99, "abc"):
        assert dave.get(f"/api/documents/{doc}/download?version={v}").status_code == 404


def test_edit_grantee_cannot_share_delete_or_see_who_has_access(world):
    alice, drawings = world["apis"]["alice"], world["docs"][DRAWINGS]       # alice has EDIT here
    assert alice.get(f"/api/documents/{drawings}/grants").status_code == 403
    assert alice.post(f"/api/documents/{drawings}/grants",
                      json={"email": email("dave"), "level": "read"}).status_code == 403
    assert alice.delete(f"/api/documents/{drawings}").status_code == 403


def test_mass_assignment_cannot_change_ownership(world, shared_app):
    # alice may edit DRAWINGS (owned by bob); she must not be able to take it
    alice, drawings = world["apis"]["alice"], world["docs"][DRAWINGS]
    for body in ({"owner_id": world["users"]["alice"]}, {"deleted_at": None}, {"id": "x"},
                 {"current_version": 99}, {"name": "ok", "owner_id": world["users"]["alice"]}):
        assert alice.patch(f"/api/documents/{drawings}", json=body).status_code == 400
    db = raw_db(shared_app)
    row = db.execute("SELECT owner_id FROM documents WHERE id=?", (drawings,)).fetchone()
    assert row["owner_id"] == world["users"]["bob"]


def test_admin_cannot_read_content_by_any_route(world):
    admin = world["apis"]["admin"]
    for doc_id in world["docs"].values():
        assert admin.get(f"/api/documents/{doc_id}").status_code == 404
        assert admin.get(f"/api/documents/{doc_id}/download").status_code == 404
        assert admin.post(f"/api/documents/{doc_id}/grants",
                          json={"email": email("admin"), "level": "read"}).status_code == 404
    assert admin.get("/api/documents").get_json()["items"] == []
    listing = admin.get("/api/admin/documents").get_json()["items"]
    assert len(listing) == 4
    for item in listing:                        # metadata only: no path to content
        assert not ({"blob_id", "wrapped_key", "sha256", "content", "download"} & set(item))


def test_admin_cannot_be_granted_access_even_by_a_stray_row(world, shared_app):
    """Defence in depth: if a grant row for an admin ever got into the database
    (bug, manual edit), the decision function and the list query still refuse."""
    db = raw_db(shared_app)
    doc, admin_id, alice_id = world["docs"][SALARY], world["users"]["admin"], world["users"]["alice"]
    db.execute("INSERT INTO grants (document_id,user_id,level,granted_by,created_at) VALUES (?,?,?,?,?)",
               (doc, admin_id, "edit", alice_id, "2026-01-01T00:00:00Z"))
    try:
        admin = world["apis"]["admin"]
        assert admin.get(f"/api/documents/{doc}").status_code == 404
        assert admin.get(f"/api/documents/{doc}/download").status_code == 404
        assert admin.get("/api/documents").get_json()["items"] == []
    finally:
        db.execute("DELETE FROM grants WHERE user_id=?", (admin_id,))
        db.close()
