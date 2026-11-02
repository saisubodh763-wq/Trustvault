"""Standard #3: taking access away works immediately, and everything issued
before that moment stops working. The design that makes this true: sessions
carry no rights, there are no signed links, and nothing is cached - every
request re-reads users, sessions and grants inside the same transaction."""
from datetime import timedelta

from conftest import ACME, DRAWINGS, Api, doc_ids, email, raw_db, user_ids
from trustvault import clock


def test_revoked_grant_stops_the_very_next_request_on_the_same_session(app):
    alice, carol = Api(app, "alice"), Api(app, "carol")
    acme, carol_id = doc_ids(app)[ACME], user_ids(app)["carol"]
    assert carol.get(f"/api/documents/{acme}/download").status_code == 200   # before
    assert alice.delete(f"/api/documents/{acme}/grants/{carol_id}").status_code == 200
    assert carol.get(f"/api/documents/{acme}/download").status_code == 404   # same cookie, after
    assert carol.get(f"/api/documents/{acme}").status_code == 404
    assert acme not in [d["id"] for d in carol.get("/api/documents").get_json()["items"]]
    assert carol.get(f"/api/documents/{acme}/download?version=1").status_code == 404


def test_regranting_restores_access_and_it_is_a_new_decision(app):
    alice, carol = Api(app, "alice"), Api(app, "carol")
    acme, carol_id = doc_ids(app)[ACME], user_ids(app)["carol"]
    alice.delete(f"/api/documents/{acme}/grants/{carol_id}")
    assert carol.get(f"/api/documents/{acme}").status_code == 404
    alice.post(f"/api/documents/{acme}/grants", json={"email": email("carol"), "level": "read"})
    assert carol.get(f"/api/documents/{acme}").status_code == 200


def test_downgrade_from_edit_to_read_is_immediate(app):
    bob, alice = Api(app, "bob"), Api(app, "alice")
    drawings = doc_ids(app)[DRAWINGS]
    assert alice.patch(f"/api/documents/{drawings}", json={"description": "a"}).status_code == 200
    bob.post(f"/api/documents/{drawings}/grants", json={"email": email("alice"), "level": "read"})
    assert alice.patch(f"/api/documents/{drawings}", json={"description": "b"}).status_code == 403
    assert alice.get(f"/api/documents/{drawings}").status_code == 200


def test_time_limited_grant_expires_without_anyone_doing_anything(app):
    alice, dave = Api(app, "alice"), Api(app, "dave")
    acme = doc_ids(app)[ACME]
    soon = clock.fmt(clock.now_dt() + timedelta(hours=1))
    r = alice.post(f"/api/documents/{acme}/grants",
                   json={"email": email("dave"), "level": "read", "expires_at": soon})
    assert r.status_code == 201
    assert dave.get(f"/api/documents/{acme}/download").status_code == 200
    clock.advance(1800)                      # half the grant's life; Dave is still active
    assert dave.get(f"/api/documents/{acme}/download").status_code == 200
    clock.advance(1801)                      # now past expiry, session still fresh (30 min idle)
    assert dave.get(f"/api/documents/{acme}/download").status_code == 404
    assert acme not in [d["id"] for d in dave.get("/api/documents").get_json()["items"]]


def test_expiry_must_be_in_the_future_and_bounded(app):
    alice, acme = Api(app, "alice"), doc_ids(app)[ACME]
    past = clock.fmt(clock.now_dt() - timedelta(hours=1))
    far = clock.fmt(clock.now_dt() + timedelta(days=400))
    for bad in (past, far, "tomorrow-ish"):
        r = alice.post(f"/api/documents/{acme}/grants",
                       json={"email": email("dave"), "level": "read", "expires_at": bad})
        assert r.status_code == 400, bad


def test_disabling_a_user_kills_their_existing_session_instantly(app):
    admin, carol = Api(app, "admin"), Api(app, "carol")
    acme, carol_id = doc_ids(app)[ACME], user_ids(app)["carol"]
    assert carol.get(f"/api/documents/{acme}/download").status_code == 200
    r = admin.patch(f"/api/admin/users/{carol_id}", json={"active": False})
    assert r.status_code == 200 and r.json["sessions_revoked"] >= 1
    assert carol.get(f"/api/documents/{acme}/download").status_code == 401
    assert carol.get("/api/documents").status_code == 401
    assert Api(app).login("carol").status_code == 401                 # cannot log back in


def test_demoting_a_user_caps_their_rights_at_once(app):
    """A grant row says 'edit', but the role cap is applied at decision time."""
    admin = Api(app, "admin")
    r = admin.post("/api/admin/users", json={"email": "erin@trustvault.test", "name": "Erin",
                                              "role": "owner"})
    temp = r.json["temporary_password"]
    erin = Api(app)
    erin.login("erin", temp)
    assert erin.post("/api/auth/change-password",
                     json={"current": temp, "new": "Erin-new-passw0rd!"}).status_code == 200
    drawings = doc_ids(app)[DRAWINGS]
    Api(app, "bob").post(f"/api/documents/{drawings}/grants",
                         json={"email": "erin@trustvault.test", "level": "edit"})
    assert erin.patch(f"/api/documents/{drawings}", json={"description": "ok"}).status_code == 200
    admin.patch(f"/api/admin/users/{user_ids(app)['erin']}", json={"role": "viewer"})
    erin2 = Api(app)
    assert erin2.login("erin", "Erin-new-passw0rd!").status_code == 200
    assert erin2.get(f"/api/documents/{drawings}").status_code == 200
    assert erin2.patch(f"/api/documents/{drawings}", json={"description": "no"}).status_code == 403
    # and the stale session from before the demotion is gone
    assert erin.get(f"/api/documents/{drawings}").status_code == 401


def test_logout_makes_a_stolen_cookie_useless(app):
    carol = Api(app, "carol")
    cookie = carol.c.get_cookie("tv_session").value
    csrf = carol.csrf
    assert carol.post("/api/auth/logout").status_code == 200
    thief = Api(app)
    thief.c.set_cookie("tv_session", cookie)
    thief.csrf = csrf
    assert thief.get("/api/documents").status_code == 401


def test_password_change_ends_every_other_session(app):
    laptop, phone = Api(app, "carol"), Api(app, "carol")
    assert phone.get("/api/documents").status_code == 200
    r = laptop.post("/api/auth/change-password",
                    json={"current": "Demo-Passw0rd-2026", "new": "Carol-Other-passw0rd!"})
    assert r.status_code == 200
    assert phone.get("/api/documents").status_code == 401
    assert laptop.get("/api/documents").status_code == 200


def test_admin_password_reset_locks_the_account_until_changed(app):
    admin, carol = Api(app, "admin"), Api(app, "carol")
    r = admin.post(f"/api/admin/users/{user_ids(app)['carol']}/reset-password")
    temp = r.json["temporary_password"]
    assert carol.get("/api/documents").status_code == 401                 # old session dead
    assert Api(app).login("carol").status_code == 401                     # old password dead
    fresh = Api(app)
    assert fresh.login("carol", temp).status_code == 200
    assert fresh.get("/api/documents").status_code == 403                 # nothing until changed
    assert fresh.get(f"/api/documents/{doc_ids(app)[ACME]}/download").status_code == 403


def test_deleting_a_document_removes_access_for_everyone_else_at_once(app):
    alice, carol = Api(app, "alice"), Api(app, "carol")
    acme = doc_ids(app)[ACME]
    assert carol.get(f"/api/documents/{acme}/download").status_code == 200
    assert alice.delete(f"/api/documents/{acme}").status_code == 200
    assert carol.get(f"/api/documents/{acme}/download").status_code == 404
    assert acme not in [d["id"] for d in carol.get("/api/documents").get_json()["items"]]
    assert alice.post(f"/api/documents/{acme}/restore").status_code == 200
    assert carol.get(f"/api/documents/{acme}/download").status_code == 200   # grant survived delete


def test_session_idle_and_absolute_limits(app):
    carol = Api(app, "carol")
    clock.advance(61 * 60)
    assert carol.get("/api/documents").status_code == 401           # idle
    carol2 = Api(app, "carol")
    alive_until = None
    for step in range(1, 13):                                       # active every 50 minutes
        clock.advance(50 * 60)
        if carol2.get("/api/documents").status_code == 401:
            alive_until = step * 50
            break
    assert alive_until is not None, "session outlived the absolute limit"
    assert 8 * 60 - 50 < alive_until <= 8 * 60 + 50                 # ended at the 8 hour mark


def test_session_token_is_stored_only_as_a_hash(app):
    carol = Api(app, "carol")
    token = carol.c.get_cookie("tv_session").value
    db = raw_db(app)
    ids = [r["id"] for r in db.execute("SELECT id FROM sessions")]
    assert token not in ids and len(ids) >= 1
    assert all(len(i) == 64 for i in ids)
