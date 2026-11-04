"""Authentication: login, lockout, enumeration, session handling, password policy."""
import time

from conftest import Api, audit_rows, build_app, email, raw_db, user_ids
from trustvault import clock
from trustvault.security import DUMMY_HASH, hash_password, verify_password

GOOD = "Demo-Passw0rd-2026"


def test_login_failure_messages_do_not_reveal_whether_an_account_exists(app):
    a = Api(app).login("carol", "wrong-password-123")
    b = Api(app).login("nobody@trustvault.test", "wrong-password-123")
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json()


def test_disabled_and_locked_accounts_look_the_same_as_a_bad_password(app):
    Api(app, "admin").patch(f"/api/admin/users/{user_ids(app)['dave']}", json={"active": False})
    disabled = Api(app).login("dave", GOOD)                    # correct password, disabled
    unknown = Api(app).login("nobody@trustvault.test", GOOD)
    assert disabled.status_code == unknown.status_code == 401
    assert disabled.get_json() == unknown.get_json()


def test_lockout_after_repeated_failures_then_recovers(app):
    for _ in range(5):
        assert Api(app).login("carol", "not-the-password").status_code == 401
    assert Api(app).login("carol", GOOD).status_code == 401           # locked even with the right one
    assert any(r["action"] == "auth.lockout" for r in audit_rows(app))
    clock.advance(16 * 60)
    assert Api(app).login("carol", GOOD).status_code == 200


def test_successful_login_resets_the_failure_counter(app):
    for _ in range(4):
        Api(app).login("carol", "not-the-password")
    assert Api(app).login("carol", GOOD).status_code == 200
    for _ in range(4):
        Api(app).login("carol", "not-the-password")
    assert Api(app).login("carol", GOOD).status_code == 200            # never reached 5 in a row


def test_per_address_throttle(tmp_path):
    app = build_app(tmp_path, ip_failure_limit=6, lockout_threshold=100)
    codes = [Api(app).login(f"user{i}@trustvault.test", "x" * 12).status_code for i in range(8)]
    assert 429 in codes
    assert Api(app).login("carol", GOOD).status_code == 429          # this address is cooling off


def test_passwords_are_hashed_with_a_salt_and_verified_in_constant_time_form(app):
    db = raw_db(app)
    hashes = [r["pw_hash"] for r in db.execute("SELECT pw_hash FROM users")]
    assert len(set(hashes)) == len(hashes)                             # same password, different salt
    assert all(h.startswith("scrypt$") and GOOD not in h for h in hashes)
    assert verify_password(hashes[0], GOOD) and not verify_password(hashes[0], GOOD + "x")
    assert not verify_password("garbage", GOOD) and not verify_password("", GOOD)
    assert verify_password(DUMMY_HASH, "timing-equaliser-not-a-real-password")


def test_unknown_user_costs_about_the_same_as_a_wrong_password(app):
    def timed(addr):
        t = time.perf_counter()
        Api(app).login(addr, "wrong-password-123")
        return time.perf_counter() - t
    known = sorted(timed("alice") for _ in range(4))[1]
    unknown = sorted(timed("nobody@trustvault.test") for _ in range(4))[1]
    assert unknown > known * 0.4                                     # not a fast path


def test_password_policy_is_enforced_on_change(app):
    carol = Api(app, "carol")
    for bad in ("short", "a" * 11, "password123", "aaaaaaaaaaaaaaaa", "carol@trustvault.test", GOOD):
        r = carol.post("/api/auth/change-password", json={"current": GOOD, "new": bad})
        assert r.status_code == 400, bad
    r = carol.post("/api/auth/change-password", json={"current": "wrong", "new": "Valid-passw0rd-xyz"})
    assert r.status_code == 403
    assert any(x["action"] == "auth.password_change" and x["outcome"] == "denied"
               for x in audit_rows(app))


def test_new_accounts_must_change_the_temporary_password_first(app):
    admin = Api(app, "admin")
    r = admin.post("/api/admin/users", json={"email": "frank@trustvault.test", "name": "Frank", "role": "viewer"})
    assert r.status_code == 201
    temp = r.json["temporary_password"]
    frank = Api(app)
    assert frank.login("frank", temp).status_code == 200
    assert frank.get("/api/documents").status_code == 403
    assert frank.get("/api/auth/me").status_code == 200
    assert frank.post("/api/auth/change-password",
                      json={"current": temp, "new": "Frank-chosen-passw0rd"}).status_code == 200
    assert frank.get("/api/documents").status_code == 200


def test_login_input_abuse_is_handled(app):
    c = app.test_client()
    for body in (None, [], "str", {"email": None}, {"email": ["a"], "password": {"x": 1}},
                 {"email": "a" * 10_000, "password": "b" * 10_000}):
        r = c.post("/api/auth/login", json=body) if body is not None else c.post("/api/auth/login")
        assert r.status_code in (400, 401), body
    assert c.post("/api/auth/login", data="email=a&password=b").status_code == 400


def test_session_cookie_junk_is_rejected(app):
    for junk in ("", "x", "a" * 5000, "../../etc/passwd", "' OR 1=1 --"):
        c = app.test_client()
        c.set_cookie("tv_session", junk)
        assert c.get("/api/documents").status_code == 401


def test_every_login_creates_a_fresh_session_token(app):
    one, two = Api(app, "carol"), Api(app, "carol")
    assert one.c.get_cookie("tv_session").value != two.c.get_cookie("tv_session").value
    assert one.csrf != two.csrf


def test_bad_json_to_every_post_endpoint_is_a_clean_400_or_denial(app):
    alice = Api(app, "alice")
    for url in ("/api/auth/change-password", "/api/admin/users"):
        r = alice.c.post(url, data="{oops", content_type="application/json",
                         headers={"X-CSRF-Token": alice.csrf})
        assert r.status_code in (400, 403)
        assert "Traceback" not in r.get_data(as_text=True)
