"""Standard #2: prove who reached what, including refused attempts, and make
the record hard to alter quietly."""
import hashlib
import hmac
import json
import sqlite3

import pytest

from conftest import ACME, AUDITP, SALARY, Api, audit_rows, doc_ids, email, raw_db, user_ids
from trustvault import audit as audit_mod


def actions(app, **where):
    return [(r["action"], r["outcome"], r["actor_email"]) for r in audit_rows(app, **where)]


def test_full_lifecycle_is_recorded_with_actor_and_document(app):
    alice, carol = Api(app, "alice"), Api(app, "carol")
    r = alice.upload("plan.txt", b"plan", category="Strategy")
    doc = r.json["id"]
    alice.patch(f"/api/documents/{doc}", json={"name": "Plan v2"})
    alice.upload("plan2.txt", b"plan2", url=f"/api/documents/{doc}/versions")
    alice.post(f"/api/documents/{doc}/grants", json={"email": email("carol"), "level": "read"})
    carol.get(f"/api/documents/{doc}/download")
    alice.post(f"/api/documents/{doc}/grants", json={"email": email("carol"), "level": "read",
                                                     "expires_at": "2099-01-01"} )
    alice.delete(f"/api/documents/{doc}/grants/{user_ids(app)['carol']}")
    alice.delete(f"/api/documents/{doc}")
    alice.post(f"/api/documents/{doc}/restore")
    seen = actions(app, doc_id=doc)
    names = [a for a, _o, _e in seen]
    for expected in ("document.upload", "document.update", "document.version", "grant.add",
                     "document.download", "grant.revoke", "document.delete", "document.restore"):
        assert expected in names, expected
    download = [r for r in audit_rows(app, doc_id=doc) if r["action"] == "document.download"][0]
    assert download["actor_email"] == email("carol") and download["outcome"] == "allowed"
    detail = json.loads(download["detail"])
    assert detail["sha256"] == hashlib.sha256(b"plan2").hexdigest()      # which bytes, exactly
    assert detail["version"] == 2
    update = [r for r in audit_rows(app, doc_id=doc) if r["action"] == "document.update"][0]
    change = json.loads(update["detail"])
    assert change["before"] == {"name": "plan.txt"} and change["after"] == {"name": "Plan v2"}
    assert update["actor_email"] == email("alice")


def test_a_grant_change_records_old_and_new_level(app):
    bob, acme_owner = Api(app, "bob"), Api(app, "alice")
    acme = doc_ids(app)[ACME]
    acme_owner.post(f"/api/documents/{acme}/grants", json={"email": email("carol"), "level": "read"})
    rows = [r for r in audit_rows(app, doc_id=acme) if r["action"] == "grant.change"]
    assert rows and json.loads(rows[-1]["detail"])["previous_level"] == "read"


def test_refused_attempts_are_recorded_with_reason(app):
    dave, carol = Api(app, "dave"), Api(app, "carol")
    salary, acme = doc_ids(app)[SALARY], doc_ids(app)[ACME]
    dave.get(f"/api/documents/{salary}/download")
    carol.patch(f"/api/documents/{acme}", json={"name": "x"})
    denied = [r for r in audit_rows(app) if r["action"] == "document.access_denied"]
    assert len(denied) == 2
    d1, d2 = (json.loads(r["detail"]) for r in denied)
    assert (denied[0]["actor_email"], d1["attempted"], d1["reason"]) == (email("dave"), "download", "no_access")
    assert (denied[1]["actor_email"], d2["attempted"], d2["reason"]) == (email("carol"), "edit", "insufficient_level")
    assert denied[0]["doc_id"] == salary and denied[0]["ip"]


def test_failed_logins_and_role_violations_are_recorded(app):
    Api(app).login("carol", "wrong-password-123")
    Api(app).login("nobody@trustvault.test", "whatever-123456")
    carol = Api(app, "carol")
    carol.get("/api/admin/users")
    rows = audit_rows(app)
    assert sum(1 for r in rows if r["action"] == "auth.login" and r["outcome"] == "denied") == 2
    assert any(r["action"] == "route.denied" and r["actor_email"] == email("carol") for r in rows)


def test_owner_can_see_who_touched_their_document_including_refusals(app):
    alice, dave, carol = Api(app, "alice"), Api(app, "dave"), Api(app, "carol")
    acme = doc_ids(app)[ACME]
    dave.get(f"/api/documents/{acme}/download")
    carol.get(f"/api/documents/{acme}/download")
    items = alice.get(f"/api/documents/{acme}/audit").get_json()["items"]
    who = {(i["actor_email"], i["action"], i["outcome"]) for i in items}
    assert (email("carol"), "document.download", "allowed") in who
    assert (email("dave"), "document.access_denied", "denied") in who
    assert Api(app, "carol").get(f"/api/documents/{acme}/audit").status_code == 403


def test_chain_verifies_after_normal_use(app):
    Api(app, "alice").upload("a.txt", b"a")
    Api(app, "carol").get("/api/documents")
    result = audit_mod.verify(raw_db(app), app.config["TV"])
    assert result["ok"] and result["records_checked"] > 5 and len(result["head"]) == 64
    assert Api(app, "admin").get("/api/admin/audit/verify").get_json()["ok"] is True


def test_the_application_database_user_cannot_update_or_delete_audit_rows(app):
    db = raw_db(app)
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_log SET actor_email='someone-else' WHERE seq=1")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit_log WHERE seq=1")


def _tamper(app, statement, *args):
    """Simulate an attacker with raw file access: drop the triggers, then edit."""
    db = raw_db(app)
    db.execute("DROP TRIGGER audit_no_update")
    db.execute("DROP TRIGGER audit_no_delete")
    db.execute(statement, args)
    db.close()


def test_editing_a_row_is_detected_even_with_the_triggers_gone(app):
    Api(app, "carol").get(f"/api/documents/{doc_ids(app)[SALARY]}")
    seq = [r["seq"] for r in audit_rows(app, action="document.access_denied")][0]
    _tamper(app, "UPDATE audit_log SET actor_email='nobody@x.test' WHERE seq=?", seq)
    result = Api(app, "admin").get("/api/admin/audit/verify").get_json()
    assert result["ok"] is False and result["first_bad_seq"] == seq


def test_deleting_a_row_from_the_middle_is_detected(app):
    Api(app, "dave").get(f"/api/documents/{doc_ids(app)[SALARY]}")
    Api(app, "carol").get("/api/documents")
    seqs = [r["seq"] for r in audit_rows(app)]
    middle = seqs[len(seqs) // 2]
    _tamper(app, "DELETE FROM audit_log WHERE seq=?", middle)
    result = audit_mod.verify(raw_db(app), app.config["TV"])
    assert result["ok"] is False and result["first_bad_seq"] == middle + 1


def test_forging_a_record_without_the_audit_key_is_detected(app):
    """The attacker edits a row and recomputes the hashes - with the wrong key."""
    Api(app, "dave").get(f"/api/documents/{doc_ids(app)[SALARY]}")
    db = raw_db(app)
    db.execute("DROP TRIGGER audit_no_update")
    victim = db.execute("SELECT * FROM audit_log WHERE action='document.access_denied'").fetchone()
    forged = dict(victim, actor_email="innocent@trustvault.test")
    fields = ("seq", "ts", "actor_id", "actor_email", "action", "outcome", "doc_id",
              "target_user_id", "detail", "ip")
    canon = json.dumps({k: forged[k] for k in fields}, sort_keys=True, separators=(",", ":"))
    guess_key = b"\x00" * 32
    new_hash = hmac.new(guess_key, (forged["prev_hash"] + canon).encode(), hashlib.sha256).hexdigest()
    db.execute("UPDATE audit_log SET actor_email=?, hash=? WHERE seq=?",
               (forged["actor_email"], new_hash, victim["seq"]))
    assert audit_mod.verify(db, app.config["TV"])["ok"] is False


def test_reordering_records_is_detected(app):
    Api(app, "carol").get("/api/documents")
    Api(app, "alice").get("/api/documents")
    rows = audit_rows(app)
    a, b = rows[-1], rows[-2]
    db = raw_db(app)
    db.execute("DROP TRIGGER audit_no_update")
    db.execute("UPDATE audit_log SET seq = 9999 WHERE seq=?", (a["seq"],))
    db.execute("UPDATE audit_log SET seq = ? WHERE seq=?", (a["seq"], b["seq"]))
    db.execute("UPDATE audit_log SET seq = ? WHERE seq=9999", (b["seq"],))
    assert audit_mod.verify(db, app.config["TV"])["ok"] is False


def test_no_audit_record_means_no_bytes(app, monkeypatch):
    """If the audit write fails, the file must not be served."""
    real = audit_mod.append

    def failing(db, cfg, **kw):
        if kw.get("action") == "document.download":
            raise RuntimeError("audit store unavailable")
        return real(db, cfg, **kw)

    monkeypatch.setattr(audit_mod, "append", failing)
    r = Api(app, "carol").get(f"/api/documents/{doc_ids(app)[ACME]}/download")
    assert r.status_code == 500
    assert b"Acme" not in r.data and b"CONFIDENTIAL" not in r.data


def test_a_change_and_its_audit_record_commit_together(app, monkeypatch):
    real = audit_mod.append

    def failing(db, cfg, **kw):
        if kw.get("action") == "document.delete":
            raise RuntimeError("boom")
        return real(db, cfg, **kw)

    monkeypatch.setattr(audit_mod, "append", failing)
    acme = doc_ids(app)[ACME]
    assert Api(app, "alice").delete(f"/api/documents/{acme}").status_code == 500
    row = raw_db(app).execute("SELECT deleted_at FROM documents WHERE id=?", (acme,)).fetchone()
    assert row["deleted_at"] is None                 # the delete did not happen


def test_concurrent_looking_appends_keep_one_unbroken_chain(app):
    clients = [Api(app, u) for u in ("alice", "bob", "carol", "dave")]
    for _ in range(5):
        for c in clients:
            c.get("/api/documents")
            c.get(f"/api/documents/{doc_ids(app)[SALARY]}")
    assert audit_mod.verify(raw_db(app), app.config["TV"])["ok"]


def test_audit_log_endpoint_is_admin_only_and_filterable(app):
    Api(app, "dave").get(f"/api/documents/{doc_ids(app)[SALARY]}")
    assert Api(app, "alice").get("/api/admin/audit").status_code == 403
    assert Api(app).get("/api/admin/audit").status_code == 401
    admin = Api(app, "admin")
    r = admin.get("/api/admin/audit?outcome=denied&action=document.access_denied").get_json()
    assert r["total"] == 1 and r["items"][0]["actor_email"] == email("dave")
    r = admin.get(f"/api/admin/audit?doc_id={doc_ids(app)[SALARY]}").get_json()
    assert {i["action"] for i in r["items"]} >= {"document.upload", "document.access_denied"}


def test_rewriting_only_the_stored_link_field_is_detected(app):
    """prev_hash is not part of the signed row content, so only the explicit
    link check catches an edit to it."""
    Api(app, "carol").get("/api/documents")
    seq = audit_rows(app)[-1]["seq"]
    _tamper(app, "UPDATE audit_log SET prev_hash=? WHERE seq=?", "f" * 64, seq)
    result = audit_mod.verify(raw_db(app), app.config["TV"])
    assert result["ok"] is False and result["first_bad_seq"] == seq
    assert result["problem"] == "broken link to previous record"
