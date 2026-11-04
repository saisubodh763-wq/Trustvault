# PROMPTS.md

**Read this first.** This file records what actually happened in the AI-assisted build session (2–4 Nov 2026). It does **not** cover a week of work, because the work so far was one session. Entries are real, with the real commit that fixed each one. The commit hashes below are from the local repository and will match the public repo once its history is pushed. **Add your own dated entries as you continue**: reviewers will compare this file with your commit dates.

## Context reused across the session

The standing instructions I gave the assistant, and which every later step was held to:

1. *The full challenge brief*, pasted verbatim as the first prompt. Its three standards became the test files: `test_isolation.py` (#1), `test_audit.py` (#2), `test_revocation.py` (#3).
2. **"The server decides, every request."** No rights in cookies/URLs/UI; one decision function; default-deny for unmarked routes.
3. **"Every test must be able to fail."** After the first draft I asked for a script that removes one authorisation check at a time and requires the suite to fail (`scripts/mutation_check.py`). This is the prompt that found the most.
4. **"Write expected results by hand, don't derive them from the code under test."** Used for the isolation matrix.
5. **"Refusals are evidence."** Every denied attempt gets an audit record.
6. **Honesty rule for docs:** write what's not built, not deployed, and not verified.

---

## Entry 1 — 2026-11-02 — Tests that could not fail  *(audit trail)*

**Asked:** Write `tests/test_audit.py` proving each lifecycle event (upload, update, version, share, download, revoke, delete, restore) is recorded with the right actor and details.

**Produced:** A lifecycle test whose key assertions ended in `... == hashlib.sha256(b"plan2").hexdigest() or True` and `A == "plan.txt" or A == "plan.txt"` (the same condition twice).

**Wrong:** Both assertions were tautologies. The test would pass whether or not the audit record contained the right hash or the right *before* value, so it proved nothing about the one thing an audit trail is for: *which bytes* left, and *what changed*. It looked thorough and was green.

**Instead:** Rewrote them to assert the exact hash of the version downloaded (`detail["sha256"] == sha256(b"plan2")`, `detail["version"] == 2`) and the exact before/after of the rename (`before == {"name": "plan.txt"}`, `after == {"name": "Plan v2"}`), plus the actor. Caught on a read-through before the first commit, so the committed version already has the fix: `bf15f78`. I then asked for a mutation check (standing instruction 3) so that this class of mistake is found mechanically rather than by reading.

## Entry 2 — 2026-11-02/04 — A 403 that confirmed a deleted document exists  *(access control)*

**Asked:** Implement soft delete: a deleted document must be invisible to everyone but its owner, who may only restore it.

**Produced:** In `authz.authorize()`, a deleted document returned `Decision(False, "deleted", …)` only for actions *outside* a `DELETED_OK` set. For the allowed set (`restore`, `view_grants`, `view_audit`) it fell through to the normal level check.

**Wrong:** A viewer with a read grant who POSTed `/restore` on a deleted document got **403**, while someone with no grant got 404. That told Carol "this document still exists in a deleted state", and let *anyone holding a grant* probe the state of a trashed document. The tests I had written first asserted the correct behaviour (404 for non-owners), and failed. The AI's first reaction was to treat the test as wrong; I checked the rule and the code was wrong.

**Instead:** Deleted documents now return the same "not found" decision for every non-owner before any level comparison (`authz.py`), so existence/state can't be probed. A later mutation (`deleted documents hidden from non-owners`) confirms the suite fails if this branch is removed. Fixed in `7aed6e0`.

## Entry 3 — 2026-11-04 — "The size limit is enforced" (it wasn't)  *(upload validation)*

**Asked:** Enforce a per-file upload limit and test that an oversized file is refused before being stored.

**Produced:** Set Flask's `MAX_CONTENT_LENGTH` to `max_upload_bytes + 64 KB` and wrote a test uploading 5,000 bytes against a 2,000-byte limit.

**Wrong:** The test returned **201**: the 64 KB of slack meant files up to the limit *plus 64 KB* were stored. The AI had treated a transport-level cap as the application's rule. A 20 MB limit would have silently been 20.06 MB, and, worse, the configured limit did nothing for small configured values.

**Instead:** Kept `MAX_CONTENT_LENGTH` as a coarse transport guard and enforced the exact per-file limit in `_upload_from_request()` with a 413; the test now checks 1,999 bytes accepted, 5,000 refused, and 300 KB refused by the transport cap. Fixed in `7aed6e0`.

## Entry 4 — 2026-11-04 — Two authorisation checks nothing depended on  *(access control + audit trail)*

**Asked:** Run `scripts/mutation_check.py`: delete 21 individual checks, one at a time, and report any that leave the suite green. (This is the check the brief says a judge will perform.)

**Produced:** 187 passing tests and a confident claim that the suite covered the isolation guarantees.

**Wrong:** **Two of 21 mutations survived** — the suite was green with the check removed:
* *Disabled users' sessions stop working* (`web.authenticate`): `PATCH active=false` also revokes sessions, so the per-request `active` check was never the thing that stopped the request. Tests passed whether or not the check existed.
* *Audit chain link verification*: the stored `prev_hash` column isn't part of the signed row content, so an attacker editing only that column was **undetectable** without the explicit link check, and no test did that.

**Instead:** Added `test_disabled_flag_alone_blocks_a_live_session_even_if_revocation_was_missed` (flip `active` in SQL with the session still live) and `test_rewriting_only_the_stored_link_field_is_detected`. Re-ran: **21/21 killed**. (Committed after this file was written; see the commit following `381ba76`.)

## Entry 5 — 2026-11-02 — Time tests that tested the wrong thing  *(revocation)*

**Asked:** Test that a time-limited grant expires, and that sessions have idle and absolute limits.

**Produced:** `clock.advance(3601)` then assert 404 for the expired grant; and a loop advancing 50 minutes at a time asserting an 8-hour absolute limit.

**Wrong:** Advancing 3,601 s also exceeds the 60-minute **idle** timeout, so the request returned **401**, not the 404 that proves *the grant* expired. The session test never reached the absolute limit and only checked "eventually 401" with an unreachable `else`. Both would have passed for the wrong reason.

**Instead:** Advance in two 30-minute steps so the session stays fresh, then assert 404 specifically; for the absolute limit, record at which step the 401 arrives and assert it is at the 8-hour mark (±50 min). Fixed before the first commit: `bf15f78`.

---

## What the AI got right (so this file isn't one-sided)

Most of the code was right first time, including the HMAC chain, the AAD binding of blobs to documents, and the per-request transaction structure. I checked those by tampering with the data directly in tests (drop triggers → edit/delete/reorder/forge, swap ciphertext between documents, flip a bit), not by reading the code, and each tamper is detected.

## To add yourself

* Your own dated prompts and the real commit links once history is pushed.
* Any session where you disagreed with the tool's design (e.g. admins having no content rights was a decision I had to hold against convenience).
