# THREATS.md

Each entry: **what could go wrong → what I did → test that proves it** (or, for accepted risks, why I left it).
Tests are in `tests/`; `scripts/mutation_check.py` removes 23 individual checks from the code and requires the suite to fail every time (currently 23/23 killed).

Standard I held myself to: *the server decides, every request, from the database.* Nothing about rights lives in a cookie, a URL or the UI.

---

## A. Reaching a document you were not given

| # | Threat | Defence | Test |
|---|---|---|---|
| A1 | **Hidden button, open endpoint.** UI hides Download but the API serves it. | All document routes go through one decorator `doc_route()` → one function `authz.authorize()`. UI is never consulted. | `test_every_user_every_document_every_action` (5 users × 4 docs × 11 actions, expectations written by hand) |
| A2 | **IDOR** — guess/iterate another document's id. | IDs are random UUIDv4. Even with a valid id, `authorize()` is checked. Unknown and forbidden both return **404 with an identical body**, so ids can't be probed for existence. | `test_response_for_missing_and_forbidden_documents_is_identical`, `test_bad_ids_cannot_probe_or_inject` |
| A3 | **A route nobody guarded** (new endpoint, forgotten decorator). | Default deny: a `before_request` hook refuses any endpoint without an `_auth` marker. A test enumerates every URL rule and fails the build if one is unmarked, if a `<doc_id>` route isn't `doc`-guarded, or if the set of public routes changes. | `test_every_route_declares_who_may_call_it`, `test_a_route_added_without_a_guard_fails_closed`, `test_every_api_route_rejects_anonymous_callers` |
| A4 | **Old versions / alternate download paths** (`?version=1`). | Same guard; versions belong to the document and are fetched only via the authorised row. | `test_old_versions_are_protected_like_the_document` |
| A5 | **Search/list leaks** — a search hit reveals a title you can't open; wildcard `%` widens results. | List/search use `visible_clause()` (SQL form of the same rule) with bound parameters; LIKE wildcards are escaped. A test asserts the SQL rule and `authorize()` **agree for every user in messy states** (expired grants, stray admin rows, demoted, locked-down, trashed) so they can't drift. | `test_list_query_and_authorize_agree_for_every_user_in_every_state`, `test_search_wildcards_and_injection_do_not_widen_results`, `test_search_never_reveals_documents_the_user_cannot_read` |
| A6 | **Mass assignment** — PATCH `owner_id`, `deleted_at`, `current_version`. | PATCH accepts an allow-list (`name`, `category`, `description`); anything else is a 400. Admin PATCH likewise. | `test_mass_assignment_cannot_change_ownership` |
| A7 | **Edit-grantee escalates** — shares, deletes, or lists who has access. | Rights are ordered `read < edit < owner`; share/delete/view-grants need `owner`. | `test_edit_grantee_cannot_share_delete_or_see_who_has_access` |
| A8 | **Viewer holds an `edit` row** (role changed later, or bad data). | Role cap is applied at *decision* time, not only at grant time: a viewer can never exceed `read`. | `test_demoting_a_user_caps_their_rights_at_once` |
| A9 | **Administrator reads everything.** The most common design flaw. | Admins have **no content rights at all**: can't read, download, edit, share, or be granted access — even if a stray grant row exists. They see metadata and the audit trail. See *Accepted risks* for the cost. | `test_admin_cannot_read_content_by_any_route`, `test_admin_cannot_be_granted_access_even_by_a_stray_row` |
| A10 | **Deleted document still reachable** by people it was shared with, or revealing its existence. | Deleted docs are 404 for everyone but the owner (who may only restore / view trail). Found and fixed during testing: non-owner previously got 403 on restore, confirming existence. | `test_trash_is_private_to_the_owner`, `test_deleting_a_document_removes_access_for_everyone_else_at_once` |
| A11 | **Unknown action name** passed to the decision function. | `ACTION_NEEDS[action]` raises `KeyError` → fail closed. | `test_unknown_actions_fail_closed` |
| A12 | **Race between revoke and download.** | Decision, action and audit record share one `BEGIN IMMEDIATE` transaction; SQLite serialises writers, so a download either completes entirely before the revoke or is refused. | `test_a_change_and_its_audit_record_commit_together` |

## B. Taking access away (must be immediate)

Design: **no capability tokens exist.** No signed download URLs, no JWTs, no cached permission sets. A session cookie is an opaque random value whose SHA‑256 is looked up on every request; rights are recomputed from `users`/`grants` each time. *Cost:* one or two indexed SQLite reads per request, and no horizontal scale-out without a shared DB. I accepted that deliberately.

| # | Threat | Defence | Test |
|---|---|---|---|
| B1 | Grant removed, but user's open session/tab still works. | Next request is re-evaluated; same cookie gets 404. | `test_revoked_grant_stops_the_very_next_request_on_the_same_session` |
| B2 | Edit→read downgrade lags. | Same. | `test_downgrade_from_edit_to_read_is_immediate` |
| B3 | Leaver's account still works. | Disabling revokes all sessions **and** `active` is re-checked per request (defence in depth, tested separately by flipping the flag with no revocation). | `test_disabling_a_user_kills_their_existing_session_instantly`, `test_disabled_flag_alone_blocks_a_live_session_even_if_revocation_was_missed` |
| B4 | Stolen cookie after logout. | Logout marks the session revoked server-side. | `test_logout_makes_a_stolen_cookie_useless` |
| B5 | Password reset/change leaves old sessions alive. | Both revoke every other session. Admin reset also sets `must_change_pw`, which blocks all document access until changed. | `test_password_change_ends_every_other_session`, `test_admin_password_reset_locks_the_account_until_changed` |
| B6 | Shared "for a day" but never removed. | Optional `expires_at` (≤ 1 year), evaluated at read time — nothing has to run for it to take effect. | `test_time_limited_grant_expires_without_anyone_doing_anything` |
| B7 | Session theft/long-lived sessions. | 60‑min idle and 8‑hour absolute limits; only the hash of the token is stored (DB leak ≠ live sessions). | `test_session_idle_and_absolute_limits`, `test_session_token_is_stored_only_as_a_hash` |
| B8 | **Copies already downloaded.** | **Cannot be fixed by any server-side design.** Access removal stops *future* access; bytes already saved are out of reach. The audit trail records exactly who downloaded which version (with SHA‑256) so the owner knows what is out there. Accepted. | — |

## C. The audit trail

| # | Threat | Defence | Test |
|---|---|---|---|
| C1 | Refused attempts not recorded ("we only log successes"). | Every refusal is a record: `document.access_denied` (with attempted action + reason), `route.denied`, failed/locked logins. | `test_every_refused_attempt_is_in_the_audit_trail` (count matches the matrix exactly) |
| C2 | Download without a record. | The audit row is written *before* bytes are read, in the same transaction. If the write fails, the transaction aborts and **no bytes are sent**. | `test_no_audit_record_means_no_bytes` |
| C3 | Change happens, record is lost (or vice-versa). | Change + record commit atomically. | `test_a_change_and_its_audit_record_commit_together` |
| C4 | Quietly edit/delete a row via the app or SQL. | Three layers: (1) no app code path edits it; (2) DB triggers abort UPDATE/DELETE; (3) rows form an **HMAC‑SHA256 chain** keyed with a secret that is *not in the database*. | `test_the_application_database_user_cannot_update_or_delete_audit_rows` |
| C5 | Attacker with raw file access drops the triggers and edits. | Detected by `verify()`: edited row, deleted middle row, reordered rows, rewritten link field, and a forged row using the wrong key. Admin dashboard shows chain status; a failure is a *critical* alert. | `test_editing_a_row_is_detected_even_with_the_triggers_gone`, `…deleting_a_row_from_the_middle…`, `…forging_a_record_without_the_audit_key…`, `…reordering…`, `…rewriting_only_the_stored_link_field…` |
| C6 | **Truncating the tail** of the log (a shorter chain is still a valid chain). | **Off-box anchors.** `flask audit-anchor` appends a signed `seq hash time mac` line to `TRUSTVAULT_ANCHOR_FILE`, which the app refuses to place inside the data directory. Verification fails if any anchored record is missing or changed, forged anchor lines are rejected, and a broken chain is never anchored. The admin dashboard raises a *critical* alert on mismatch and a visible nudge if anchoring isn't configured. **Residual risk:** records written after the newest anchor and then removed are undetectable — the window equals your anchor interval (run it from cron every few minutes). The anchor file only protects you if the attacker can't also edit it: keep it on separate/append-only storage or ship each line off the box. | `test_truncating_the_tail_is_invisible_to_the_chain_but_caught_by_the_anchor`, `test_forged_or_malformed_anchor_lines_are_rejected`, `test_refuses_to_anchor_a_broken_chain`, `test_anchor_must_live_outside_the_data_directory`, `test_cli_anchor_and_verify_commands` |
| C7 | Attacker who steals **both** the DB and the audit key can rewrite history. | Keys are separate env vars, never in the repo/DB. If both are stolen the attacker can rebuild a chain, but anchors you already shipped off-box (C6) still expose any rewrite of anchored history. Anchors you did *not* ship off-box, and everything newer than the last anchor, remain at risk. Accepted. | — |
| C8 | Forged/spoofed IP in the log (`X-Forwarded-For`). | Headers are ignored unless `TRUSTVAULT_PROXY_HOPS` says exactly how many trusted proxies exist (Werkzeug `ProxyFix`). Default 0. Misconfiguring this is an operator risk, documented in README. | — |
| C9 | Log flooding / log injection. | Values are stored as JSON strings (never interpreted); UI renders with `textContent`. Failed-login flood is capped by per-IP throttle. | `test_per_address_throttle` |

## D. Accounts and sessions

| # | Threat | Defence | Test |
|---|---|---|---|
| D1 | Brute-force/credential stuffing. | scrypt hashes; 5 failures → 15-min lockout (audited); per-IP failure throttle (429). | `test_lockout_after_repeated_failures_then_recovers`, `test_per_address_throttle` |
| D2 | User enumeration (message or timing). | One generic message; a dummy hash is verified for unknown/locked/disabled accounts so cost is equal. | `test_login_failure_messages_do_not_reveal…`, `test_unknown_user_costs_about_the_same…` |
| D3 | **Lockout as denial-of-service** against a named user. | Known trade-off: an attacker can lock a known e-mail for 15 min. Accepted over the alternative (unbounded guessing). Per-IP throttle limits how often it can be repeated from one address. | — |
| D4 | CSRF. | `SameSite=Strict` cookie **plus** per-session CSRF token header **plus** Origin check on every state-changing request. | `test_csrf_and_cross_origin_are_enforced` |
| D5 | XSS stealing sessions/rendering hostile filenames. | Cookie is `HttpOnly`; UI never uses `innerHTML`; strict CSP (`script-src 'self'`, no inline script). | `test_security_headers_and_cookie_flags` |
| D6 | Weak/default passwords. | Min 12 chars, common-list and repetition checks; admin-issued passwords are random, single-use, force change, and are shown once. | `test_password_policy_is_enforced_on_change`, `test_new_accounts_must_change…` |
| D7 | Session fixation. | A new random token is minted at every login; none is accepted from the client. | `test_every_login_creates_a_fresh_session_token` |
| D8 | Junk/oversized cookie, body or JSON. | Length-capped; clean 400/401, no stack traces. | `test_session_cookie_junk_is_rejected`, `test_login_input_abuse_is_handled`, `test_errors_do_not_leak_internals` |

## E. What is uploaded, and how it is stored

| # | Threat | Defence | Test |
|---|---|---|---|
| E1 | Executable/HTML/SVG upload → stored XSS when downloaded. | Extension allow-list **and** magic-byte check; Office files must be real ZIPs with the right part directory. Downloads are `attachment`, `nosniff`, sandbox CSP, and the MIME type comes from the server's table, never the client. | `test_dangerous_or_mislabelled_files_are_refused`, `test_download_headers_prevent_in_browser_execution`, `test_server_ignores_the_content_type_the_client_claims` |
| E2 | Macro-enabled Office, zip-slip, zip bombs. | `.docm` refused; `vbaProject.bin` refused; `..`/absolute paths refused; expansion size and ratio capped. | included in the refused-files parametrisation, `test_decompression_bomb_is_refused` |
| E3 | Path traversal via filename. | Filename is *only a label*: sanitised, never used as a path. Blob names are random 128-bit hex. | `test_filenames_are_sanitised_and_never_used_as_paths` |
| E4 | Resource exhaustion. | Per-file limit (20 MB), request cap, per-owner quota. | `test_oversized_upload_is_refused…`, `test_storage_quota_per_owner` |
| E5 | **Someone reads the disk / backup directly.** | AES‑256‑GCM per file, with a per-file data key wrapped by a master key (envelope encryption). Files carry no names or owners. Master key is an env var, not on disk with the data. | `test_files_on_disk_are_ciphertext_with_opaque_names` |
| E6 | **Swapping ciphertext between documents** (disk-write attacker). | AEAD associated data binds each blob to its document, version and blob id; a swap fails authentication → 500, no bytes leaked. Bit-flips also fail. | `test_a_blob_swapped_between_documents_does_not_leak_the_other`, `test_a_flipped_bit_on_disk_is_detected` |
| E7 | "Deleted" data lingers. | Soft delete (recoverable N days) then `flask purge` destroys blob **and** wrapped key (crypto-shredding). | `test_purge_destroys_blob_and_key_for_deleted_documents` |
| E8 | **No malware scanning.** | Not built. Content is validated by type, not scanned for viruses. Documents are served only as attachments and never rendered by the app, which limits exposure, but a malicious but well-formed PDF/Office file will be stored. Accepted; production should add ClamAV. | — |

## F. Where AI fits

| # | Threat | Defence | Test |
|---|---|---|---|
| F1 | AI widens access on its own. | Suggestions are rows that **cannot** grant. Only the owner's call to `POST /grants` changes access. Suggestions can only propose `read`. | `test_suggestions_are_advice_only_and_audited` |
| F2 | Decision not traceable to the suggestion. | Generation, acceptance (with suggestion id, reason, and whether the owner followed it exactly) and dismissal are all audited, with the human as actor. | `test_accepting_a_suggestion_is_a_separate_owner_decision_and_both_are_audited` |
| F3 | Replay / cross-document use of a suggestion. | A suggestion is single-use and bound to one document and one user. | `test_a_suggestion_cannot_be_used_on_another_document_or_by_another_user` |
| F4 | Leaking content to a model. | The shipped provider is a transparent rule (`rules-v1`) over metadata only. If an LLM is added later it receives metadata, never contents, and cannot reach `grants`. | — |

## G. Accepted risks and things I did not build (honest list)

1. **Downloaded copies can't be recalled** (B8). Mitigation is the audit record, not prevention.
2. **Audit records newer than the last anchor** (C6, C7): anchoring narrows the window to your anchor interval; it does not eliminate it, and it is only as safe as wherever you keep the anchors.   On Render there is no second volume or scheduler. The anchor file lives in `/tmp` and is lost on restart, so anchor lines are copied off-box manually.
3. **No MFA / SSO.** Passwords only. This is the weakest part of authentication; for real use I would put the app behind SSO.
4. **No malware scanning** (E8).
5. **SQLite, one writer, single node.** Chosen so that "decision + change + audit in one atomic transaction" is simple and demonstrably correct. Cost: not horizontally scalable.
6. **Master-key rotation is not implemented.** Per-file wrapped keys make it possible (re-wrap, don't re-encrypt), but I did not write the tool.
7. **Admin has no content rights → no break-glass.** If an owner leaves, their documents are orphaned (admins cannot demote an owner who owns documents). Safer for confidentiality, worse for operations. A real system needs a dual-control recovery process.
8. **No external sharing / links.** Deliberately omitted: every external recipient is an account. Avoids bearer-link revocation problems entirely.
9. **Lockout DoS** (D3).
10. **Rate limiting is login-only** and in the database; no general API throttle. A fronting proxy should provide one.
11. **Metadata visible to administrators**: names, categories, owner, share counts. They see *that* a file exists, never its content.
12. **Timing of "found but forbidden" vs "missing"** is not equalised beyond identical bodies/status.
13. **Test-suite caveat:** the mutation script covers the 25 checks I thought of; it is not exhaustive.

14. **Oversized uploads are not audited.** Uploads over the size limit are rejected with HTTP 413 before the application's audit write, so they do not appear in the audit trail,and the UI shows only a brief "request too large" toast. Found while attack-testing the live deployment on 06-11-2026. Known, left as is; a fix would be a request-size check inside the app, with a test first.

15. **Database file was group/world-readable (fixed).** Found by running `find /data -type f -perm /077` on the live container: `trustvault.db` was mode 644 while blobs were owner-only. Fixed by setting umask 077 and chmod 600 on the db, `-wal` and `-shm` files in `init_db`. The regression test is skipped on Windows (NTFS has no POSIX modes), so it was verified on the deployed Linux container: the same `find` now prints nothing.