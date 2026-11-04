# TrustVault: what to do next, in order

State today: code, 207 passing tests, 25/25 mutation kills, docs, Dockerfile. **Not yet:** pushed to GitHub, deployed, demoed. A judge attacks the *live URL*, so steps 1–3 come before anything else. Rough effort: steps 1–4 about half a day; the rest spread over the week.

---

## Step 1 — Put it on GitHub (10 min)

Repo: `https://github.com/saisubodh763-wq/trustvault`

```bash
unzip trustvault.zip && cd trustvault          # the zip contains .git, so history is kept
git status                                      # should be clean
git remote add origin https://github.com/saisubodh763-wq/trustvault.git
git branch -M main
git push -u origin main
```
* Repo must be **public**. Check it from a private window.
* Before pushing run `git log --oneline`: you should see ~5 commits. Don't squash them; the history is evidence.
* Confirm `.gitignore` kept `data/`, `.env` and any `*.db` out. `git ls-files | grep -E "\.env$|\.db$|data/"` should print nothing.
* Never commit the two keys. If you ever do, rotate them (this means re-creating the deployment's data; see Step 9).

## Step 2 — Deploy (45–90 min). Do it today, not on the last day.

You need: HTTPS, a **persistent disk**, one process. Easiest paths:

**A. Render (uses `render.yaml`)**
1. Render → New → Blueprint → pick the repo.
2. In the service's Environment tab set:
   * `TRUSTVAULT_MASTER_KEY` = output of `python3 -c "import secrets;print(secrets.token_hex(32))"`
   * `TRUSTVAULT_AUDIT_KEY` = a **different** value from the same command
   * `TRUSTVAULT_PROXY_HOPS=1`, `TRUSTVAULT_SEED_DEMO=1`
3. Confirm the disk is mounted at `/data` (blueprint does this). Without a disk, data vanishes on each deploy.
4. Open `https://<name>.onrender.com/healthz` → `{"status":"ok"}`.

**B. Any VPS with Docker + Caddy/nginx for HTTPS** (the commands are in README → *Deploy*). Terminate TLS at the proxy and set `TRUSTVAULT_PROXY_HOPS=1`.

**Verify after deploying (5 min):**
- Log in as each demo account (`README.md` table, password `Demo-Passw0rd-2026`).
- Dave sees *no* documents; Carol sees two; Admin gets "Audit trail verified".
- Try `/api/documents` without logging in → 401. Try `/data/trustvault.db` and `/blobs/` → 404.
- Browser shows a padlock and the cookie is marked **Secure** (DevTools → Application → Cookies).

Write the live URL into `README.md` (top) and push.

## Step 3 — Turn on audit anchoring on the live system (20 min)

Without this, deleting the *newest* audit records is undetectable.
1. Choose an anchor location **outside** `/data`: a second small disk/volume, or ship each line off the box. The app refuses to start if the path is inside the data directory.
2. Set `TRUSTVAULT_ANCHOR_FILE=/anchors/anchors.log`.
3. Schedule it every 5 minutes: `*/5 * * * * docker exec <container> flask --app wsgi audit-anchor` (Render: a Cron Job service running the same command). Optionally email or post the printed line somewhere you control.
4. Check: Admin → Alerts should stop showing "anchoring is not configured". Run `flask --app wsgi audit-verify`; it must exit 0.

**Be ready to say in the interview:** the anchor protects you only if an attacker can't also edit the anchor file; and anything newer than the last anchor is unprotected (the window = your interval).

## Step 4 — Replace demo data before you hand it in? No — but do this (15 min)

* Keep the demo accounts so judges can log in (they're public by design).
* Do **not** put real personal data in it.
* Reset the seed if it gets messy: stop the service, delete the volume contents, redeploy (seeding only happens on an empty database).

## Step 5 — Record the 5-minute demo (60 min incl. one retake)

Suggested script (watch the clock):
1. **0:00–0:30** What it is; the three standards.
2. **0:30–1:30** Dave (viewer, nothing shared) tries to open a document by URL; gets 404. Carol reads and downloads her two.
3. **1:30–2:30** Alice shares a document with Dave, Dave opens it; Alice removes him; **Dave clicks again with the same tab → refused immediately.**
4. **2:30–3:30** Admin: Audit trail filtered to *denied*; Alerts; "who downloaded this file" via the document's trail. Point out admin **cannot** open any document.
5. **3:30–4:15** Tamper test in a terminal: drop the audit triggers, edit a row, hit *Verify* → chain fails → critical alert.
6. **4:15–5:00** `pytest`, then `python scripts/mutation_check.py` (kill 25/25). Show `THREATS.md` accepted-risks section.
Upload the video (YouTube unlisted / Drive) and link it in the README.

## Step 6 — Keep history honest across the week (daily, 15 min)

The brief checks that history spans the week. Make **real** small commits daily, e.g.: day 2 Step 3 verification notes; day 3 an extra test; day 4 a UI polish; etc. Don't fake or backdate commits.

For `PROMPTS.md`:
* It needs **≥5 dated entries, ≥2 about authorisation/audit**. It already has 5 real ones from the build session; **add your own** as you keep using the tool: *prompt → what it produced → what was specifically wrong → what you did → commit link*.
* After you push, replace the local commit hashes in `PROMPTS.md` with links: `https://github.com/saisubodh763-wq/trustvault/commit/<hash>`.
* "The AI was helpful" is not an entry. If you ask an AI to review the code and it finds nothing, say so *and show how you verified*.

## Step 7 — Attack your own deployment (2–3 hours; the most valuable thing you can do)

Use two browsers/profiles (or `curl`) against the **live URL**. Work down this list, and record anything surprising in `THREATS.md`:
1. As Dave, request every document id you can learn (from Alice's trail you can't!). Try `/api/documents/<id>/download?version=1`.
2. Replay a request from Carol's session after Alice revokes her; swap CSRF token/cookies between users.
3. Upload: `.html`, `.svg`, `.exe` renamed `.pdf`, a zip bomb `.docx`, a 25 MB file, a filename like `../../x.txt`.
4. Log in with a wrong password 6 times; confirm lockout and that the message doesn't reveal if the account exists.
5. Tamper with the cookie, remove the CSRF header, send a cross-origin `Origin`.
6. Disable a user in Admin while they're logged in; their next click must fail.
7. Try the admin API as Alice (`/api/admin/*` → 403) and look for it in the audit trail.
8. Try to find the DB or blobs through the web (`/data`, `/blobs`, `/.git`, `/static`).
If something works that shouldn't, **write a failing test first**, then fix it, then add the entry to `THREATS.md`. That's worth marks.

Optional: ask an independent reviewer (a person or a fresh AI session with no context) to attack it, then record what they found.

## Step 8 — Know your code for the interview (2 hours)

You will be asked to explain and then *change* something live. Be able to do these cold:
* **Where is the decision made when someone downloads a file?** `routes_docs.py::download` is wrapped by `@doc_route("download")` → `web.py::doc_route` → `authz.authorize()`. If the `authorize` call is removed, the handler never gets a document row. `mutation_check.py` mutation 10 demonstrates exactly this.
* **How do revokes work immediately?** No tokens or caches; each request re-reads user, session and grants.
* **What stops the audit trail being altered?** triggers + HMAC chain with a key outside the DB + off-box anchors; and what they *don't* stop.
* **Why SQLite and one worker?** The decision, the action and the audit write are one `BEGIN IMMEDIATE` transaction.
* **Why can't admins read documents?** Separation of duties; cost = orphaned documents, no break-glass.
* **Practice a change:** e.g. add a new right "comment" between read and edit (edit `RANK`, `ACTION_NEEDS`, the CHECK constraint, and tests), or make grants expire by default after 90 days. Run `pytest` after.

## Step 9 — Known gaps you may choose to close (optional, in priority order)

| Gap | Effort | Why it matters |
|---|---|---|
| MFA/SSO (TOTP) | 1 day | Passwords-only is the weakest authentication point |
| Master-key rotation tool (re-wrap per-file keys) | 3 h | Needed to survive a key leak without re-uploading |
| General API rate limit | 2 h | Only login is throttled today |
| Owner-recovery ("break-glass" with two admins) | 1 day | Admins can't touch documents, so leavers orphan them |
| Malware scan (ClamAV) on upload | 3 h | Files are validated by type only |
| Browser tests (Playwright) for the UI | 3 h | UI was driven by hand once |

Put the ones you *don't* do in the write-up as "known, deliberately left".

## Step 10 — Final submission checklist

- [ ] Public GitHub repo, history across days
- [ ] Live URL in README; demo credentials work for each role
- [ ] `README.md`, `THREATS.md`, `PROMPTS.md` (≥5 dated entries, ≥2 on authz/audit, links to commits), `docs/API.md`, `docs/WRITEUP.md`
- [ ] Schema is in `trustvault/db.py`; setup is in README → Deploy (works from a clean clone: try it in a fresh folder)
- [ ] Tests pass: `pytest`; `python scripts/mutation_check.py` → 0 survived
- [ ] Anchoring configured and `audit-verify` exits 0 on the live system
- [ ] 5-minute video linked
- [ ] No real secrets in git (`git log -p | grep -i "master_key="` shows nothing real)

## Things you must be honest about (don't hide these)

Not built: MFA, external sharing, malware scanning, key rotation, break-glass, groups/folders. Records newer than the last anchor and copies already downloaded cannot be protected. The commit history reflects a short build until you keep working. All of this is already written in `THREATS.md` §G and `docs/WRITEUP.md`; keep them in sync with what you actually do.
