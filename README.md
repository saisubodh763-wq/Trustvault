# TrustVault

A document platform where the wrong person cannot reach a file, and where you can prove exactly who reached it, including the attempts that were refused.

Flask + SQLite + AES‑256‑GCM encrypted blobs + a vanilla‑JS single-page UI (no inline scripts, no `innerHTML`).
Why this stack: one process, one database file, and one `BEGIN IMMEDIATE` transaction per request means **"is this allowed → do it → record it" is a single atomic unit**. That is the property the whole design leans on, and it is easy to demonstrate. The cost (single writer, no scale‑out) is in `THREATS.md`.

> **Live URL:** https://trustvault-8v9l.onrender.com
> **Repository:** https://github.com/saisubodh763-wq/trustvault

## Demo accounts (seed data — public, demo only)

All use the password `Demo-Passw0rd-2026`.

| Role | Login | What to try |
|---|---|---|
| Administrator | `admin@trustvault.test` | Alerts, audit trail + chain verification, user management. Note: **cannot open any document** |
| Owner | `alice@trustvault.test` | Owns "Salary letters 2026" and "Customer contract – Acme"; has *edit* on Bob's drawings |
| Owner | `bob@trustvault.test` | Owns "Drawings – partner pack" and "Audit papers FY26" |
| Viewer | `carol@trustvault.test` | Read access to Acme contract and Audit papers only |
| Viewer | `dave@trustvault.test` | Has been given nothing. Try to find anything |

## Roles (what each can do)

| | Admin | Owner | Viewer |
|---|---|---|---|
| Upload / delete / restore own documents | – | ✔ | – |
| Grant & revoke read/edit on own documents | – | ✔ | – |
| Read / download documents granted to them | – | ✔ | ✔ (read only) |
| Edit documents granted *edit* | – | ✔ | – (capped at read) |
| See who touched their document (incl. refusals) | – | ✔ (own docs) | – |
| Manage users, reset passwords, end sessions | ✔ | – | – |
| See all activity, alerts, refused attempts, verify the audit chain | ✔ | – | – |
| **Read any document content** | **never** | only own/granted | only granted |

## Permission model in my own words

* Every document has exactly one **owner**. New documents are private.
* The owner gives **named people** either `read` or `edit` on that **one document**. There are no folders or groups, because inheritance is how "access to a folder so they can see one file" turns into forty files. Per‑document grants are verbose but never surprising.
* Rights are ordered `read < edit < owner`. Only the owner can share, un‑share, delete or restore.
* A grant may carry an expiry, evaluated at read time.
* **Roles cap rights at decision time**: a viewer never exceeds `read`, whatever rows say.
* **Administrators have no content rights.** They run the system and watch the audit trail; they cannot read, download, edit or be granted a document.
* One function, `trustvault/authz.py::authorize()`, makes every decision. List/search use a SQL form of the same rule and a test proves the two agree.

## What "taking access away immediately" means here

Nothing is cached and nothing is pre‑signed. The cookie is an opaque random token (only its hash is stored). Each request re‑reads the user, session and grant in the same transaction as the action. Revoke → the very next request is refused. Cost: a couple of indexed reads per request. What can't be undone: bytes someone already downloaded (the audit trail tells you precisely what they took).

## How the audit trail is protected

Append‑only rows, hash‑chained with HMAC‑SHA256 under a key that is **not in the database**; SQLite triggers refuse UPDATE/DELETE; `/api/admin/audit/verify` recomputes the chain and the admin dashboard raises a critical alert if it fails. The audit row for a download is written *before* the bytes are read, in the same transaction — no record, no bytes. **Anchors** defend against someone deleting the newest records: `flask --app wsgi audit-anchor` (run it from cron every few minutes) appends a signed head hash to `TRUSTVAULT_ANCHOR_FILE`, kept *outside* the data volume; `audit-verify` and the admin alerts fail if any anchored record is missing or changed. Still not defended: records newer than the last anchor, and an attacker who controls both the database and the anchor store. See `THREATS.md`.

## Run locally

```bash
pip install -r requirements-dev.txt
export TRUSTVAULT_ENV=development          # auto-generates dev keys under ./data (never use in production)
flask --app trustvault seed-demo           # loads the demo accounts above
flask --app trustvault run                 # http://127.0.0.1:5000
```

## Tests

```bash
pytest                                     # 197 tests (isolation matrix, revocation, audit tamper, uploads, authn, features)
python scripts/mutation_check.py           # removes 23 authorisation checks one at a time; every one must make the suite fail
```

`tests/test_isolation.py` runs every user against every document and every action, with expected results written by hand. `scripts/mutation_check.py` is the answer to "what if one check is removed?" — currently 25/25 killed. Two checks survived on the first run (of 21 then); the tests for them were added (see `PROMPTS.md`).

## Deploy (from a clean clone)

Any host that runs a container with a **persistent volume** works. SQLite and the blob store live in `/data`.

```bash
docker build -t trustvault .
export TRUSTVAULT_MASTER_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export TRUSTVAULT_AUDIT_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")   # must differ
docker run -d -p 8000:8000 -v tv-data:/data \
  -e TRUSTVAULT_MASTER_KEY -e TRUSTVAULT_AUDIT_KEY \
  -e TRUSTVAULT_PROXY_HOPS=1 \
  -e TRUSTVAULT_SEED_DEMO=1 \
  trustvault
```

* **Put it behind HTTPS.** Cookies are `Secure` in production, so plain HTTP will not log in.
* `TRUSTVAULT_PROXY_HOPS` = number of trusted proxies in front. Wrong values let clients spoof the IP written to the audit log.
* **Keep the two keys out of the data volume and out of git.** Lose the master key → files are unrecoverable. Lose the audit key → the chain can't be verified.
* Run **one** gunicorn worker (the Dockerfile does). SQLite is a single‑writer store.
* **Real (non-demo) first admin:** omit `TRUSTVAULT_SEED_DEMO`, then
  `docker exec -e TRUSTVAULT_ADMIN_PASSWORD='…' <container> flask --app wsgi create-admin you@company.com`.
* Operations: `flask --app wsgi purge` (destroy documents deleted > 30 days ago, blob + key), `audit-verify` (checks the chain **and** the anchors; non-zero exit if either fails), `audit-anchor` (append a signed chain-head line to `TRUSTVAULT_ANCHOR_FILE`; **schedule it every few minutes**, e.g. `*/5 * * * * docker exec <container> flask --app wsgi audit-anchor`, and keep the file outside the data volume or ship each line off the box).
* `render.yaml` is a Render blueprint (Docker, 1 GB disk, health check `/healthz`); set the two keys in the dashboard.

## Layout

```
trustvault/authz.py       THE authorisation decision (+ SQL form for lists)
trustvault/web.py         authentication, CSRF, default-deny hook, doc_route / authed guards
trustvault/audit.py       HMAC-chained append-only trail + verify
trustvault/storage.py     AES-256-GCM envelope encryption, AAD-bound blobs
trustvault/validation.py  upload + filename + metadata validation
trustvault/routes_*.py    auth / documents+sharing / admin
trustvault/suggest.py     sharing suggestions (advice only, never grants)
tests/  scripts/mutation_check.py  THREATS.md  PROMPTS.md  docs/API.md  docs/WRITEUP.md
```

Docs: [`THREATS.md`](THREATS.md) · [`PROMPTS.md`](PROMPTS.md) · [`docs/API.md`](docs/API.md) · [`docs/WRITEUP.md`](docs/WRITEUP.md)

## Known gaps (deliberately left)

Details in THREATS.md section G.

- Authentication is passwords only: no MFA/SSO.
- No malware scanning; files are checked by type and size only.
- No master-key rotation tool (per-file wrapped keys make it possible, I did not build it).
- No break-glass recovery: admins cannot read documents by design, so a leaver's documents are orphaned.
- Uploads over the size limit get HTTP 413 before the audit write, so they are not audited.
- Audit anchoring on Render is manual (the anchor file is lost on restart).
- Rate limiting covers login only.
- No browser (UI) tests; the UI was tested by hand.
- One file-permission test fails on Windows only (NTFS has no POSIX modes); it passes on Linux.