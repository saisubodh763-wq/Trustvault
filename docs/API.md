# API reference

Base path `/api`. JSON in/out except uploads (`multipart/form-data`) and downloads (raw bytes).
Authentication is a session cookie (`tv_session`, HttpOnly, SameSite=Strict, Secure in production).
Every **POST/PATCH/DELETE** must also send `X-CSRF-Token` (returned by `/auth/login` and `/auth/me`), and any `Origin` header must match the host.

**Who may call** — roles: `admin`, `owner`, `viewer`. "Document right" is decided per request by `authz.authorize()`:
`read < edit < owner`. A document's owner has `owner`; anyone else needs an unexpired grant (viewers are capped at `read`); **admins have no document rights**.

**Status codes.** `401` not signed in · `403` signed in but not allowed (wrong role, or you can read the document but lack the needed right) · `404` the document does not exist **or you hold no right to it** (deliberately indistinguishable) · `409` conflict · `413` too large · `422` validation · `429` throttled. Every `403/404` on a document is written to the audit trail.

## Public

| Method & path | Who | Notes |
|---|---|---|
| `GET /healthz` | anyone | liveness |
| `GET /`, `GET /ui/*` | anyone | the single-page UI (static files only) |
| `POST /api/auth/login` | anyone | `{email,password}` → sets cookie, returns `{user,csrf}`. Generic failure message; 5 failures locks the account 15 min; per-IP throttle |

## Session

| Method & path | Who | Notes |
|---|---|---|
| `GET /api/auth/me` | any signed-in user | also usable while a password change is pending |
| `POST /api/auth/logout` | any signed-in user | revokes the session server-side |
| `POST /api/auth/change-password` | any signed-in user | `{current,new}`; ends all *other* sessions; required before anything else when `must_change_pw` |

## Documents

| Method & path | Who | Notes |
|---|---|---|
| `POST /api/documents` | role `owner` | multipart: `file`, optional `name`, `category`, `description`. Validated by extension + signature; ≤ 20 MB; per-owner quota. New docs are private to the uploader. Audited |
| `GET /api/documents` | any signed-in user | **only documents the caller may read.** Query: `q` (name), `owner` (email/name), `category`, `from`/`to` (YYYY-MM-DD), `limit` (≤100), `offset` |
| `GET /api/categories` | any signed-in user | categories among readable documents only |
| `GET /api/trash` | role `owner` | the caller's own deleted documents |
| `GET /api/documents/{id}` | doc right ≥ `read` | metadata + version list |
| `PATCH /api/documents/{id}` | doc right ≥ `edit` | only `name`, `category`, `description`; any other key → 400. Audited with before/after |
| `GET /api/documents/{id}/download?version=N` | doc right ≥ `read` | audit record is written first; if it fails, no bytes are sent. `attachment`, `nosniff`, sandbox CSP |
| `POST /api/documents/{id}/versions` | doc right ≥ `edit` | multipart `file`; adds a version |
| `DELETE /api/documents/{id}` | doc right = `owner` | soft delete; invisible to everyone else immediately |
| `POST /api/documents/{id}/restore` | doc right = `owner` | only while deleted and not purged |
| `GET /api/documents/{id}/audit` | doc right = `owner` | last 200 events for this document, including refused attempts |

## Sharing (owner of the document only)

| Method & path | Who | Notes |
|---|---|---|
| `GET /api/documents/{id}/grants` | `owner` | who has access, level, expiry, who granted |
| `POST /api/documents/{id}/grants` | `owner` | `{email, level: read\|edit, expires_at?, suggestion_id?}`. Cannot target admins; viewers get `read` only; expiry must be future and ≤ 1 year. Re-posting changes the level (audited with previous level) |
| `DELETE /api/documents/{id}/grants/{user_id}` | `owner` | effective on the very next request |
| `POST /api/documents/{id}/suggestions` | `owner` | rule-based suggestions (read only). **Grants nothing.** Audited |
| `POST /api/documents/{id}/suggestions/{sid}/dismiss` | `owner` | audited |

## Administration (role `admin` only; others get 403 and a `route.denied` audit record)

| Method & path | Notes |
|---|---|
| `GET /api/admin/users` | |
| `POST /api/admin/users` | `{email,name,role}` → one-time temporary password; user must change it |
| `PATCH /api/admin/users/{id}` | `{role?, active?}` only. Can't change yourself; can't demote an owner who owns documents. Revokes the user's sessions |
| `POST /api/admin/users/{id}/reset-password` | one-time temporary password; revokes sessions; locks the account to "change password" |
| `POST /api/admin/users/{id}/revoke-sessions` | |
| `GET /api/admin/documents` | **metadata only** (name, category, owner, share count, download count, refused count). No content, no download |
| `GET /api/admin/audit` | filters: `actor`, `action`, `outcome`, `doc_id`, `actor_id`, `target_user_id`, `from`, `to`, `limit` ≤ 500, `offset` |
| `GET /api/admin/audit/verify` | recomputes the HMAC chain; reports the first bad record |
| `GET /api/admin/alerts` | audit-chain failure, repeated refusals, bulk downloads, failed logins, admin password resets, edit grants |

## Audit event names

`auth.login`, `auth.logout`, `auth.lockout`, `auth.password_change`, `route.denied`, `document.upload|update|version|download|delete|restore|purge|access_denied`, `grant.add|change|revoke`, `suggestion.generated|dismissed`, `user.create|update|disable|password_reset`, `session.revoke`. Each record: time, actor, action, **outcome (`allowed`/`denied`)**, document, target user, detail JSON, IP, hash-chain fields.
