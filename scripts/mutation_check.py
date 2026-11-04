#!/usr/bin/env python3
"""Does the test suite actually test authorisation?

Takes ONE authorisation check out of the code at a time, runs the tests, and
requires the suite to FAIL. A mutation that leaves the suite green means a
check nobody is testing. Exit status is non-zero if any mutation survives.

    python scripts/mutation_check.py
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (file, original text, replacement, what it removes)
MUTATIONS = [
    ("trustvault/authz.py",
     "    if RANK[level] < RANK[needed]:\n        return Decision(False, \"insufficient_level\", level=level, can_read=True), None",
     "    if False:\n        return Decision(False, \"insufficient_level\", level=level, can_read=True), None",
     "level check: read-only users can edit/share/delete"),
    ("trustvault/authz.py",
     "    if level is None:\n        return Decision(False, \"no_access\"), None",
     "    if False:\n        return Decision(False, \"no_access\"), None",
     "no-access check: anyone can open any document"),
    ("trustvault/authz.py",
     "    if user[\"role\"] == \"admin\":\n        return None\n    if user[\"role\"] == \"owner\" and",
     "    if user[\"role\"] == \"owner\" and",
     "admin has no content rights"),
    ("trustvault/authz.py",
     "    if user[\"role\"] == \"viewer\":\n        level = \"read\"                       # role cap",
     "    if False:\n        level = \"read\"",
     "viewer role cap"),
    ("trustvault/authz.py",
     " AND (expires_at IS NULL OR expires_at > ?)\",\n        (doc[\"id\"], user[\"id\"], clock.now()),",
     "\",\n        (doc[\"id\"], user[\"id\"]),",
     "grant expiry in authorize()"),
    ("trustvault/authz.py",
     "        if level != \"owner\":\n            return Decision(False, \"deleted\"), None",
     "        if False:\n            return Decision(False, \"deleted\"), None",
     "deleted documents hidden from non-owners"),
    ("trustvault/authz.py",
     "    if not user[\"active\"] or user[\"must_change_pw\"]:\n        return None",
     "    if False:\n        return None",
     "inactive / must-change-password users get no rights"),
    ("trustvault/authz.py",
     "    if not user[\"active\"] or user[\"must_change_pw\"] or user[\"role\"] == \"admin\":\n        return \"0\", []",
     "    if False:\n        return \"0\", []",
     "list/search: admin & inactive filter"),
    ("trustvault/authz.py",
     "        return f\"(d.owner_id = ? OR {grant})\", [user[\"id\"], user[\"id\"], clock.now()]\n    return grant, [user[\"id\"], clock.now()]",
     "        return \"1\", []\n    return \"1\", []",
     "list/search: only my documents"),
    ("trustvault/web.py",
     "            doc_id = kwargs.pop(\"doc_id\")\n            user = authenticate()",
     "            doc_id = kwargs.pop(\"doc_id\")\n            user = authenticate()\n            return fn(get_db().execute(\"SELECT * FROM documents WHERE id=?\", (doc_id,)).fetchone(), *args, **kwargs)",
     "document guard bypassed entirely"),
    ("trustvault/web.py",
     "            if role and user[\"role\"] != role:",
     "            if False:",
     "role check on admin/owner routes"),
    ("trustvault/web.py",
     "        if getattr(fn, \"_auth\", None) not in (\"public\", \"user\", \"admin\", \"doc\"):\n            raise ApiError(403, \"forbidden\")",
     "        pass",
     "default-deny for unguarded routes"),
    ("trustvault/web.py",
     "        if not hmac.compare_digest(sent, sess[\"csrf\"]):\n            raise ApiError(403, \"missing or invalid CSRF token\")",
     "        if False:\n            raise ApiError(403, \"missing or invalid CSRF token\")",
     "CSRF check"),
    ("trustvault/web.py",
     "    if user is None or not user[\"active\"]:\n        raise ApiError(401, \"authentication required\")",
     "    if user is None:\n        raise ApiError(401, \"authentication required\")",
     "disabled users' sessions stop working"),
    ("trustvault/web.py",
     "    sess = db.execute(\"SELECT * FROM sessions WHERE id = ? AND revoked_at IS NULL\",",
     "    sess = db.execute(\"SELECT * FROM sessions WHERE id = ? AND (revoked_at IS NULL OR 1)\",",
     "revoked sessions rejected"),
    ("trustvault/routes_docs.py",
     "    audit.append(db, cfg(), actor=g.user, action=\"document.download\"",
     "    (lambda *a, **k: None)(db, cfg(), actor=g.user, action=\"document.download\"",
     "download audit record"),
    ("trustvault/routes_docs.py",
     "    unknown = set(body) - allowed\n    if unknown:\n        raise ApiError(400, f\"cannot change: {', '.join(sorted(unknown))}\")",
     "    unknown = set()",
     "mass-assignment guard on PATCH document"),
    ("trustvault/routes_docs.py",
     "    if target[\"role\"] == \"admin\":\n        raise ApiError(422, \"administrator accounts cannot be given document access\")",
     "    if False:\n        raise ApiError(422, \"x\")",
     "cannot grant admins access"),
    ("trustvault/routes_admin.py",
     "    revoked = _revoke_sessions(db, target[\"id\"])      # takes effect on the very next request",
     "    revoked = 0",
     "session revocation on disable/demote"),
    ("trustvault/audit.py",
     "        elif row[\"prev_hash\"] != prev:",
     "        elif False:",
     "audit chain link verification"),
    ("trustvault/storage.py",
     "    aad = _aad(doc_id, version, blob_id)\n    try:",
     "    aad = b\"\"\n    try:",
     "blob/document binding (AAD) on read"),
]


def run_tests(workdir: Path) -> bool:
    r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                       cwd=workdir, capture_output=True, text=True)
    return r.returncode == 0


def main() -> int:
    survivors, errors = [], []
    for i, (rel, old, new, what) in enumerate(MUTATIONS, 1):
        tmp = Path(tempfile.mkdtemp(prefix="tv_mut_"))
        try:
            shutil.copytree(ROOT, tmp / "p", ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "data", ".pytest_cache", ".mutation_tmp"))
            target = tmp / "p" / rel
            text = target.read_text()
            if text.count(old) != 1:
                errors.append((what, f"pattern matched {text.count(old)} times in {rel}"))
                print(f"[{i:02}/{len(MUTATIONS)}] ERROR    {what}")
                continue
            target.write_text(text.replace(old, new))
            passed = run_tests(tmp / "p")
            print(f"[{i:02}/{len(MUTATIONS)}] {'SURVIVED' if passed else 'killed  '} {what}")
            if passed:
                survivors.append(what)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(MUTATIONS) - len(survivors) - len(errors)} killed, "
          f"{len(survivors)} survived, {len(errors)} could not be applied")
    for what in survivors:
        print("  UNTESTED CHECK:", what)
    for what, why in errors:
        print("  BAD MUTATION  :", what, "-", why)
    return 1 if survivors or errors else 0


if __name__ == "__main__":
    sys.exit(main())
