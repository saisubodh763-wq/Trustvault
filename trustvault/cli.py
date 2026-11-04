"""Operator commands: `flask --app trustvault create-admin|seed-demo|purge|audit-verify|audit-head`."""
from __future__ import annotations

import getpass
import os
import uuid
from datetime import timedelta

import click

from . import audit, clock, storage
from .db import connect, tx
from .security import hash_password, password_problem


def register(app):
    cfg = app.config["TV"]

    @app.cli.command("create-admin")
    @click.argument("email")
    @click.option("--name", default="Administrator")
    def create_admin(email, name):
        """Create the first administrator (password from TRUSTVAULT_ADMIN_PASSWORD or a prompt)."""
        password = os.environ.get("TRUSTVAULT_ADMIN_PASSWORD") or getpass.getpass("Password: ")
        problem = password_problem(password, email)
        if problem:
            raise click.ClickException(problem)
        db = connect(cfg.db_path)
        with tx(db):
            uid = str(uuid.uuid4())
            db.execute("INSERT INTO users (id,email,name,role,pw_hash,created_at)"
                       " VALUES (?,?,?,'admin',?,?)",
                       (uid, email.lower(), name, hash_password(password), clock.now()))
            audit.append(db, cfg, actor=None, actor_email="cli", action="user.create",
                         outcome="allowed", target_user_id=uid,
                         detail={"email": email.lower(), "role": "admin", "via": "cli"})
        click.echo(f"administrator {email} created")

    @app.cli.command("seed-demo")
    def seed_demo():
        """Load demo users and documents. NEVER run this on a real deployment."""
        from .seed import seed
        seed(cfg)
        click.echo("demo data loaded (see README for the demo accounts)")

    @app.cli.command("purge")
    @click.option("--days", default=None, type=int)
    def purge(days):
        """Permanently destroy documents deleted more than N days ago (blob + key)."""
        days = cfg.purge_after_days if days is None else days
        cutoff = clock.fmt(clock.now_dt() - timedelta(days=days))
        db = connect(cfg.db_path)
        docs = db.execute("SELECT id FROM documents WHERE deleted_at IS NOT NULL AND"
                          " purged_at IS NULL AND deleted_at <= ?", (cutoff,)).fetchall()
        for d in docs:
            versions = db.execute("SELECT blob_id FROM versions WHERE document_id=? AND blob_id"
                                  " IS NOT NULL", (d["id"],)).fetchall()
            with tx(db):
                db.execute("UPDATE versions SET blob_id=NULL, wrapped_key=NULL WHERE document_id=?",
                           (d["id"],))
                db.execute("DELETE FROM grants WHERE document_id=?", (d["id"],))
                db.execute("UPDATE documents SET purged_at=? WHERE id=?", (clock.now(), d["id"]))
                audit.append(db, cfg, actor=None, actor_email="system", action="document.purge",
                             outcome="allowed", doc_id=d["id"], detail={"versions": len(versions)})
            for v in versions:                     # delete files only after the DB commit
                storage.remove(cfg, v["blob_id"])
        click.echo(f"purged {len(docs)} document(s)")

    @app.cli.command("audit-verify")
    def audit_verify():
        """Verify the audit chain AND any off-box anchors; non-zero exit if either fails."""
        db = connect(cfg.db_path)
        result = audit.verify(db, cfg)
        anchors = audit.verify_anchors(db, cfg)
        click.echo({"chain": result, "anchors": anchors})
        raise SystemExit(0 if result["ok"] and anchors["ok"] is not False else 2)

    @app.cli.command("audit-anchor")
    def audit_anchor():
        """Append a signed chain-head anchor to TRUSTVAULT_ANCHOR_FILE and print it.
        Run from cron (e.g. every 15 min) and ship the line off the box too."""
        try:
            line = audit.write_anchor(connect(cfg.db_path), cfg)
        except RuntimeError as exc:
            raise click.ClickException(str(exc))
        click.echo(line)

    @app.cli.command("audit-head")
    def audit_head():
        """Print the current chain head. Store it somewhere the app cannot write."""
        click.echo(audit.head(connect(cfg.db_path)))
