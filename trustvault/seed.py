"""Demo data. The passwords below are public (they are in the README) and exist
only so a reviewer can log in. Never seed a deployment that holds real data."""
from __future__ import annotations

import hashlib
import uuid

from . import audit, clock, storage
from .config import Config
from .db import connect, init_db, tx
from .security import hash_password

DEMO_PASSWORD = "Demo-Passw0rd-2026"
USERS = [
    ("admin@trustvault.test", "Ada Admin", "admin"),
    ("alice@trustvault.test", "Alice Owner (HR)", "owner"),
    ("bob@trustvault.test", "Bob Owner (Engineering)", "owner"),
    ("carol@trustvault.test", "Carol Viewer", "viewer"),
    ("dave@trustvault.test", "Dave Viewer", "viewer"),
]
# (owner, name, category, filename, content)
DOCS = [
    ("alice", "Salary letters 2026", "HR", "salary-letters-2026.txt",
     "CONFIDENTIAL - salary letters\nEmployee 001: 84,000\nEmployee 002: 91,500\n"),
    ("alice", "Customer contract - Acme", "Contracts", "acme-contract.txt",
     "CONFIDENTIAL - Acme customer contract. Term 24 months.\n"),
    ("bob", "Drawings - partner pack", "Engineering", "partner-drawings.txt",
     "CONFIDENTIAL - drawing index shared with external partner.\n"),
    ("bob", "Audit papers FY26", "Finance", "audit-papers.csv",
     "ledger,amount\nA-100,12000\nA-101,4500\n"),
]
# (doc name, grantee, level)
GRANTS = [
    ("Customer contract - Acme", "carol", "read"),
    ("Audit papers FY26", "carol", "read"),
    ("Drawings - partner pack", "alice", "edit"),
]


def seed(cfg: Config) -> None:
    init_db(cfg.db_path)
    db = connect(cfg.db_path)
    ids = {}
    with tx(db):
        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise RuntimeError("database is not empty; refusing to seed")
        for email, name, role in USERS:
            uid = str(uuid.uuid4())
            ids[email.split("@")[0]] = uid
            db.execute("INSERT INTO users (id,email,name,role,pw_hash,created_at) VALUES (?,?,?,?,?,?)",
                       (uid, email, name, role, hash_password(DEMO_PASSWORD), clock.now()))
            audit.append(db, cfg, actor=None, actor_email="seed", action="user.create",
                         outcome="allowed", target_user_id=uid, detail={"email": email, "role": role})
        docs = {}
        for owner, name, category, filename, content in DOCS:
            did, data = str(uuid.uuid4()), content.encode()
            owner_row = {"id": ids[owner], "email": f"{owner}@trustvault.test"}
            blob_id, wrapped = storage.put(cfg, data, did, 1)
            now = clock.now()
            db.execute("INSERT INTO documents (id,owner_id,name,category,description,created_at,"
                       "updated_at,current_version) VALUES (?,?,?,?,?,?,?,1)",
                       (did, ids[owner], name, category, "Demo document", now, now))
            mime = "text/csv; charset=utf-8" if filename.endswith(".csv") else "text/plain; charset=utf-8"
            sha = hashlib.sha256(data).hexdigest()
            db.execute("INSERT INTO versions (id,document_id,version,blob_id,wrapped_key,size,sha256,"
                       "mime,original_filename,uploaded_by,created_at) VALUES (?,?,1,?,?,?,?,?,?,?,?)",
                       (str(uuid.uuid4()), did, blob_id, wrapped, len(data), sha, mime, filename,
                        ids[owner], now))
            audit.append(db, cfg, actor=owner_row, action="document.upload", outcome="allowed",
                         doc_id=did, detail={"name": name, "category": category, "size": len(data),
                                             "sha256": sha, "version": 1})
            docs[name] = (did, owner)
        for doc_name, grantee, level in GRANTS:
            did, owner = docs[doc_name]
            db.execute("INSERT INTO grants (document_id,user_id,level,granted_by,created_at)"
                       " VALUES (?,?,?,?,?)", (did, ids[grantee], level, ids[owner], clock.now()))
            audit.append(db, cfg, actor={"id": ids[owner], "email": f"{owner}@trustvault.test"},
                         action="grant.add", outcome="allowed", doc_id=did,
                         target_user_id=ids[grantee],
                         detail={"level": level, "target": f"{grantee}@trustvault.test"})
    db.close()
