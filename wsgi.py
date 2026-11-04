"""Production entrypoint:  gunicorn --workers 1 --threads 8 wsgi:app

SQLite allows one writer at a time and every security decision here relies on
BEGIN IMMEDIATE, so run ONE worker process (threads are fine).

TRUSTVAULT_SEED_DEMO=1 loads the public demo accounts when - and only when -
the database has no users. Never set it on a deployment holding real data.
"""
import os

from trustvault import create_app
from trustvault.db import connect
from trustvault.seed import seed

app = create_app()

if os.environ.get("TRUSTVAULT_SEED_DEMO") == "1":
    _cfg = app.config["TV"]
    _db = connect(_cfg.db_path)
    try:
        empty = _db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None
    finally:
        _db.close()
    if empty:
        seed(_cfg)
