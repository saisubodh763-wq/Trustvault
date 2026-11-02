import io
import os
import sqlite3

import pytest

from trustvault import clock, create_app
from trustvault.config import Config
from trustvault.db import connect
from trustvault.seed import DEMO_PASSWORD, seed

ALL_USERS = ["admin", "alice", "bob", "carol", "dave"]


def email(short: str) -> str:
    return f"{short}@trustvault.test"


class Api:
    """A browser-like client: its own cookie jar, sends the CSRF header."""

    def __init__(self, app, who: str | None = None):
        self.app = app
        self.c = app.test_client()
        self.csrf = None
        if who:
            r = self.login(who)
            assert r.status_code == 200, r.get_data(as_text=True)

    def login(self, who: str, password: str = DEMO_PASSWORD):
        addr = who if "@" in who else email(who)
        r = self.c.post("/api/auth/login", json={"email": addr, "password": password})
        if r.status_code == 200:
            self.csrf = r.json["csrf"]
        return r

    def _h(self):
        return {"X-CSRF-Token": self.csrf} if self.csrf else {}

    def get(self, url, **kw):
        return self.c.get(url, headers=self._h(), **kw)

    def post(self, url, **kw):
        return self.c.post(url, headers=self._h(), **kw)

    def patch(self, url, **kw):
        return self.c.patch(url, headers=self._h(), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(), **kw)

    def upload(self, filename: str, content: bytes, url="/api/documents", **form):
        data = {"file": (io.BytesIO(content), filename)}
        data.update(form)
        return self.post(url, data=data, content_type="multipart/form-data")


def build_app(tmp_path, **overrides):
    clock.reset()
    cfg = Config(data_dir=tmp_path, master_key=os.urandom(32), audit_key=os.urandom(32),
                 secure_cookies=False, testing=True, **overrides)
    app = create_app(cfg)
    seed(cfg)
    return app


@pytest.fixture
def app(tmp_path):
    yield build_app(tmp_path)
    clock.reset()


@pytest.fixture(scope="module")
def shared_app(tmp_path_factory):
    app = build_app(tmp_path_factory.mktemp("shared"))
    yield app
    clock.reset()


def raw_db(app) -> sqlite3.Connection:
    return connect(app.config["TV"].db_path)


def doc_ids(app) -> dict:
    db = raw_db(app)
    try:
        return {r["name"]: r["id"] for r in db.execute("SELECT id, name FROM documents")}
    finally:
        db.close()


def user_ids(app) -> dict:
    db = raw_db(app)
    try:
        return {r["email"].split("@")[0]: r["id"] for r in db.execute("SELECT id, email FROM users")}
    finally:
        db.close()


def audit_rows(app, **where):
    db = raw_db(app)
    try:
        sql = "SELECT * FROM audit_log"
        if where:
            sql += " WHERE " + " AND ".join(f"{k}=?" for k in where)
        return [dict(r) for r in db.execute(sql + " ORDER BY seq", list(where.values()))]
    finally:
        db.close()


SALARY, ACME, DRAWINGS, AUDITP = ("Salary letters 2026", "Customer contract - Acme",
                                  "Drawings - partner pack", "Audit papers FY26")
