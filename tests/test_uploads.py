"""Upload validation and storage: what is accepted, how it is named, and why a
stolen disk or a swapped file does not leak anything."""
import io
import os
import zipfile
from pathlib import Path

import pytest

from conftest import ACME, Api, build_app, doc_ids, raw_db

PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 20


def make_zip(entries: dict, compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


DOCX = make_zip({"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>"})
XLSX = make_zip({"[Content_Types].xml": "<x/>", "xl/workbook.xml": "<w/>"})


@pytest.mark.parametrize("name,content", [
    ("a.pdf", PDF), ("a.png", PNG), ("a.jpg", JPG), ("a.jpeg", JPG), ("a.txt", b"hello"),
    ("a.csv", b"a,b\n1,2\n"), ("a.docx", DOCX), ("a.xlsx", XLSX),
    ("a.pptx", make_zip({"[Content_Types].xml": "<x/>", "ppt/presentation.xml": "<p/>"})),
])
def test_legitimate_files_are_accepted(app, name, content):
    r = Api(app, "alice").upload(name, content, category="Reports")
    assert r.status_code == 201, r.get_data(as_text=True)


@pytest.mark.parametrize("name,content,why", [
    ("evil.exe", b"MZ\x90\x00", "executable"),
    ("page.html", b"<script>alert(1)</script>", "html"),
    ("pic.svg", b"<svg onload=alert(1)/>", "svg"),
    ("macro.docm", DOCX, "macro-enabled extension"),
    ("script.js", b"alert(1)", "javascript"),
    ("noext", b"hello", "no extension"),
    ("trailing.", b"hello", "trailing dot"),
    ("fake.pdf", b"<html>not a pdf</html>", "magic mismatch pdf"),
    ("fake.png", PDF, "magic mismatch png"),
    ("fake.jpg", PNG, "magic mismatch jpg"),
    ("fake.txt", b"abc\x00def", "binary in text"),
    ("fake.txt", b"\xff\xfe\xfd", "invalid utf-8"),
    ("fake.docx", b"not a zip", "docx not a zip"),
    ("fake.docx", make_zip({"hello.txt": "x"}), "zip without content types"),
    ("fake.docx", XLSX, "xlsx content under docx name"),
    ("empty.txt", b"", "empty"),
    ("macro.docx", make_zip({"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>",
                             "word/vbaProject.bin": "x"}), "macros inside"),
    ("slip.docx", make_zip({"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>",
                            "../../evil": "x"}), "zip path traversal"),
])
def test_dangerous_or_mislabelled_files_are_refused(app, name, content, why):
    r = Api(app, "alice").upload(name, content)
    assert r.status_code == 422, (why, r.status_code, r.get_data(as_text=True))
    assert raw_db(app).execute("SELECT COUNT(*) c FROM documents").fetchone()["c"] == 4


def test_decompression_bomb_is_refused(app):
    bomb = make_zip({"[Content_Types].xml": "<x/>", "word/document.xml": "0" * 30_000_000})
    assert len(bomb) < 1_000_000                       # tiny on the wire, huge when expanded
    assert Api(app, "alice").upload("bomb.docx", bomb).status_code == 422


def test_oversized_upload_is_refused_before_it_is_stored(tmp_path):
    app = build_app(tmp_path, max_upload_bytes=2000)
    alice = Api(app, "alice")
    assert alice.upload("ok.txt", b"x" * 1999).status_code == 201
    assert alice.upload("big.txt", b"x" * 5000).status_code == 413          # over the file limit
    assert alice.upload("huge.txt", b"x" * 300_000).status_code == 413      # over the transport cap
    assert raw_db(app).execute("SELECT COUNT(*) c FROM documents").fetchone()["c"] == 5


def test_storage_quota_per_owner(tmp_path):
    app = build_app(tmp_path, owner_quota_bytes=300)
    alice = Api(app, "alice")
    assert alice.upload("a.txt", b"x" * 100).status_code in (201, 413)
    assert alice.upload("b.txt", b"y" * 5000).status_code == 413


def test_viewers_and_admins_cannot_upload(app):
    for who in ("carol", "dave", "admin"):
        assert Api(app, who).upload("a.txt", b"x").status_code == 403, who
    assert Api(app).upload("a.txt", b"x").status_code == 401


def test_clean_filename_handles_both_path_separators_directly():
    from trustvault.validation import clean_filename
    assert clean_filename("..\\..\\windows\\system32\\x.txt") == "x.txt"
    assert clean_filename("a/b\\c/d.txt") == "d.txt"


@pytest.mark.parametrize("hostile,expected", [
    ("../../etc/passwd.txt", "passwd.txt"),
    ("..\\..\\windows\\system32\\x.txt", None),      # HTTP layer unescapes backslashes first
    ("/abs/path/report.txt", "report.txt"),
    ("<img src=x onerror=alert(1)>.txt", "_img src_x onerror_alert(1)_.txt"),
    ("a\x00b.txt", "ab.txt"),
    ("..hidden.txt", "hidden.txt"),
    ("na‮me.txt", "name.txt"),
])
def test_filenames_are_sanitised_and_never_used_as_paths(app, hostile, expected):
    r = Api(app, "alice").upload(hostile, b"hello", name="")
    assert r.status_code == 201, r.get_data(as_text=True)
    alice = Api(app, "alice")
    doc = alice.get(f"/api/documents/{r.json['id']}").get_json()
    if expected is not None:
        assert doc["versions"][0]["original_filename"] == expected
    assert "/" not in doc["filename"] and "\\" not in doc["filename"] and ".." not in doc["filename"]


def test_metadata_fields_are_validated(app):
    alice = Api(app, "alice")
    assert alice.upload("a.txt", b"x", category="<script>").status_code == 422
    assert alice.upload("a.txt", b"x", category="a" * 80).status_code == 422
    assert alice.upload("a.txt", b"x", name="n" * 300).status_code == 422
    assert alice.upload("a.txt", b"x", description="d" * 2000).status_code == 422


def test_download_headers_prevent_in_browser_execution(app):
    alice = Api(app, "alice")
    r = alice.upload("report.pdf", PDF)
    d = alice.get(f"/api/documents/{r.json['id']}/download")
    assert d.status_code == 200 and d.data == PDF
    assert d.headers["Content-Disposition"].startswith("attachment;")
    assert d.headers["X-Content-Type-Options"] == "nosniff"
    assert d.headers["Content-Type"] == "application/pdf"
    assert "sandbox" in d.headers["Content-Security-Policy"]
    assert d.headers["Cache-Control"] == "no-store"


def test_server_ignores_the_content_type_the_client_claims(app):
    alice = Api(app, "alice")
    data = {"file": (io.BytesIO(b"plain text"), "note.txt", "text/html")}
    r = alice.post("/api/documents", data=data, content_type="multipart/form-data")
    d = alice.get(f"/api/documents/{r.json['id']}/download")
    assert d.headers["Content-Type"].startswith("text/plain")


def test_files_on_disk_are_ciphertext_with_opaque_names(app):
    secret = b"TOP-SECRET-MARKER-" + os.urandom(8).hex().encode()
    Api(app, "alice").upload("secret.txt", secret)
    blob_dir: Path = app.config["TV"].blob_dir
    files = [p for p in blob_dir.rglob("*") if p.is_file()]
    assert len(files) == 5
    for p in files:
        assert secret not in p.read_bytes()
        assert "secret" not in p.name and len(p.name) == 32
        assert (p.stat().st_mode & 0o077) == 0                       # owner-only permissions
    assert b"CONFIDENTIAL" not in b"".join(p.read_bytes() for p in files)


def test_a_blob_swapped_between_documents_does_not_leak_the_other(app):
    """An attacker with disk write access copies document A's ciphertext over B's."""
    db = raw_db(app)
    docs = doc_ids(app)
    a = db.execute("SELECT blob_id FROM versions WHERE document_id=?", (docs["Salary letters 2026"],)).fetchone()
    b = db.execute("SELECT blob_id FROM versions WHERE document_id=?", (docs[ACME],)).fetchone()
    root = app.config["TV"].blob_dir
    src = root / a["blob_id"][:2] / a["blob_id"]
    dst = root / b["blob_id"][:2] / b["blob_id"]
    dst.write_bytes(src.read_bytes())
    r = Api(app, "carol").get(f"/api/documents/{docs[ACME]}/download")
    assert r.status_code == 500
    assert b"Employee" not in r.data and b"salary" not in r.data.lower()


def test_a_flipped_bit_on_disk_is_detected(app):
    docs, db = doc_ids(app), raw_db(app)
    b = db.execute("SELECT blob_id FROM versions WHERE document_id=?", (docs[ACME],)).fetchone()
    p = app.config["TV"].blob_dir / b["blob_id"][:2] / b["blob_id"]
    raw = bytearray(p.read_bytes())
    raw[-1] ^= 1
    p.write_bytes(bytes(raw))
    assert Api(app, "carol").get(f"/api/documents/{docs[ACME]}/download").status_code == 500


def test_new_versions_keep_history_and_old_versions_stay_downloadable_to_the_authorised(app):
    alice, carol = Api(app, "alice"), Api(app, "carol")
    acme = doc_ids(app)[ACME]
    assert alice.upload("v2.txt", b"second", url=f"/api/documents/{acme}/versions").json["version"] == 2
    assert carol.get(f"/api/documents/{acme}/download").data == b"second"
    assert b"Acme" in carol.get(f"/api/documents/{acme}/download?version=1").data
    assert carol.get(f"/api/documents/{acme}/download?version=3").status_code == 404


def test_purge_destroys_blob_and_key_for_deleted_documents(app):
    from trustvault import clock
    from trustvault.cli import register  # noqa: F401  (commands are registered on the app)
    alice, acme, db = Api(app, "alice"), doc_ids(app)[ACME], raw_db(app)
    blob = db.execute("SELECT blob_id FROM versions WHERE document_id=?", (acme,)).fetchone()["blob_id"]
    alice.delete(f"/api/documents/{acme}")
    clock.advance(31 * 86400)
    result = app.test_cli_runner().invoke(args=["purge"])
    assert "purged 1" in result.output, result.output
    assert not (app.config["TV"].blob_dir / blob[:2] / blob).exists()
    row = db.execute("SELECT blob_id, wrapped_key FROM versions WHERE document_id=?", (acme,)).fetchone()
    assert row["blob_id"] is None and row["wrapped_key"] is None
    alice = Api(app, "alice")                       # old session expired during the 31 days
    assert alice.post(f"/api/documents/{acme}/restore").status_code == 404      # gone for good
    assert Api(app, "carol").get(f"/api/documents/{acme}/download").status_code == 404
