"""Upload validation: what is accepted, and what the file is *named*.

Never trusted from the client: the declared content type, the extension on its
own, and the filename as a path. The server decides the stored MIME type from a
fixed table after checking the file's real signature.
"""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile

ALLOWED = {
    # ext: (mime, kind)
    "pdf":  ("application/pdf", "pdf"),
    "png":  ("image/png", "png"),
    "jpg":  ("image/jpeg", "jpeg"),
    "jpeg": ("image/jpeg", "jpeg"),
    "txt":  ("text/plain; charset=utf-8", "text"),
    "csv":  ("text/csv; charset=utf-8", "text"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "ooxml:word/"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "ooxml:xl/"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "ooxml:ppt/"),
}
MAX_ZIP_ENTRIES = 5000
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024
MAX_ZIP_RATIO = 100
CATEGORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _\-/&.]{0,49}$")


class ValidationError(ValueError):
    pass


def clean_filename(raw: str) -> str:
    """Strip any path, control characters and odd Unicode; never empty."""
    name = unicodedata.normalize("NFKC", raw or "")
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable())
    name = re.sub(r"[^\w.\- ()]", "_", name, flags=re.UNICODE).strip(" .")
    if not name:
        raise ValidationError("file name is empty")
    return name[:120]


def validate_upload(raw_filename: str, data: bytes) -> tuple[str, str, str]:
    """Return (clean_filename, extension, mime) or raise ValidationError."""
    name = clean_filename(raw_filename)
    if "." not in name:
        raise ValidationError("file needs an extension")
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED:
        raise ValidationError(f"file type .{ext} is not allowed")
    if len(data) == 0:
        raise ValidationError("file is empty")
    mime, kind = ALLOWED[ext]
    if kind == "pdf":
        if not data.startswith(b"%PDF-"):
            raise ValidationError("content is not a PDF")
    elif kind == "png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValidationError("content is not a PNG")
    elif kind == "jpeg":
        if not data.startswith(b"\xff\xd8\xff"):
            raise ValidationError("content is not a JPEG")
    elif kind == "text":
        if b"\x00" in data:
            raise ValidationError("text file contains binary data")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError("text file is not valid UTF-8")
    elif kind.startswith("ooxml:"):
        _check_ooxml(data, kind.split(":", 1)[1])
    return name, ext, mime


def _check_ooxml(data: bytes, required_dir: str) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile:
        raise ValidationError("content is not a valid Office file")
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValidationError("archive has too many entries")
    names = [i.filename for i in infos]
    total = 0
    for i in infos:
        if i.filename.startswith("/") or ".." in i.filename.split("/"):
            raise ValidationError("archive contains unsafe paths")
        total += i.file_size
        if i.compress_size and i.file_size / i.compress_size > MAX_ZIP_RATIO and i.file_size > 1_000_000:
            raise ValidationError("archive compression ratio is suspicious")
    if total > MAX_ZIP_UNCOMPRESSED:
        raise ValidationError("archive expands too large")
    if "[Content_Types].xml" not in names:
        raise ValidationError("content is not an Office document")
    if not any(n.startswith(required_dir) for n in names):
        raise ValidationError("Office content does not match the file extension")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise ValidationError("macro-enabled content is not allowed")


def clean_text(value, field: str, max_len: int, required: bool = True) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    value = "".join(ch for ch in unicodedata.normalize("NFKC", value) if ch.isprintable() or ch == "\n").strip()
    if required and not value:
        raise ValidationError(f"{field} is required")
    if len(value) > max_len:
        raise ValidationError(f"{field} is too long (max {max_len})")
    return value


def clean_category(value) -> str:
    value = clean_text(value or "General", "category", 50)
    if not CATEGORY_RE.match(value):
        raise ValidationError("category may contain letters, digits, spaces and - _ / & .")
    return value
