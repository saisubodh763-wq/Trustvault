"""Runtime configuration.

Secrets come from the environment, never from the repository. Two independent
32-byte keys are used:

* TRUSTVAULT_MASTER_KEY - wraps the per-file data keys (envelope encryption).
* TRUSTVAULT_AUDIT_KEY  - HMAC key for the audit hash chain.

They are separate on purpose: leaking one must not let an attacker forge the
other. In production both are mandatory; the app refuses to start without them.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    data_dir: Path
    master_key: bytes
    audit_key: bytes
    secure_cookies: bool = True
    max_upload_bytes: int = 20 * 1024 * 1024
    owner_quota_bytes: int = 500 * 1024 * 1024
    session_absolute_hours: int = 8
    session_idle_minutes: int = 60
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    ip_failure_limit: int = 30          # failed logins per IP per 10 minutes
    proxy_hops: int = 0                 # trusted reverse proxies in front of us
    purge_after_days: int = 30
    testing: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "trustvault.db"

    @property
    def blob_dir(self) -> Path:
        return self.data_dir / "blobs"

    def validate(self) -> None:
        if len(self.master_key) != 32 or len(self.audit_key) != 32:
            raise RuntimeError("master and audit keys must each be 32 bytes")
        if self.master_key == self.audit_key:
            raise RuntimeError("master key and audit key must differ")


def _load_key(name: str, data_dir: Path, production: bool) -> bytes:
    raw = os.environ.get(name)
    if raw:
        key = bytes.fromhex(raw.strip())
        if len(key) != 32:
            raise RuntimeError(f"{name} must be 64 hex characters (32 bytes)")
        return key
    if production:
        raise RuntimeError(
            f"{name} is not set. Generate one with: python -c "
            "\"import secrets; print(secrets.token_hex(32))\""
        )
    # Development only: persist a generated key so restarts keep working.
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / f".{name.lower()}"
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    key = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key.hex())
    return key


def from_env() -> Config:
    env = os.environ.get("TRUSTVAULT_ENV", "production").lower()
    production = env != "development"
    data_dir = Path(os.environ.get("TRUSTVAULT_DATA", "data")).resolve()
    cfg = Config(
        data_dir=data_dir,
        master_key=_load_key("TRUSTVAULT_MASTER_KEY", data_dir, production),
        audit_key=_load_key("TRUSTVAULT_AUDIT_KEY", data_dir, production),
        secure_cookies=production,
        proxy_hops=int(os.environ.get("TRUSTVAULT_PROXY_HOPS", "0")),
    )
    cfg.validate()
    return cfg
