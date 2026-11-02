"""Encrypted blob storage.

Why a file is unreachable without authorisation:
* Blobs live under a data directory that is never served by the web app, under
  random 128-bit names that carry no document or user information.
* Every blob is encrypted with AES-256-GCM using its own random data key; the
  data key is wrapped with the master key (envelope encryption) and kept in the
  database. Disk access alone yields only ciphertext.
* The AAD binds a blob to its document, version and blob id, so ciphertext
  swapped between documents fails authentication instead of leaking.
* Purging deletes the blob and the wrapped key (crypto-shredding).
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Config


class StorageError(Exception):
    pass


def _aad(doc_id: str, version: int, blob_id: str) -> bytes:
    return f"{doc_id}:{version}:{blob_id}".encode()


def _path(cfg: Config, blob_id: str) -> Path:
    if len(blob_id) != 32 or any(c not in "0123456789abcdef" for c in blob_id):
        raise StorageError("invalid blob id")
    return cfg.blob_dir / blob_id[:2] / blob_id


def put(cfg: Config, plaintext: bytes, doc_id: str, version: int) -> tuple[str, bytes]:
    """Encrypt and store. Returns (blob_id, wrapped_key)."""
    blob_id = secrets.token_hex(16)
    aad = _aad(doc_id, version, blob_id)
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = nonce + AESGCM(data_key).encrypt(nonce, plaintext, aad)
    wrap_nonce = os.urandom(12)
    wrapped = wrap_nonce + AESGCM(cfg.master_key).encrypt(wrap_nonce, data_key, aad)

    path = _path(cfg, blob_id)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(ciphertext)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return blob_id, wrapped


def get(cfg: Config, blob_id: str, wrapped_key: bytes, doc_id: str, version: int) -> bytes:
    aad = _aad(doc_id, version, blob_id)
    try:
        data_key = AESGCM(cfg.master_key).decrypt(wrapped_key[:12], wrapped_key[12:], aad)
        raw = _path(cfg, blob_id).read_bytes()
        return AESGCM(data_key).decrypt(raw[:12], raw[12:], aad)
    except (InvalidTag, FileNotFoundError) as exc:
        raise StorageError("stored file failed integrity check or is missing") from exc


def remove(cfg: Config, blob_id: str) -> None:
    try:
        _path(cfg, blob_id).unlink()
    except FileNotFoundError:
        pass
