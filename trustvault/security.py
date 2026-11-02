"""Password hashing, session tokens and password policy."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P = 2 ** 14, 8, 1

COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiopas", "letmein12345",
    "administrator", "welcome12345", "changeme1234", "trustvault123",
}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _N, _R, _P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r),
                                p=int(p), dklen=len(expected))
    except Exception:
        return False
    return hmac.compare_digest(actual, expected)


# Verified against when the account does not exist, so "no such user" costs the
# same time as "wrong password" and cannot be told apart by timing.
DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


def password_problem(password: str, email: str = "") -> str | None:
    if len(password) < 12:
        return "password must be at least 12 characters"
    if len(password) > 128:
        return "password must be at most 128 characters"
    if password.lower() in COMMON_PASSWORDS:
        return "password is too common"
    if email and password.lower() == email.lower():
        return "password must not equal the email address"
    if len(set(password)) < 5:
        return "password is too repetitive"
    return None


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, token_hash(token)


def temp_password() -> str:
    return secrets.token_urlsafe(15)
