from __future__ import annotations

import hashlib

from .config import PBKDF2_ITERATIONS, REALM


def derive_user_key(username: str, password: str) -> bytes:
    salt = f"{REALM}{username}".encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )