from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    return os.urandom(32)


def encrypt(key: bytes, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, payload, None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt(key: bytes, token: str) -> dict[str, Any]:
    raw = base64.b64decode(token.encode("utf-8"))
    nonce = raw[:12]
    ciphertext = raw[12:]
    cipher = AESGCM(key)
    payload = cipher.decrypt(nonce, ciphertext, None)
    return json.loads(payload.decode("utf-8"))


def current_timestamp() -> int:
    return int(time.time())


def is_expired(timestamp: int, lifetime: int) -> bool:
    return current_timestamp() > timestamp + lifetime
