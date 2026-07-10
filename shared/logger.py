from __future__ import annotations

from typing import Any


def short_key(key: bytes) -> str:
    if not key:
        return ""
    text = key.hex().upper()
    if len(text) <= 12:
        return text
    return f"{text[:6]}...{text[-4:]}"


def log(component: str, event: str, details: dict[str, Any] | None = None) -> None:
    prefix = f"[{component}] {event}"
    if not details:
        print(prefix)
        return

    rendered: list[str] = []
    for key, value in details.items():
        if isinstance(value, bytes):
            rendered.append(f"{key}={short_key(value)}")
        else:
            rendered.append(f"{key}={value}")
    print(prefix + ": " + ", ".join(rendered))
