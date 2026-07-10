from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class KerberosSession:
    client_id: str
    Kc_v: bytes
    login_timestamp: int
    ticket_expiration: int
