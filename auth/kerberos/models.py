from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Self


@dataclass(slots=True)
class TicketTGS:
    client_id: str
    client_address: str
    tgs_id: str
    session_key: str
    timestamp: int
    lifetime: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_address": self.client_address,
            "tgs_id": self.tgs_id,
            "session_key": self.session_key,
            "timestamp": self.timestamp,
            "lifetime": self.lifetime,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            client_id=str(data["client_id"]),
            client_address=str(data["client_address"]),
            tgs_id=str(data["tgs_id"]),
            session_key=str(data["session_key"]),
            timestamp=int(data["timestamp"]),
            lifetime=int(data["lifetime"]),
        )


@dataclass(slots=True)
class ASReply:
    session_key: str
    tgs_id: str
    timestamp: int
    lifetime: int
    ticket_tgs: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_key": self.session_key,
            "tgs_id": self.tgs_id,
            "timestamp": self.timestamp,
            "lifetime": self.lifetime,
            "ticket_tgs": self.ticket_tgs,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            session_key=str(data["session_key"]),
            tgs_id=str(data["tgs_id"]),
            timestamp=int(data["timestamp"]),
            lifetime=int(data["lifetime"]),
            ticket_tgs=str(data["ticket_tgs"]),
        )
