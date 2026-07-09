from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Mapping


@dataclass(slots=True)
class Packet:
    type: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({"type": self.type, "data": self.data}, ensure_ascii=False)

    @classmethod
    def from_json(cls, raw: str) -> Packet:
        payload = json.loads(raw)
        return cls(type=payload["type"], data=payload.get("data", {}))


def create_packet(packet_type: str, **data: Any) -> Packet:
    return Packet(type=packet_type, data=data)


def send_packet(writer: Any, packet: Packet) -> None:
    writer.write(packet.to_json() + "\n")
    writer.flush()


def receive_packet(reader: Any) -> Packet | None:
    raw = reader.readline()
    if raw == "":
        return None
    try:
        return Packet.from_json(raw)
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
