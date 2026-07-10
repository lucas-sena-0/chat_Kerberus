from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ReplayCache:
    _entries: set[tuple[str, int]] = field(default_factory=set, init=False, repr=False)

    def contains(self, client_id: str, timestamp: int) -> bool:
        return (client_id, timestamp) in self._entries

    def add(self, client_id: str, timestamp: int) -> None:
        self._entries.add((client_id, timestamp))

    def remove(self, client_id: str, timestamp: int) -> None:
        self._entries.discard((client_id, timestamp))
