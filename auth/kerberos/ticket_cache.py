from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TicketCache:
    _tickets: list[Any] = field(default_factory=list, init=False, repr=False)

    def store(self, ticket: Any) -> None:
        self._tickets.append(ticket)

    def find(self, **criteria: Any) -> list[Any]:
        if not criteria:
            return list(self._tickets)

        matches: list[Any] = []
        for ticket in self._tickets:
            if all(getattr(ticket, key, None) == value for key, value in criteria.items()):
                matches.append(ticket)
        return matches

    def remove(self, **criteria: Any) -> int:
        if not criteria:
            count = len(self._tickets)
            self._tickets.clear()
            return count

        kept: list[Any] = []
        removed = 0
        for ticket in self._tickets:
            if all(getattr(ticket, key, None) == value for key, value in criteria.items()):
                removed += 1
                continue
            kept.append(ticket)
        self._tickets = kept
        return removed
