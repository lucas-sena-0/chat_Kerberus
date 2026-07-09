from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PrincipalDatabase:
    path: Path

    @classmethod
    def default(cls) -> PrincipalDatabase:
        return cls(path=Path(__file__).with_name("principals.json"))

    def _load(self) -> dict:
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def user_exists(self, username: str) -> bool:
        data = self._load()
        return username in data.get("users", {})

    def get_password(self, username: str) -> str:
        data = self._load()
        return str(data["users"][username]["password"])

    def service_exists(self, service_name: str) -> bool:
        data = self._load()
        return service_name in data.get("services", {})
