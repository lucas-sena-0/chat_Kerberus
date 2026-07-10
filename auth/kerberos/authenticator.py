from __future__ import annotations

from dataclasses import dataclass

from .crypto import current_timestamp, decrypt, encrypt
from .models import Authenticator, TicketTGS


@dataclass(slots=True)
class AuthenticatorFactory:
    max_skew: int = 300

    def create(
        self,
        client_id: str,
        client_address: str,
        timestamp: int | None = None,
    ) -> Authenticator:
        return Authenticator(
            client_id=client_id,
            client_address=client_address,
            timestamp=current_timestamp() if timestamp is None else timestamp,
        )

    def decrypt(self, key: bytes, token: str) -> Authenticator:
        return Authenticator.from_dict(decrypt(key, token))

    def encrypt(self, key: bytes, authenticator: Authenticator) -> str:
        return encrypt(key, authenticator.to_dict())

    def validate(self, ticket: TicketTGS, authenticator: Authenticator) -> bool:
        return abs(current_timestamp() - authenticator.timestamp) <= self.max_skew
