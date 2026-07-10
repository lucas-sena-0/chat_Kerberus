from __future__ import annotations

import base64
from dataclasses import dataclass, field

from shared.logger import log

from .config import CHAT_SERVICE
from .crypto import current_timestamp, decrypt, derive_shared_key, encrypt, is_expired
from .models import Authenticator, TicketV
from .replay_cache import ReplayCache
from .session_context import KerberosSession


@dataclass(slots=True)
class ServiceAuthenticator:
    service_name: str = CHAT_SERVICE
    replay_cache: ReplayCache = field(default_factory=ReplayCache)
    max_skew: int = 300

    def _service_key(self) -> bytes:
        return derive_shared_key(self.service_name)

    def _decode_session_key(self, session_key_text: str) -> bytes:
        return base64.b64decode(session_key_text.encode("utf-8"))

    def authenticate(
        self,
        ticket_token: str,
        authenticator_token: str,
        client_address: str,
    ) -> tuple[KerberosSession, str]:
        ticket = TicketV.from_dict(decrypt(self._service_key(), ticket_token))
        log("CHAT", "TicketV validado", {"client_id": ticket.client_id, "service_id": ticket.service_id})
        if is_expired(ticket.timestamp, ticket.lifetime):
            raise ValueError("Ticket expirado.")

        if ticket.client_address != client_address:
            raise ValueError("Authenticator inválido.")

        kc_v = self._decode_session_key(ticket.session_key)
        authenticator = Authenticator.from_dict(decrypt(kc_v, authenticator_token))
        log("CHAT", "Authenticator descriptografado", {"client_id": authenticator.client_id})

        if authenticator.client_id != ticket.client_id:
            raise ValueError("Authenticator inválido.")
        if authenticator.client_address != ticket.client_address:
            raise ValueError("Authenticator inválido.")
        if abs(current_timestamp() - authenticator.timestamp) > self.max_skew:
            raise ValueError("Authenticator inválido.")
        if self.replay_cache.contains(authenticator.client_id, authenticator.timestamp):
            raise ValueError("Replay detectado.")

        self.replay_cache.add(authenticator.client_id, authenticator.timestamp)
        log("CHAT", "Replay Cache atualizado", {"client_id": authenticator.client_id})
        session = KerberosSession(
            client_id=ticket.client_id,
            Kc_v=kc_v,
            login_timestamp=authenticator.timestamp,
            ticket_expiration=ticket.timestamp + ticket.lifetime,
        )
        mutual_auth_payload = encrypt(kc_v, {"timestamp": authenticator.timestamp + 1})
        log("CHAT", "Autenticação mútua concluída", {"client_id": ticket.client_id})
        return session, mutual_auth_payload
