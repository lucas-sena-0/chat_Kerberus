from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, socket
from typing import Any, Iterable

from shared.logger import log

from .authenticator import AuthenticatorFactory
from .config import AS_PORT, DEFAULT_LIFETIME, CHAT_SERVICE, TGS_ID
from .crypto import current_timestamp, decrypt, derive_shared_key, encrypt, generate_key, is_expired
from .models import Authenticator, TicketTGS, TicketV
from .principal_db import PrincipalDatabase
from .ticket_cache import TicketCache


def _json_loads(raw: str) -> dict[str, Any]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Mensagem invalida")
    return payload


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


@dataclass(slots=True)
class TGSServer:
    host: str = "127.0.0.1"
    port: int = 9001
    principal_db: PrincipalDatabase = field(default_factory=PrincipalDatabase.default)
    ticket_cache: TicketCache = field(default_factory=TicketCache)
    authenticator_factory: AuthenticatorFactory = field(default_factory=AuthenticatorFactory)

    def _tgs_key(self) -> bytes:
        return derive_shared_key(TGS_ID)

    def _service_key(self, service_id: str) -> bytes:
        return derive_shared_key(service_id)

    def _decode_session_key(self, key_text: str) -> bytes:
        return base64.b64decode(key_text.encode("utf-8"))

    def process_request(self, request: dict[str, Any], client_address: str) -> dict[str, Any]:
        service_id = str(request.get("service", "")).strip()
        if not service_id:
            raise ValueError("Servico desconhecido")
        if not self.principal_db.service_exists(service_id):
            raise ValueError("Servico desconhecido")

        ticket_token = str(request.get("ticket", ""))
        authenticator_token = str(request.get("authenticator", ""))
        if not ticket_token or not authenticator_token:
            raise ValueError("Authenticator invalido")

        ticket = TicketTGS.from_dict(decrypt(self._tgs_key(), ticket_token))
        log("TGS", "TicketTGS descriptografado", {"client_id": ticket.client_id, "timestamp": ticket.timestamp})
        if is_expired(ticket.timestamp, ticket.lifetime):
            raise ValueError("Ticket expirado")

        kc_tgs = self._decode_session_key(ticket.session_key)
        authenticator = self.authenticator_factory.decrypt(kc_tgs, authenticator_token)

        if authenticator.client_id != ticket.client_id:
            raise ValueError("Client ID diferente")
        if authenticator.client_address != ticket.client_address:
            raise ValueError("Endereco diferente")
        if not self.authenticator_factory.validate(ticket, authenticator):
            raise ValueError("Authenticator invalido")
        log("TGS", "Authenticator validado", {"client_id": authenticator.client_id})

        kc_v = generate_key()
        kc_v_text = base64.b64encode(kc_v).decode("utf-8")
        log("TGS", "Kc_v gerada", {"client_id": ticket.client_id, "kc_v": kc_v})
        ticket_v = TicketV(
            client_id=ticket.client_id,
            client_address=ticket.client_address,
            service_id=service_id,
            session_key=kc_v_text,
            timestamp=current_timestamp(),
            lifetime=DEFAULT_LIFETIME,
        )
        ticket_v_token = encrypt(self._service_key(service_id), ticket_v.to_dict())
        self.ticket_cache.store(ticket_v)
        log("TGS", "TicketV emitido", {"client_id": ticket.client_id, "service_id": service_id})

        reply_payload = {
            "session_key": kc_v_text,
            "service_id": service_id,
            "timestamp": current_timestamp(),
            "lifetime": DEFAULT_LIFETIME,
            "ticket_v": ticket_v_token,
        }
        return {"ok": True, "type": "tgs_reply", "payload": encrypt(kc_tgs, reply_payload)}

    def handle_json(self, raw: str, client_address: str) -> str:
        try:
            request = _json_loads(raw)
            response = self.process_request(request, client_address)
        except ValueError as exc:
            response = {"ok": False, "type": "error", "error": "request_error", "message": str(exc)}
        return _json_dumps(response)

    def start(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"TGS ouvindo em {self.host}:{self.port}")

            while True:
                connection, address = server_socket.accept()
                with connection:
                    reader = connection.makefile("r", encoding="utf-8", newline="\n")
                    writer = connection.makefile("w", encoding="utf-8", newline="\n")
                    raw = reader.readline()
                    if not raw:
                        continue
                    response = self.handle_json(raw, str(address[0]))
                    writer.write(response + "\n")
                    writer.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Servidor TGS da etapa 2 do Kerberos.")
    parser.add_argument("--host", default="127.0.0.1", help="Endereco para bind do TGS")
    parser.add_argument("--port", default=9001, type=int, help="Porta TCP do TGS")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    TGSServer(host=args.host, port=args.port).start()


if __name__ == "__main__":
    main()
