from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, socket
from typing import Any, Iterable

from .authenticator import AuthenticatorFactory
from .config import CHAT_SERVICE, TGS_ID
from .crypto import decrypt, encrypt, current_timestamp, derive_shared_key
from .kdf import derive_user_key
from .models import ASReply, Authenticator, TicketTGS, TicketV


def _json_loads(raw: str) -> dict[str, Any]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Mensagem invalida")
    return payload


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


@dataclass(slots=True)
class KerberosClient:
    username: str
    password: str
    client_address: str = "127.0.0.1"
    authenticator_factory: AuthenticatorFactory = field(default_factory=AuthenticatorFactory)
    kc: bytes = field(init=False, repr=False)
    kc_tgs: bytes | None = field(default=None, init=False, repr=False)
    ticket_tgs: str | None = field(default=None, init=False, repr=False)
    kc_v: bytes | None = field(default=None, init=False, repr=False)
    ticket_v: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.kc = derive_user_key(self.username, self.password)

    def load_as_reply(self, payload: str) -> ASReply:
        reply = ASReply.from_dict(decrypt(self.kc, payload))
        self.kc_tgs = base64.b64decode(reply.session_key.encode("utf-8"))
        self.ticket_tgs = reply.ticket_tgs
        return reply

    def build_authenticator(self, timestamp: int | None = None) -> str:
        if self.kc_tgs is None:
            raise ValueError("Kc_tgs indisponivel")
        authenticator = self.authenticator_factory.create(
            client_id=self.username,
            client_address=self.client_address,
            timestamp=current_timestamp() if timestamp is None else timestamp,
        )
        return self.authenticator_factory.encrypt(self.kc_tgs, authenticator)

    def build_tgs_request(self, service_id: str = CHAT_SERVICE, timestamp: int | None = None) -> dict[str, Any]:
        if self.ticket_tgs is None or self.kc_tgs is None:
            raise ValueError("TicketTGS indisponivel")
        return {
            "type": "tgs_request",
            "service": service_id,
            "ticket": self.ticket_tgs,
            "authenticator": self.build_authenticator(timestamp=timestamp),
        }

    def handle_tgs_reply(self, payload: str) -> dict[str, Any]:
        if self.kc_tgs is None:
            raise ValueError("Kc_tgs indisponivel")
        reply = decrypt(self.kc_tgs, payload)
        self.kc_v = base64.b64decode(str(reply["session_key"]).encode("utf-8"))
        self.ticket_v = str(reply["ticket_v"])
        return reply

    def request_tgs(self, host: str, port: int, service_id: str = CHAT_SERVICE) -> dict[str, Any]:
        request = self.build_tgs_request(service_id=service_id)
        with socket(AF_INET, SOCK_STREAM) as connection:
            connection.connect((host, port))
            writer = connection.makefile("w", encoding="utf-8", newline="\n")
            reader = connection.makefile("r", encoding="utf-8", newline="\n")
            writer.write(_json_dumps(request) + "\n")
            writer.flush()
            raw = reader.readline()
            if not raw:
                raise ValueError("TGS sem resposta")
            response = _json_loads(raw)
            if response.get("type") != "tgs_reply":
                raise ValueError(str(response.get("message", "Erro ao consultar TGS")))
            return self.handle_tgs_reply(str(response["payload"]))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cliente Kerberos da etapa 2.")
    parser.add_argument("--username", required=True, help="Nome do usuario")
    parser.add_argument("--password", required=True, help="Senha do usuario")
    parser.add_argument("--client-address", default="127.0.0.1", help="Endereco do cliente")
    parser.add_argument("--tgs-host", default="127.0.0.1", help="Endereco do TGS")
    parser.add_argument("--tgs-port", default=9001, type=int, help="Porta TCP do TGS")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    client = KerberosClient(args.username, args.password, client_address=args.client_address)
    print("Cliente Kerberos pronto. Carregue um payload do AS com load_as_reply() e depois use request_tgs().")


if __name__ == "__main__":
    main()
