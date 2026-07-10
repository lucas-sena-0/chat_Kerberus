from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, socket
from typing import Any, Iterable

from shared.logger import log

from .authenticator import AuthenticatorFactory
from .config import AS_HOST, AS_PORT, CHAT_SERVICE, DEMO_MODE, TGS_HOST, TGS_PORT
from .crypto import decrypt, current_timestamp
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

    def _demo(self, message: str) -> None:
        if DEMO_MODE:
            print(message)

    def __post_init__(self) -> None:
        self.kc = derive_user_key(self.username, self.password)
        self._demo("[2] Derivando Kc a partir da senha")
        log("CLIENT", "Kc derivada", {"client_id": self.username, "kc": self.kc})

    def load_as_reply(self, payload: str) -> ASReply:
        reply = ASReply.from_dict(decrypt(self.kc, payload))
        self.kc_tgs = base64.b64decode(reply.session_key.encode("utf-8"))
        self.ticket_tgs = reply.ticket_tgs
        self._demo("[3] Descriptografando resposta do AS")
        log("CLIENT", "Kc_tgs recebida", {"client_id": self.username, "kc_tgs": self.kc_tgs})
        return reply

    def request_as(self, host: str = AS_HOST, port: int = AS_PORT) -> ASReply:
        self._demo("[1] Solicitando TicketTGS ao AS")
        with socket(AF_INET, SOCK_STREAM) as connection:
            connection.connect((host, port))
            writer = connection.makefile("w", encoding="utf-8", newline="\n")
            reader = connection.makefile("r", encoding="utf-8", newline="\n")
            request = {"type": "as_request", "client_id": self.username, "service": "tgs"}
            writer.write(_json_dumps(request) + "\n")
            writer.flush()
            raw = reader.readline()
            if not raw:
                raise ValueError("AS sem resposta")
            response = _json_loads(raw)
            if not response.get("ok", False):
                raise ValueError(str(response.get("message", "Falha ao consultar AS")))
            if response.get("type") != "as_reply":
                raise ValueError("Resposta do AS invalida")
            return self.load_as_reply(str(response["payload"]))

    def build_authenticator(self, timestamp: int | None = None) -> str:
        if self.kc_tgs is None:
            raise ValueError("Kc_tgs indisponivel")
        self._demo("[4] Criando Authenticator para o TGS")
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
        log("CLIENT", "Kc_v recebida", {"client_id": self.username, "kc_v": self.kc_v})
        return reply

    def request_tgs(self, host: str, port: int, service_id: str = CHAT_SERVICE) -> dict[str, Any]:
        self._demo("[5] Solicitando TicketV")
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
            if not response.get("ok", False):
                raise ValueError(str(response.get("message", "Erro ao consultar TGS")))
            if response.get("type") != "tgs_reply":
                raise ValueError("Resposta do TGS invalida")
            return self.handle_tgs_reply(str(response["payload"]))

    def run_full_flow(self, as_host: str = AS_HOST, as_port: int = AS_PORT, tgs_host: str = TGS_HOST, tgs_port: int = TGS_PORT) -> dict[str, Any]:
        as_reply = self.request_as(host=as_host, port=as_port)
        tgs_reply = self.request_tgs(host=tgs_host, port=tgs_port)
        self._demo("[6] Recebendo TicketV")
        self._demo("[7] Validando autenticação mútua")
        self._demo("[8] Entrada no chat autorizada")
        return {"as_reply": as_reply, "tgs_reply": tgs_reply, "ticket_v": self.ticket_v, "kc_v": self.kc_v}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cliente Kerberos simplificado.")
    parser.add_argument("--username", required=True, help="Nome do usuario")
    parser.add_argument("--password", required=True, help="Senha do usuario")
    parser.add_argument("--client-address", default="127.0.0.1", help="Endereco do cliente")
    parser.add_argument("--as-host", default=AS_HOST, help="Endereco do AS")
    parser.add_argument("--as-port", default=AS_PORT, type=int, help="Porta TCP do AS")
    parser.add_argument("--tgs-host", default=TGS_HOST, help="Endereco do TGS")
    parser.add_argument("--tgs-port", default=TGS_PORT, type=int, help="Porta TCP do TGS")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    client = KerberosClient(args.username, args.password, client_address=args.client_address)
    try:
        client.run_full_flow(as_host=args.as_host, as_port=args.as_port, tgs_host=args.tgs_host, tgs_port=args.tgs_port)
        print("[OK] Fluxo Kerberos concluído")
    except Exception as exc:
        print(f"[ERRO] {exc}")


if __name__ == "__main__":
    main()
