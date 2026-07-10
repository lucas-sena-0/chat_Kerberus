from __future__ import annotations

import argparse
import base64
import json
from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, socket
from typing import Any, Iterable

from shared.logger import log

from .config import AS_HOST, AS_PORT, DEFAULT_LIFETIME, TGS_ID
from .crypto import current_timestamp, derive_shared_key, encrypt, generate_key
from .kdf import derive_user_key
from .models import ASReply, TicketTGS
from .principal_db import PrincipalDatabase


def _json_loads(raw: str) -> dict[str, Any]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Mensagem invalida")
    return payload


@dataclass(slots=True)
class AuthenticationServer:
    host: str = AS_HOST
    port: int = AS_PORT
    principal_db: PrincipalDatabase = field(default_factory=PrincipalDatabase.default)

    def _tgs_key(self) -> bytes:
        return derive_shared_key(TGS_ID)

    def process_request(self, request: dict[str, Any], client_address: str) -> dict[str, Any]:
        client_id = str(request.get("client_id", "")).strip()
        service_id = str(request.get("service", "")).strip()

        if not client_id or not self.principal_db.user_exists(client_id):
            raise ValueError("Usuário inexistente")
        if service_id != "tgs":
            raise ValueError("Serviço desconhecido")

        password = self.principal_db.get_password(client_id)
        kc = derive_user_key(client_id, password)
        log("AS", "Kc derivada com sucesso", {"client_id": client_id, "kc": kc})

        kc_tgs = generate_key()
        log("AS", "Kc_tgs gerada", {"client_id": client_id, "kc_tgs": kc_tgs})

        timestamp = current_timestamp()
        ticket_tgs = TicketTGS(
            client_id=client_id,
            client_address=client_address,
            tgs_id=TGS_ID,
            session_key=base64.b64encode(kc_tgs).decode("utf-8"),
            timestamp=timestamp,
            lifetime=DEFAULT_LIFETIME,
        )
        log("AS", "TicketTGS criado", {"client_id": client_id, "timestamp": timestamp})

        ticket_tgs_token = encrypt(self._tgs_key(), ticket_tgs.to_dict())
        reply = ASReply(
            session_key=base64.b64encode(kc_tgs).decode("utf-8"),
            tgs_id=TGS_ID,
            timestamp=timestamp,
            lifetime=DEFAULT_LIFETIME,
            ticket_tgs=ticket_tgs_token,
        )

        payload = encrypt(kc, reply.to_dict())
        log("AS", "Resposta criptografada com Kc", {"client_id": client_id})
        return {"ok": True, "type": "as_reply", "payload": payload}

    def handle_json(self, raw: str, client_address: str) -> str:
        try:
            request = _json_loads(raw)
            response = self.process_request(request, client_address)
        except ValueError as exc:
            response = {"ok": False, "type": "error", "error": "request_error", "message": str(exc)}
        return json.dumps(response, ensure_ascii=False)

    def start(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"AS ouvindo em {self.host}:{self.port}")

            while True:
                connection, address = server_socket.accept()
                with connection:
                    reader = connection.makefile("r", encoding="utf-8", newline="\n")
                    writer = connection.makefile("w", encoding="utf-8", newline="\n")
                    raw = reader.readline()
                    if not raw:
                        continue
                    writer.write(self.handle_json(raw, str(address[0])) + "\n")
                    writer.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Servidor de autenticação Kerberos.")
    parser.add_argument("--host", default=AS_HOST, help="Endereco para bind do AS")
    parser.add_argument("--port", default=AS_PORT, type=int, help="Porta TCP do AS")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    AuthenticationServer(host=args.host, port=args.port).start()


if __name__ == "__main__":
    main()