from __future__ import annotations

import argparse
import base64
import json
from socket import AF_INET, SOCK_STREAM, socket
from threading import Event, Thread
from typing import Any, Iterable

from shared.protocol import Packet, create_packet, receive_packet, send_packet

from auth.kerberos.authenticator import AuthenticatorFactory
from auth.kerberos.crypto import current_timestamp, decrypt


def _json_loads(raw: str) -> dict[str, Any]:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Mensagem invalida")
    return payload


def _json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


class ChatClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.host = host
        self.port = port
        self.connection: socket | None = None
        self.reader = None
        self.writer = None
        self._running = False
        self._receiver_ready = Event()
        self.authenticator_factory = AuthenticatorFactory()
        self.username: str | None = None
        self.ticket_v: str | None = None
        self.kc_v: bytes | None = None

    def configure_kerberos(self, username: str, ticket_v: str, kc_v_b64: str) -> None:
        self.username = username
        self.ticket_v = ticket_v
        self.kc_v = base64.b64decode(kc_v_b64.encode("utf-8"))

    def connect(self) -> None:
        self.connection = socket(AF_INET, SOCK_STREAM)
        self.connection.connect((self.host, self.port))
        self.reader = self.connection.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.connection.makefile("w", encoding="utf-8", newline="\n")

    def kerberos_authenticate(self) -> tuple[bool, str]:
        assert self.writer is not None and self.reader is not None and self.username is not None
        assert self.ticket_v is not None and self.kc_v is not None
        authenticator = self.authenticator_factory.create(
            client_id=self.username,
            client_address=self.host,
            timestamp=current_timestamp(),
        )
        authenticator_token = self.authenticator_factory.encrypt(self.kc_v, authenticator)
        send_packet(
            self.writer,
            create_packet("kerberos_auth", ticket=self.ticket_v, authenticator=authenticator_token),
        )
        packet = receive_packet(self.reader)
        if packet is None:
            return False, "conexao encerrada durante autenticacao kerberos"
        if packet.type == "kerberos_error":
            return False, str(packet.data.get("message", "falha na autenticacao kerberos"))
        if packet.type != "kerberos_mutual":
            return False, "resposta kerberos invalida"

        payload = str(packet.data.get("payload", ""))
        if not payload:
            return False, "resposta kerberos invalida"

        mutual = decrypt(self.kc_v, payload)
        received_timestamp = int(mutual["timestamp"])
        sent_timestamp = authenticator.timestamp
        if received_timestamp != sent_timestamp + 1:
            return False, "falha na autenticacao mutua"

        return True, "autenticado com Kerberos"

    def start(self) -> None:
        self.connect()
        authenticated, message = self.kerberos_authenticate()
        if not authenticated:
            print(f"[auth] {message}")
            self.close()
            return

        self._running = True
        print(f"[auth] {message}")
        print("Digite /list para listar usuarios ou /quit para sair. Qualquer outro texto sera enviado como mensagem.")
        receiver = Thread(target=self._receive_loop, daemon=True)
        receiver.start()
        self._receiver_ready.set()
        self._send_loop()

    def _receive_loop(self) -> None:
        assert self.reader is not None
        self._receiver_ready.wait()
        while self._running:
            try:
                packet = receive_packet(self.reader)
            except ValueError as exc:
                print(f"[erro] {exc}")
                break

            if packet is None:
                print("[info] conexao encerrada pelo servidor")
                break
            self._render_packet(packet)

        self._running = False

    def _render_packet(self, packet: Packet) -> None:
        if packet.type == "chat":
            sender = str(packet.data.get("sender", "?"))
            message = str(packet.data.get("message", ""))
            print(f"<{sender}> {message}")
            return

        if packet.type == "system":
            print(f"[sistema] {packet.data.get('message', '')}")
            return

        if packet.type == "users":
            users = packet.data.get("users", [])
            print("[usuarios] " + ", ".join(map(str, users)) if users else "[usuarios] nenhum usuario online")
            return

        if packet.type == "error":
            print(f"[erro] {packet.data.get('message', '')}")
            return

        print(f"[desconhecido] {packet.type}: {packet.data}")

    def _send_loop(self) -> None:
        assert self.writer is not None
        while self._running:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "/quit"
                print()

            if not line:
                continue

            if line == "/quit":
                send_packet(self.writer, create_packet("quit"))
                self._running = False
                break

            if line == "/list":
                send_packet(self.writer, create_packet("list"))
                continue

            send_packet(self.writer, create_packet("msg", message=line))

        self.close()

    def close(self) -> None:
        self._running = False
        if self.writer is not None:
            try:
                self.writer.close()
            except OSError:
                pass
            self.writer = None
        if self.reader is not None:
            try:
                self.reader.close()
            except OSError:
                pass
            self.reader = None
        if self.connection is not None:
            try:
                self.connection.close()
            except OSError:
                pass
            self.connection = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cliente de chat integrado ao Kerberos.")
    parser.add_argument("--host", default="127.0.0.1", help="Endereco do servidor")
    parser.add_argument("--port", default=5000, type=int, help="Porta TCP do servidor")
    parser.add_argument("-u", "--username", required=True, help="Nome de usuario")
    parser.add_argument("--ticket-v", required=True, help="TicketV em Base64")
    parser.add_argument("--kc-v", required=True, help="Kc_v em Base64")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    client = ChatClient(host=args.host, port=args.port)
    client.configure_kerberos(args.username, args.ticket_v, args.kc_v)
    client.start()


if __name__ == "__main__":
    main()
