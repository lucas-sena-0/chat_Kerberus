from __future__ import annotations

import argparse
from socket import AF_INET, SOCK_STREAM, socket
from threading import Event, Thread
from typing import Iterable

from shared.protocol import Packet, create_packet, receive_packet, send_packet


class ChatClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        self.host = host
        self.port = port
        self.connection: socket | None = None
        self.reader = None
        self.writer = None
        self._running = False
        self._receiver_ready = Event()

    def connect(self) -> None:
        self.connection = socket(AF_INET, SOCK_STREAM)
        self.connection.connect((self.host, self.port))
        self.reader = self.connection.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.connection.makefile("w", encoding="utf-8", newline="\n")

    def login(self, username: str, password: str) -> tuple[bool, str]:
        assert self.writer is not None and self.reader is not None
        send_packet(self.writer, create_packet("auth", username=username, password=password))
        packet = receive_packet(self.reader)
        if packet is None:
            return False, "conexao encerrada durante autenticacao"
        if packet.type == "auth_ok":
            return True, str(packet.data.get("message", "autenticado"))
        return False, str(packet.data.get("message", "falha na autenticacao"))

    def start(self, username: str, password: str) -> None:
        self.connect()
        authenticated, message = self.login(username, password)
        if not authenticated:
            print(f"[auth] {message}")
            self.close()
            return

        self._running = True
        print(f"[auth] {message}")
        print("Digite mensagens e use /users para listar usuarios ou /quit para sair.")
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

            if line == "/users":
                send_packet(self.writer, create_packet("users"))
                continue

            send_packet(self.writer, create_packet("chat", message=line))

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
    parser = argparse.ArgumentParser(description="Cliente de chat modular preparado para Kerberos.")
    parser.add_argument("--host", default="127.0.0.1", help="Endereco do servidor")
    parser.add_argument("--port", default=5000, type=int, help="Porta TCP do servidor")
    parser.add_argument("-u", "--username", help="Nome de usuario")
    parser.add_argument("-p", "--password", help="Senha do usuario")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    username = args.username or input("Usuario: ").strip()
    password = args.password or input("Senha: ").strip()
    client = ChatClient(host=args.host, port=args.port)
    client.start(username=username, password=password)


if __name__ == "__main__":
    main()
