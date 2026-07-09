from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from socket import AF_INET, SOCK_STREAM, SO_REUSEADDR, SOL_SOCKET, socket
from threading import Lock, Thread
from typing import Iterable, TextIO

from shared.protocol import Packet, create_packet, receive_packet, send_packet


DEFAULT_CREDENTIALS: dict[str, str] = {
    "alice": "alice123",
    "bob": "bob123",
    "carol": "carol123",
}


@dataclass(slots=True, eq=False)
class ClientSession:
    server: "ChatServer"
    connection: socket
    address: tuple[str, int]
    reader: TextIO = field(init=False, repr=False)
    writer: TextIO = field(init=False, repr=False)
    username: str | None = None
    _send_lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.reader = self.connection.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.connection.makefile("w", encoding="utf-8", newline="\n")

    def send(self, packet: Packet) -> None:
        with self._send_lock:
            if not self._closed:
                send_packet(self.writer, packet)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.reader.close()
        finally:
            try:
                self.writer.close()
            finally:
                self.connection.close()

    def run(self) -> None:
        try:
            auth_packet = receive_packet(self.reader)
            if auth_packet is None or auth_packet.type != "auth":
                return

            username = str(auth_packet.data.get("username", "")).strip()
            password = str(auth_packet.data.get("password", ""))

            if not username or not password:
                self.send(create_packet("auth_error", message="username e password sao obrigatorios"))
                return

            if self.server.is_username_taken(username):
                self.send(create_packet("auth_error", message="usuario ja esta em uso"))
                return

            if not self.server.authenticate(username, password):
                self.send(create_packet("auth_error", message="credenciais invalidas"))
                return

            self.username = username
            self.server.register_user(username)
            self.send(create_packet("auth_ok", username=username, message="autenticado com sucesso"))
            self.server.broadcast_system(f"{username} entrou no chat.", exclude=self)
            self._chat_loop()
        finally:
            if self.username is not None:
                self.server.unregister_user(self.username)
                self.server.broadcast_system(f"{self.username} saiu do chat.", exclude=self)
            self.close()

    def _chat_loop(self) -> None:
        assert self.username is not None
        while True:
            packet = receive_packet(self.reader)
            if packet is None:
                return

            if packet.type == "chat":
                message = str(packet.data.get("message", "")).strip()
                if message:
                    self.server.broadcast_chat(self.username, message)
                continue

            if packet.type == "users":
                self.send(create_packet("users", users=self.server.list_users()))
                continue

            if packet.type == "quit":
                return


@dataclass(slots=True)
class ChatServer:
    host: str = "127.0.0.1"
    port: int = 5000
    credentials: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_CREDENTIALS))
    _active_users: set[str] = field(default_factory=set, init=False, repr=False)
    _sessions: set[ClientSession] = field(default_factory=set, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _running: bool = field(default=False, init=False, repr=False)

    def start(self) -> None:
        self._running = True
        with socket(AF_INET, SOCK_STREAM) as server_socket:
            server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            print(f"Servidor ouvindo em {self.host}:{self.port}")

            try:
                while self._running:
                    connection, address = server_socket.accept()
                    session = ClientSession(server=self, connection=connection, address=address)
                    with self._lock:
                        self._sessions.add(session)
                    Thread(target=self._run_session, args=(session,), daemon=True).start()
            except KeyboardInterrupt:
                print("\nEncerrando servidor...")
            finally:
                self.shutdown()

    def shutdown(self) -> None:
        self._running = False
        with self._lock:
            sessions = list(self._sessions)
        for session in sessions:
            session.close()

    def _run_session(self, session: ClientSession) -> None:
        try:
            session.run()
        finally:
            with self._lock:
                self._sessions.discard(session)

    def authenticate(self, username: str, password: str) -> bool:
        return self.credentials.get(username) == password

    def register_user(self, username: str) -> None:
        with self._lock:
            self._active_users.add(username)

    def unregister_user(self, username: str) -> None:
        with self._lock:
            self._active_users.discard(username)

    def is_username_taken(self, username: str) -> bool:
        with self._lock:
            return username in self._active_users

    def list_users(self) -> list[str]:
        with self._lock:
            return sorted(self._active_users)

    def broadcast_chat(self, username: str, message: str) -> None:
        self.broadcast(create_packet("chat", sender=username, message=message))

    def broadcast_system(self, message: str, exclude: ClientSession | None = None) -> None:
        self.broadcast(create_packet("system", message=message), exclude=exclude)

    def broadcast(self, packet: Packet, exclude: ClientSession | None = None) -> None:
        with self._lock:
            sessions = list(self._sessions)
        for session in sessions:
            if session is not exclude:
                session.send(packet)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Servidor de chat simples preparado para Kerberos.")
    parser.add_argument("--host", default="127.0.0.1", help="Endereco para bind do servidor")
    parser.add_argument("--port", default=5000, type=int, help="Porta TCP do servidor")
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    ChatServer(host=args.host, port=args.port).start()


if __name__ == "__main__":
    main()
