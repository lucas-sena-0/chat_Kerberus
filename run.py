from __future__ import annotations

import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path
from typing import Sequence

from auth.kerberos.config import AS_HOST, AS_PORT, CHAT_HOST, CHAT_PORT, TGS_HOST, TGS_PORT


ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
REQUIREMENTS_FILE = ROOT / "requirements.txt"
SCRIPT_PATH = Path(__file__).resolve()


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def _in_venv() -> bool:
    return sys.prefix != sys.base_prefix


def _ensure_venv() -> None:
    if not VENV_DIR.exists():
        print("[setup] criando .venv...")
        venv.EnvBuilder(with_pip=True).create(VENV_DIR)


def _install_requirements() -> None:
    if not REQUIREMENTS_FILE.exists():
        raise FileNotFoundError("requirements.txt nao encontrado.")

    print("[setup] instalando dependencias...")
    subprocess.run(
        [str(_venv_python()), "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
        check=True,
    )


def _delegate_to_venv(argv: Sequence[str]) -> None:
    subprocess.run([str(_venv_python()), str(SCRIPT_PATH), *argv], check=True)
    raise SystemExit(0)


def _bootstrap_and_delegate(argv: Sequence[str]) -> None:
    if not VENV_DIR.exists():
        _ensure_venv()
        _install_requirements()
    _delegate_to_venv(argv)


def _run_as(args: argparse.Namespace) -> None:
    from auth.kerberos.as_server import main as as_main

    as_main(["--host", args.host, "--port", str(args.port)])


def _run_tgs(args: argparse.Namespace) -> None:
    from auth.kerberos.tgs_server import main as tgs_main

    tgs_main(["--host", args.host, "--port", str(args.port)])


def _run_chat(args: argparse.Namespace) -> None:
    from server.server import main as chat_main

    chat_main(["--host", args.host, "--port", str(args.port)])


def _run_kerberos(args: argparse.Namespace) -> None:
    from auth.kerberos.kerberos_client import main as kerberos_main

    kerberos_main(
        [
            "--username",
            args.username,
            "--password",
            args.password,
            "--client-address",
            args.client_address,
            "--as-host",
            args.as_host,
            "--as-port",
            str(args.as_port),
            "--tgs-host",
            args.tgs_host,
            "--tgs-port",
            str(args.tgs_port),
        ]
    )


def _run_login(args: argparse.Namespace) -> None:
    from client.login import main as login_main

    login_main(
        [
            "-u",
            args.username,
            "-p",
            args.password,
            "--client-address",
            args.client_address,
            "--as-host",
            args.as_host,
            "--as-port",
            str(args.as_port),
            "--tgs-host",
            args.tgs_host,
            "--tgs-port",
            str(args.tgs_port),
            "--chat-host",
            args.chat_host,
            "--chat-port",
            str(args.chat_port),
        ]
    )


def _run_client(args: argparse.Namespace) -> None:
    from client.client import main as client_main

    client_main(
        [
            "--host",
            args.host,
            "--port",
            str(args.port),
            "-u",
            args.username,
            "--ticket-v",
            args.ticket_v,
            "--kc-v",
            args.kc_v,
        ]
    )


def _run_test(_: argparse.Namespace) -> None:
    subprocess.run([sys.executable, "-m", "pytest"], check=True)


def _run_setup(_: argparse.Namespace) -> None:
    _ensure_venv()
    _install_requirements()
    print(f"[setup] pronto. Use '{_venv_python()}' ou ative a .venv para rodar o projeto.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Launcher multiplataforma do Chat Kerberus.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup", help="Cria a .venv e instala dependencias")
    setup_parser.set_defaults(func=_run_setup)

    as_parser = subparsers.add_parser("as", help="Sobe o Authentication Server")
    as_parser.add_argument("--host", default=AS_HOST)
    as_parser.add_argument("--port", default=AS_PORT, type=int)
    as_parser.set_defaults(func=_run_as)

    tgs_parser = subparsers.add_parser("tgs", help="Sobe o Ticket Granting Server")
    tgs_parser.add_argument("--host", default=TGS_HOST)
    tgs_parser.add_argument("--port", default=TGS_PORT, type=int)
    tgs_parser.set_defaults(func=_run_tgs)

    chat_parser = subparsers.add_parser("chat", help="Sobe o servidor de chat")
    chat_parser.add_argument("--host", default=CHAT_HOST)
    chat_parser.add_argument("--port", default=CHAT_PORT, type=int)
    chat_parser.set_defaults(func=_run_chat)

    kerberos_parser = subparsers.add_parser("kerberos", help="Executa apenas AS + TGS")
    kerberos_parser.add_argument("-u", "--username", default="lucas")
    kerberos_parser.add_argument("-p", "--password", default="senha123")
    kerberos_parser.add_argument("--client-address", default="127.0.0.1")
    kerberos_parser.add_argument("--as-host", default=AS_HOST)
    kerberos_parser.add_argument("--as-port", default=AS_PORT, type=int)
    kerberos_parser.add_argument("--tgs-host", default=TGS_HOST)
    kerberos_parser.add_argument("--tgs-port", default=TGS_PORT, type=int)
    kerberos_parser.set_defaults(func=_run_kerberos)

    login_parser = subparsers.add_parser("login", help="Executa o fluxo Kerberos e entra no chat")
    login_parser.add_argument("-u", "--username", default="lucas")
    login_parser.add_argument("-p", "--password", default="senha123")
    login_parser.add_argument("--client-address", default="127.0.0.1")
    login_parser.add_argument("--as-host", default=AS_HOST)
    login_parser.add_argument("--as-port", default=AS_PORT, type=int)
    login_parser.add_argument("--tgs-host", default=TGS_HOST)
    login_parser.add_argument("--tgs-port", default=TGS_PORT, type=int)
    login_parser.add_argument("--chat-host", default=CHAT_HOST)
    login_parser.add_argument("--chat-port", default=CHAT_PORT, type=int)
    login_parser.set_defaults(func=_run_login)

    client_parser = subparsers.add_parser("client", help="Abre o cliente de chat com TicketV e Kc_v")
    client_parser.add_argument("--host", default=CHAT_HOST)
    client_parser.add_argument("--port", default=CHAT_PORT, type=int)
    client_parser.add_argument("-u", "--username", required=True)
    client_parser.add_argument("--ticket-v", required=True)
    client_parser.add_argument("--kc-v", required=True)
    client_parser.set_defaults(func=_run_client)

    test_parser = subparsers.add_parser("test", help="Executa a suite de testes")
    test_parser.set_defaults(func=_run_test)

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if not arguments:
        build_parser().print_help()
        return

    if arguments[0] in {"-h", "--help"}:
        build_parser().print_help()
        return

    command = arguments[0]
    if command != "setup" and not _in_venv():
        _bootstrap_and_delegate(arguments)

    args = build_parser().parse_args(arguments)
    if command == "setup" and not _in_venv():
        _ensure_venv()
        _install_requirements()
        return

    args.func(args)


if __name__ == "__main__":
    main()