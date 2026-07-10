from __future__ import annotations

import argparse
import base64
from typing import Iterable

from auth.kerberos.config import AS_HOST, AS_PORT, CHAT_HOST, CHAT_PORT, TGS_HOST, TGS_PORT
from auth.kerberos.kerberos_client import KerberosClient
from client.client import ChatClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Executa o fluxo Kerberos completo (AS + TGS) e conecta ao chat."
    )
    parser.add_argument("-u", "--username", required=True, help="Nome do usuario")
    parser.add_argument("-p", "--password", required=True, help="Senha do usuario")
    parser.add_argument("--client-address", default="127.0.0.1", help="Endereco do cliente")
    parser.add_argument("--as-host", default=AS_HOST)
    parser.add_argument("--as-port", default=AS_PORT, type=int)
    parser.add_argument("--tgs-host", default=TGS_HOST)
    parser.add_argument("--tgs-port", default=TGS_PORT, type=int)
    parser.add_argument("--chat-host", default=CHAT_HOST)
    parser.add_argument("--chat-port", default=CHAT_PORT, type=int)
    return parser


def main(argv: Iterable[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    kerberos = KerberosClient(
        username=args.username,
        password=args.password,
        client_address=args.client_address,
    )
    try:
        kerberos.run_full_flow(
            as_host=args.as_host,
            as_port=args.as_port,
            tgs_host=args.tgs_host,
            tgs_port=args.tgs_port,
        )
    except Exception as exc:
        print(f"[ERRO] Falha no fluxo Kerberos: {exc}")
        return

    if kerberos.ticket_v is None or kerberos.kc_v is None:
        print("[ERRO] TicketV ou Kc_v ausentes apos o fluxo Kerberos.")
        return

    kc_v_b64 = base64.b64encode(kerberos.kc_v).decode("utf-8")

    chat = ChatClient(host=args.chat_host, port=args.chat_port)
    chat.configure_kerberos(args.username, kerberos.ticket_v, kc_v_b64)
    chat.start()


if __name__ == "__main__":
    main()
