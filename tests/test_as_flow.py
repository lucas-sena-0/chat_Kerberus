import base64

import pytest

from auth.kerberos.as_server import AuthenticationServer
from auth.kerberos.config import TGS_ID
from auth.kerberos.crypto import decrypt, derive_shared_key
from auth.kerberos.kdf import derive_user_key
from auth.kerberos.models import ASReply, TicketTGS


def test_valid_user_receives_reply():
    server = AuthenticationServer()
    response = server.process_request({"client_id": "lucas", "service": "tgs"}, "127.0.0.1")
    assert response["ok"] is True
    assert response["type"] == "as_reply"


def test_correct_password_decrypts_reply():
    server = AuthenticationServer()
    response = server.process_request({"client_id": "lucas", "service": "tgs"}, "127.0.0.1")
    kc = derive_user_key("lucas", "senha123")
    reply = ASReply.from_dict(decrypt(kc, response["payload"]))
    assert reply.tgs_id == "tgs"
    ticket = TicketTGS.from_dict(decrypt(derive_shared_key(TGS_ID), reply.ticket_tgs))
    assert ticket.client_id == "lucas"
    assert ticket.tgs_id == "tgs"


def test_wrong_password_cannot_decrypt_reply():
    server = AuthenticationServer()
    response = server.process_request({"client_id": "lucas", "service": "tgs"}, "127.0.0.1")
    wrong_kc = derive_user_key("lucas", "senha_errada")
    with pytest.raises(Exception):
        decrypt(wrong_kc, response["payload"])


def test_unknown_user_is_rejected():
    server = AuthenticationServer()
    with pytest.raises(ValueError, match="Usuário inexistente"):
        server.process_request({"client_id": "desconhecido", "service": "tgs"}, "127.0.0.1")
