import base64

import pytest

from auth.kerberos.authenticator import AuthenticatorFactory
from auth.kerberos.config import CHAT_SERVICE, DEFAULT_LIFETIME, TGS_ID
from auth.kerberos.crypto import current_timestamp, decrypt, derive_shared_key, encrypt, generate_key
from auth.kerberos.models import Authenticator, TicketTGS, TicketV
from auth.kerberos.tgs_server import TGSServer


def _build_valid_request(client_id: str = "lucas", client_address: str = "127.0.0.1") -> dict:
    kc_tgs = generate_key()
    timestamp = current_timestamp()
    ticket = TicketTGS(
        client_id=client_id,
        client_address=client_address,
        tgs_id=TGS_ID,
        session_key=base64.b64encode(kc_tgs).decode("utf-8"),
        timestamp=timestamp,
        lifetime=DEFAULT_LIFETIME,
    )
    authenticator = Authenticator(client_id=client_id, client_address=client_address, timestamp=timestamp)
    factory = AuthenticatorFactory()
    return {
        "service": CHAT_SERVICE,
        "ticket": encrypt(derive_shared_key(TGS_ID), ticket.to_dict()),
        "authenticator": factory.encrypt(kc_tgs, authenticator),
        "kc_tgs": kc_tgs,
        "timestamp": timestamp,
    }


def test_valid_ticket_generates_ticket_v():
    server = TGSServer()
    data = _build_valid_request()
    response = server.process_request(data, "127.0.0.1")
    assert response["ok"] is True
    assert response["type"] == "tgs_reply"
    reply = decrypt(data["kc_tgs"], response["payload"])
    assert reply["service_id"] == CHAT_SERVICE
    assert reply["ticket_v"]


def test_expired_ticket_is_rejected():
    server = TGSServer()
    data = _build_valid_request()
    ticket = TicketTGS.from_dict(decrypt(derive_shared_key(TGS_ID), data["ticket"]))
    ticket.timestamp -= 10_000
    data["ticket"] = encrypt(derive_shared_key(TGS_ID), ticket.to_dict())
    with pytest.raises(ValueError, match="Ticket expirado"):
        server.process_request(data, "127.0.0.1")


def test_invalid_authenticator_is_rejected():
    server = TGSServer()
    data = _build_valid_request()
    bad_auth = Authenticator(client_id="alice", client_address="127.0.0.1", timestamp=data["timestamp"])
    data["authenticator"] = AuthenticatorFactory().encrypt(data["kc_tgs"], bad_auth)
    with pytest.raises(ValueError, match="Client ID diferente"):
        server.process_request(data, "127.0.0.1")


def test_unknown_service_is_rejected():
    server = TGSServer()
    data = _build_valid_request()
    data["service"] = "desconhecido"
    with pytest.raises(ValueError, match="Servico desconhecido"):
        server.process_request(data, "127.0.0.1")
