import base64

import pytest

from auth.kerberos.authenticator import AuthenticatorFactory
from auth.kerberos.config import CHAT_SERVICE, DEFAULT_LIFETIME, TGS_ID
from auth.kerberos.crypto import current_timestamp, decrypt, derive_shared_key, encrypt, generate_key
from auth.kerberos.models import Authenticator, TicketV
from auth.kerberos.service_auth import ServiceAuthenticator


def _build_valid_ticket_and_authenticator(client_id: str = "lucas", client_address: str = "127.0.0.1") -> tuple[str, str, bytes, int]:
    kc_v = generate_key()
    timestamp = current_timestamp()
    ticket = TicketV(
        client_id=client_id,
        client_address=client_address,
        service_id=CHAT_SERVICE,
        session_key=base64.b64encode(kc_v).decode("utf-8"),
        timestamp=timestamp,
        lifetime=DEFAULT_LIFETIME,
    )
    authenticator = Authenticator(client_id=client_id, client_address=client_address, timestamp=timestamp)
    factory = AuthenticatorFactory()
    return (
        encrypt(derive_shared_key(CHAT_SERVICE), ticket.to_dict()),
        factory.encrypt(kc_v, authenticator),
        kc_v,
        timestamp,
    )


def test_valid_ticketv_authenticates_client():
    service = ServiceAuthenticator()
    ticket, authenticator, kc_v, timestamp = _build_valid_ticket_and_authenticator()
    session, mutual = service.authenticate(ticket, authenticator, "127.0.0.1")
    assert session.client_id == "lucas"
    assert session.Kc_v == kc_v
    assert decrypt(kc_v, mutual)["timestamp"] == timestamp + 1


def test_expired_ticketv_is_rejected():
    service = ServiceAuthenticator()
    ticket, authenticator, _, _ = _build_valid_ticket_and_authenticator()
    decoded = TicketV.from_dict(decrypt(derive_shared_key(CHAT_SERVICE), ticket))
    decoded.timestamp -= 10_000
    ticket = encrypt(derive_shared_key(CHAT_SERVICE), decoded.to_dict())
    with pytest.raises(ValueError, match="Ticket expirado"):
        service.authenticate(ticket, authenticator, "127.0.0.1")


def test_altered_authenticator_is_rejected():
    service = ServiceAuthenticator()
    ticket, authenticator, kc_v, _ = _build_valid_ticket_and_authenticator()
    tampered = authenticator[:-2] + "AA"
    with pytest.raises(Exception):
        service.authenticate(ticket, tampered, "127.0.0.1")


def test_client_id_divergence_is_rejected():
    service = ServiceAuthenticator()
    ticket, authenticator, kc_v, timestamp = _build_valid_ticket_and_authenticator()
    bad_auth = Authenticator(client_id="alice", client_address="127.0.0.1", timestamp=timestamp)
    bad_token = AuthenticatorFactory().encrypt(kc_v, bad_auth)
    with pytest.raises(ValueError, match="Authenticator inválido"):
        service.authenticate(ticket, bad_token, "127.0.0.1")


def test_replay_cache_rejects_same_authenticator():
    service = ServiceAuthenticator()
    ticket, authenticator, _, _ = _build_valid_ticket_and_authenticator()
    service.authenticate(ticket, authenticator, "127.0.0.1")
    with pytest.raises(ValueError, match="Replay detectado"):
        service.authenticate(ticket, authenticator, "127.0.0.1")
