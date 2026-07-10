from __future__ import annotations


class KerberosError(Exception):
    pass


class InvalidTicketError(KerberosError):
    pass


class ExpiredTicketError(KerberosError):
    pass


class InvalidAuthenticatorError(KerberosError):
    pass


class ReplayDetectedError(KerberosError):
    pass
