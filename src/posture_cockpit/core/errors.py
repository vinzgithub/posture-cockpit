# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The exception a check receives when the network gives no usable answer.

It lives in its own module so that :mod:`.network` and :mod:`.egress` can both
use it without importing each other."""


class NetworkError(Exception):
    """A question got no usable answer (timeout, refused, DNS server failure, destination not allowed).

    The engine reports the check as "not evaluated" rather than as a failure."""

    # Version 0.4: where a connection to one address stopped, when known: "tcp" (the connection
    # itself), "tls" (the negotiation) or "http" (the request, once connected).
    stage: str = ""


class Refused(NetworkError):
    """The server's address answered and refused the connection: nothing listens on that port.

    Unlike a timeout, this is a definite answer, and a check may treat it as
    such (no MTA-STS policy server, for instance)."""


class ConnectionTimedOut(NetworkError):
    """The remote connection did not finish within the allowed time."""


class ConnectionReset(NetworkError):
    """The connection was reset while communicating with the remote host."""


class ConnectionClosed(ConnectionReset):
    """The server closed the connection without a word, during the TLS negotiation or before
    answering the request (version 0.4). A kind of reset for the checks written before."""


class TLSHandshakeError(NetworkError):
    """TLS negotiation failed before a usable certificate or response was obtained."""


class TLSAlert(TLSHandshakeError):
    """The server ended the TLS negotiation with an alert (version 0.4); ``alert`` is its name
    as OpenSSL reports it, e.g. ``"tlsv1_alert_protocol_version"``."""

    def __init__(self, message: str, alert: str):
        super().__init__(message)
        self.alert = alert


class Unreachable(NetworkError):
    """This machine has no route to the address, IPv6 absent for instance (version 0.4).

    It says nothing about the server: the address could not be tested from here."""


class LegacyUnsupported(NetworkError):
    """This machine's TLS library cannot offer the old version of TLS asked for (version 0.4).

    It says nothing about the server: whether it accepts that version is unknown."""
