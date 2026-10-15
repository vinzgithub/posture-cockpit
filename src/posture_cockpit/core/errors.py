# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The exception a check receives when the network gives no usable answer.

It lives in its own module so that :mod:`.network` and :mod:`.egress` can both
use it without importing each other."""


class NetworkError(Exception):
    """A question got no usable answer (timeout, refused, DNS server failure, destination not allowed).

    The engine reports the check as "not evaluated" rather than as a failure."""


class Refused(NetworkError):
    """The server's address answered and refused the connection: nothing listens on that port.

    Unlike a timeout, this is a definite answer, and a check may treat it as
    such (no MTA-STS policy server, for instance)."""


class ConnectionTimedOut(NetworkError):
    """The remote connection did not finish within the allowed time."""


class ConnectionReset(NetworkError):
    """The connection was reset while communicating with the remote host."""


class TLSHandshakeError(NetworkError):
    """TLS negotiation failed before a usable certificate or response was obtained."""
