# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The exception a check receives when the network gives no usable answer.

It lives in its own module so that :mod:`.network` and :mod:`.egress` can both
use it without importing each other."""


class NetworkError(Exception):
    """A question got no usable answer (timeout, refused, DNS server failure, destination not allowed).

    The engine reports the check as "not evaluated" rather than as a failure."""
