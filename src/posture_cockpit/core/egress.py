# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Which addresses a scan may connect to: the one place that decides.

Posture Cockpit connects to servers chosen by its users, through the names they
type and the redirections those servers send back. Without a rule, anyone able
to add a domain could make the application talk to its own administration
ports, to the cloud metadata service, or to any machine of the local network
(server-side request forgery, SSRF).

The rule is applied by :class:`~.network.LiveNetwork` to every connection, after
the name is resolved and before the socket is opened, and the connection is
then made to that very address. So neither a redirection nor a DNS answer that
changes between two questions (DNS rebinding) can lead elsewhere.

Every address falls into one of three zones:

``public``
    reachable from the Internet: always allowed (on the allowed ports).
``internal``
    private networks (RFC 1918, RFC 4193…), loopback, documentation ranges:
    refused, unless the scan runs in an internal perimeter whose networks
    include the address.
``forbidden``
    link-local, multicast, reserved, cloud metadata services: never contacted,
    whatever the mode. They are not services of an audited domain.

The address tables follow the IANA special-purpose address registries. They
are written out here rather than taken from :mod:`ipaddress` properties such as
``is_global``, whose answers changed between Python versions.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from .errors import NetworkError

Address = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network


class Zone(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    FORBIDDEN = "forbidden"


def _networks(*cidrs: str) -> tuple[Network, ...]:
    return tuple(ip_network(c) for c in cidrs)


# Never contacted, in any mode.
FORBIDDEN_NETWORKS = _networks(
    "0.0.0.0/8",          # "this network"
    "169.254.0.0/16",     # IPv4 link-local, including the cloud metadata service 169.254.169.254
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved, and the broadcast address 255.255.255.255
    "100.100.100.200/32", # Alibaba Cloud metadata service (inside the shared range 100.64.0.0/10)
    "168.63.129.16/32",   # Azure host services (a public address, special inside Azure)
    "192.0.0.192/32",     # Oracle Cloud metadata service (old address)
    "::/128",             # unspecified
    "100::/64",           # discard-only
    "fe80::/10",          # IPv6 link-local
    "ff00::/8",           # multicast
    "fd00:ec2::254/128",  # AWS metadata service over IPv6 (inside the private range fc00::/7)
)

# IPv4 ranges that are not reachable from the Internet (IANA, RFC 6890 and updates).
IPV4_NOT_PUBLIC = _networks(
    "10.0.0.0/8",         # private (RFC 1918)
    "100.64.0.0/10",      # shared address space, carrier-grade NAT (RFC 6598)
    "127.0.0.0/8",        # loopback
    "172.16.0.0/12",      # private (RFC 1918)
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # documentation (TEST-NET-1)
    "192.88.99.0/24",     # former 6to4 relay anycast
    "192.168.0.0/16",     # private (RFC 1918)
    "198.18.0.0/15",      # benchmarking
    "198.51.100.0/24",    # documentation (TEST-NET-2)
    "203.0.113.0/24",     # documentation (TEST-NET-3)
)

# Only global unicast IPv6 (2000::/3) is public, minus these special ranges.
IPV6_GLOBAL_UNICAST = ip_network("2000::/3")
IPV6_NOT_PUBLIC = _networks(
    "2001::/23",          # IETF protocol assignments, including Teredo (2001::/32)
    "2001:db8::/32",      # documentation
    "3fff::/20",          # documentation (RFC 9637)
)

# IPv6 prefixes that carry an IPv4 address the traffic is translated to.
NAT64_PREFIX = ip_network("64:ff9b::/96")  # well-known NAT64 prefix (RFC 6052)

# Ranges an internal perimeter may open. Loopback, link-local and the rest stay closed.
INTERNAL_RANGES = _networks(
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "100.64.0.0/10",                                  # RFC 6598, used inside some networks
    "fc00::/7",                                       # IPv6 unique local addresses (RFC 4193)
)

WEB_PORTS = frozenset({80, 443})


def _in_any(address: Address, networks: Iterable[Network]) -> bool:
    return any(address.version == n.version and address in n for n in networks)


def _translated_ipv4(address: IPv6Address) -> IPv4Address | None:
    """The IPv4 address an IPv6 address stands for, when it is a translation of one."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address in NAT64_PREFIX:
        return IPv4Address(int(address) & 0xFFFFFFFF)
    return address.sixtofour  # 2002::/16, None otherwise


def classify(address: Address) -> Zone:
    """The zone of an address (see the module documentation)."""
    if isinstance(address, IPv6Address):
        translated = _translated_ipv4(address)
        if translated is not None:
            zone = classify(translated)
            if address.ipv4_mapped is not None:
                return zone  # ::ffff:a.b.c.d *is* a.b.c.d for the operating system
            # A translator would carry the traffic to that IPv4 address: only a public one is acceptable.
            return Zone.PUBLIC if zone is Zone.PUBLIC else Zone.FORBIDDEN
    if _in_any(address, FORBIDDEN_NETWORKS):
        return Zone.FORBIDDEN
    if isinstance(address, IPv4Address):
        return Zone.INTERNAL if _in_any(address, IPV4_NOT_PUBLIC) else Zone.PUBLIC
    if address in IPV6_GLOBAL_UNICAST and not _in_any(address, IPV6_NOT_PUBLIC):
        return Zone.PUBLIC
    return Zone.INTERNAL


class DestinationBlocked(NetworkError):
    """A connection the egress policy refused. The check is reported as "not evaluated", with the reason.

    ``reason``: ``"forbidden"`` (never contacted), ``"private"`` (not public, Internet mode),
    ``"outside"`` (not in the internal perimeter) or ``"port"`` (port not allowed)."""

    def __init__(self, host: str, address: Address, port: int, reason: str):
        self.host = host
        self.address = address
        self.port = port
        self.reason = reason
        super().__init__(f"{host} ({address}) port {port}: destination blocked ({reason})")


@dataclass(frozen=True)
class EgressPolicy:
    """The addresses and ports a scan may connect to.

    The default policy is the Internet mode: public addresses, ports 80 and 443.
    An internal perimeter adds its ``networks`` and ``ports``. This class trusts
    whoever builds it: the networks an administrator may enter are validated by
    :func:`validate_internal_networks`."""

    networks: tuple[Network, ...] = ()
    ports: frozenset[int] = field(default=WEB_PORTS)
    name: str = ""  # name of the internal perimeter, for messages and logs

    @property
    def internal(self) -> bool:
        return bool(self.networks)

    def check(self, host: str, address: Address, port: int) -> None:
        """Raises :class:`DestinationBlocked` unless this connection is allowed."""
        zone = classify(address)
        if zone is Zone.FORBIDDEN:
            raise DestinationBlocked(host, address, port, "forbidden")
        if zone is Zone.INTERNAL and not self.covers(address):
            raise DestinationBlocked(host, address, port, "outside" if self.internal else "private")
        if port not in self.ports:
            raise DestinationBlocked(host, address, port, "port")

    def covers(self, address: Address) -> bool:
        """Whether ``address`` is in one of the perimeter's networks."""
        # An IPv4-mapped address is matched against the IPv4 networks of the perimeter.
        if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return _in_any(address, self.networks)


INTERNET = EgressPolicy()


def parse_address(text: str) -> Address | None:
    """The address written in ``text`` (``"192.0.2.1"``, ``"2001:db8::1"``), or None for a host name.

    Only the canonical notations count: ``"127.1"`` or ``"0x7f000001"`` are names
    for this module, and the resolver will find no such name."""
    try:
        return ip_address(text.strip("[]"))
    except ValueError:
        return None


def validate_internal_networks(lines: Iterable[str]) -> tuple[Network, ...]:
    """Networks typed by an administrator for an internal perimeter, checked.

    Each must lie inside :data:`INTERNAL_RANGES`, so a perimeter can open a part
    of the private network but never the loopback, the link-local range, the
    metadata services or the whole Internet. Raises ValueError with the faulty line."""
    networks = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            network = ip_network(text, strict=False)
        except ValueError:
            raise ValueError(text) from None
        if not any(network.version == r.version and network.subnet_of(r)  # type: ignore[arg-type]
                   for r in INTERNAL_RANGES):
            raise ValueError(text)
        networks.append(network)
    return tuple(networks)
