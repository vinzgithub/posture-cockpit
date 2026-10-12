# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""DNS hosts: which one serves a domain, and where its settings are.

The plan gives step-by-step instructions for the DNS host of the domain. The
host is recognised from the name servers (NS records); the user can pick
another one on the page. The steps themselves are texts in the locale files,
under ``dnshost.<id>.*``.

Adding a DNS host: add a :class:`DnsHost` below and its texts in every
locale file (the test ``test_every_dns_host_has_its_texts`` lists them).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class DnsHost:
    id: str
    name: str
    ns_suffixes: tuple[str, ...]  # name servers ending with one of these belong to this host


DNS_HOSTS = (
    DnsHost("ovh", "OVHcloud", ("ovh.net", "ovh.ca", "anycast.me")),
    DnsHost("gandi", "Gandi", ("gandi.net",)),
    DnsHost("ionos", "IONOS", ("ui-dns.com", "ui-dns.org", "ui-dns.de", "ui-dns.biz")),
    DnsHost("cloudflare", "Cloudflare", ("ns.cloudflare.com",)),
)
# Generic instructions, for every other host.
OTHER = DnsHost("other", "", ())


def by_id(host_id: str) -> DnsHost:
    return next((h for h in DNS_HOSTS if h.id == host_id), OTHER)


def detect(nameservers: Iterable[str]) -> DnsHost | None:
    """The host most of these name servers belong to, or None when none is known."""
    votes: dict[str, int] = {}
    for ns in nameservers:
        ns = ns.lower().rstrip(".")
        for host in DNS_HOSTS:
            if any(ns == s or ns.endswith("." + s) for s in host.ns_suffixes):
                votes[host.id] = votes.get(host.id, 0) + 1
    if not votes:
        return None
    return by_id(max(votes, key=lambda host_id: votes[host_id]))
