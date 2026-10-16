# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Local HTTPS observations. Historical announcements never change a verdict."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


def max_age(header: str) -> int | None:
    for directive in header.split(',')[0].split(';'):
        name, _, value = directive.strip().partition('=')
        if name.lower() == 'max-age':
            value = value.strip().strip('"')
            if not value.isascii() or not value.isdigit():
                return None
            digits = value.lstrip("0") or "0"
            return 365 * 86400 if len(digits) > 8 else min(int(digits), 365 * 86400)
    return None


def summarize(events: list[tuple[str, dict]], now: datetime) -> dict[str, dict[str, Any]]:
    """Replay oldest first. Missing/invalid headers do not erase a prior valid policy."""
    hosts: dict[str, dict[str, Any]] = {}
    for at, observations in sorted(events, key=lambda event: datetime.fromisoformat(event[0])):
        date = datetime.fromisoformat(at)
        if date > now:
            continue
        for host, observation in observations.items():
            state = hosts.setdefault(host, {})
            if observation.get('available'):
                state['last_available'] = at
            # All headers retained here have been received over authenticated modern TLS.
            for header in observation.get('hsts', []):
                age = max_age(header)
                if age is None:
                    continue
                if age == 0:
                    state.pop('hsts', None)
                    state.pop('preload', None)
                else:
                    state['preload'] = any(d.strip().lower() == 'preload'
                                           for d in header.split(',')[0].split(';'))
                    state['hsts'] = {'header': header, 'at': at,
                                     'expires_at': (date + timedelta(seconds=age)).isoformat(),
                                     'include_subdomains': any(d.strip().lower() == 'includesubdomains'
                                                               for d in header.split(';'))}
    for state in hosts.values():
        if state.get('hsts') and datetime.fromisoformat(state['hsts']['expires_at']) <= now:
            state.pop('hsts')
    return hosts


def announced(host: str, history: dict, now: datetime) -> dict:
    """Exact host, or an unexpired includeSubDomains policy on an ancestor."""
    found = dict(history.get(host, {}))
    found.pop('hsts', None)  # Revalidate expiry at the scan clock, even for an older snapshot.
    labels = host.split('.')
    for i in range(len(labels)):
        name = '.'.join(labels[i:])
        policy = history.get(name, {}).get('hsts')
        if (policy and datetime.fromisoformat(policy['expires_at']) > now
                and (name == host or policy['include_subdomains'])):
            found['hsts'] = {**policy, 'source': name}
            break
    return found


def compact(events: list[tuple[str, dict]]) -> list[dict]:
    """At most two dated observations per host: last interpretable HSTS and last availability.

    Keep zero max-age as a tombstone and retain the original date, including for expired
    policies. Expiry is applied at read time; a missing header never renews its lifetime.
    """
    policies: dict[str, tuple[str, str]] = {}
    available: dict[str, str] = {}
    for at, observations in sorted(events, key=lambda event: datetime.fromisoformat(event[0])):
        for host, observation in observations.items():
            if observation.get("available"):
                available[host] = at
            for header in observation.get("hsts", []):
                if max_age(header) is not None:
                    policies[host] = (at, header)
    grouped: dict[str, dict] = {}
    for host, (at, header) in policies.items():
        grouped.setdefault(at, {}).setdefault(host, {})["hsts"] = [header]
    for host, at in available.items():
        grouped.setdefault(at, {}).setdefault(host, {})["available"] = True
    return [{"at": at, "observation": observation} for at, observation in sorted(
        grouped.items(), key=lambda item: datetime.fromisoformat(item[0]))]
