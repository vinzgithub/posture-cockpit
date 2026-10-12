# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Internal perimeters: the parts of a private network an administrator opens to scans.

A perimeter names the networks a scan may reach (inside the private ranges
only, see :func:`~posture_cockpit.core.egress.validate_internal_networks`), the
DNS servers that know the internal names, the ports of the internal sites,
and the certificate authority that signs their certificates.

A domain attached to a perimeter is scanned with that perimeter's rule, and
only administrators see it. The feature as a whole stays off until the
instance is started with ``POSTURE_COCKPIT_INTERNAL_SCANS=1``.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass

from cryptography import x509

from ..core.egress import EgressPolicy, Network, Zone, classify, parse_address, validate_internal_networks
from .database import Database, Row, utcnow

MAX_NETWORKS = 50
MAX_NAMESERVERS = 4
MAX_PORTS = 10
MAX_PEM = 100_000
DEFAULT_PORTS = "443 80"


class PerimeterError(ValueError):
    """A field of the perimeter form is not acceptable. ``key`` is the text explaining why."""

    def __init__(self, field: str, key: str, value: str = ""):
        self.field = field
        self.key = key
        self.value = value
        super().__init__(f"{field}: {key} {value}".strip())


@dataclass(frozen=True)
class Perimeter:
    id: int
    name: str
    networks: tuple[Network, ...]
    nameservers: tuple[str, ...]
    ports: frozenset[int]
    ca_pem: str
    created_at: str

    def policy(self) -> EgressPolicy:
        return EgressPolicy(networks=self.networks, ports=self.ports, name=self.name)

    @property
    def ca_subjects(self) -> list[str]:
        """Names of the certificate authorities trusted in this perimeter, for display."""
        if not self.ca_pem:
            return []
        return [c.subject.rfc4514_string() for c in x509.load_pem_x509_certificates(self.ca_pem.encode())]


@dataclass(frozen=True)
class PerimeterForm:
    """What an administrator typed, checked and normalized (see :func:`parse_form`)."""

    name: str
    networks: str
    nameservers: str
    ports: str
    ca_pem: str


def _items(text: str) -> list[str]:
    return [item for item in re.split(r"[\s,;]+", text) if item]


def parse_form(name: str, networks: str, nameservers: str, ports: str, ca_pem: str) -> PerimeterForm:
    """Checks a perimeter typed by an administrator. Raises :class:`PerimeterError`."""
    name = name.strip()
    if not 1 <= len(name) <= 60:
        raise PerimeterError("name", "error.perimeter_name")

    items = _items(networks)
    if not 1 <= len(items) <= MAX_NETWORKS:
        raise PerimeterError("networks", "error.perimeter_networks_count", str(MAX_NETWORKS))
    try:
        parsed = validate_internal_networks(items)
    except ValueError as e:
        raise PerimeterError("networks", "error.perimeter_network", str(e)) from None

    servers = _items(nameservers)
    if len(servers) > MAX_NAMESERVERS:
        raise PerimeterError("nameservers", "error.perimeter_nameservers_count", str(MAX_NAMESERVERS))
    for server in servers:
        address = parse_address(server)
        if address is None or classify(address) is Zone.FORBIDDEN:
            raise PerimeterError("nameservers", "error.perimeter_nameserver", server)

    port_items = _items(ports) or _items(DEFAULT_PORTS)
    if len(port_items) > MAX_PORTS or not all(p.isdigit() and 1 <= int(p) <= 65535 for p in port_items):
        raise PerimeterError("ports", "error.perimeter_ports", str(MAX_PORTS))

    pem = ca_pem.strip()
    if pem:
        if len(pem) > MAX_PEM:
            raise PerimeterError("ca_pem", "error.perimeter_ca")
        try:
            if not x509.load_pem_x509_certificates(pem.encode()):
                raise ValueError("no certificate")
            ssl.create_default_context().load_verify_locations(cadata=pem)  # what the scans will do
        except (ValueError, ssl.SSLError):
            raise PerimeterError("ca_pem", "error.perimeter_ca") from None
        pem += "\n"

    return PerimeterForm(name=name, networks="\n".join(str(n) for n in parsed),
                         nameservers="\n".join(str(parse_address(s)) for s in servers),
                         ports=" ".join(str(p) for p in sorted({int(p) for p in port_items})), ca_pem=pem)


def _perimeter(row: Row) -> Perimeter:
    return Perimeter(
        id=row["id"], name=row["name"],
        # Stored values were validated when saved; validating again guards against a hand-edited database.
        networks=validate_internal_networks(row["networks"].splitlines()),
        nameservers=tuple(_items(row["nameservers"])),
        ports=frozenset(int(p) for p in _items(row["ports"])),
        ca_pem=row["ca_pem"], created_at=row["created_at"])


class Perimeters:
    def __init__(self, db: Database):
        self.db = db

    def all(self) -> list[tuple[Perimeter, int]]:
        """Every perimeter, with the number of domains attached to it."""
        rows = self.db.all("SELECT p.*, (SELECT COUNT(*) FROM domains d WHERE d.perimeter_id = p.id) AS domains "
                           "FROM perimeters p ORDER BY lower(p.name)")
        return [(_perimeter(r), int(r["domains"])) for r in rows]

    def get(self, perimeter_id: int | None) -> Perimeter | None:
        if perimeter_id is None:
            return None
        row = self.db.one("SELECT * FROM perimeters WHERE id = ?", (perimeter_id,))
        return _perimeter(row) if row else None

    def name_taken(self, name: str, except_id: int | None = None) -> bool:
        return self.db.one("SELECT 1 FROM perimeters WHERE lower(name) = lower(?) AND id IS NOT ?",
                           (name, except_id)) is not None

    def create(self, form: PerimeterForm, user_id: int | None) -> int:
        cur = self.db.execute(
            "INSERT INTO perimeters(name, networks, nameservers, ports, ca_pem, created_at, created_by)"
            " VALUES(?, ?, ?, ?, ?, ?, ?)",
            (form.name, form.networks, form.nameservers, form.ports, form.ca_pem, utcnow(), user_id))
        return int(cur.lastrowid or 0)

    def update(self, perimeter_id: int, form: PerimeterForm) -> None:
        self.db.execute("UPDATE perimeters SET name = ?, networks = ?, nameservers = ?, ports = ?, ca_pem = ? "
                        "WHERE id = ?", (form.name, form.networks, form.nameservers, form.ports, form.ca_pem,
                                         perimeter_id))

    def domains(self, perimeter_id: int) -> list[Row]:
        return self.db.all("SELECT * FROM domains WHERE perimeter_id = ? ORDER BY name", (perimeter_id,))

    def delete(self, perimeter_id: int) -> bool:
        """Deletes a perimeter that no domain uses any more; False when some still do."""
        if self.domains(perimeter_id):
            return False
        self.db.execute("DELETE FROM perimeters WHERE id = ?", (perimeter_id,))
        return True
