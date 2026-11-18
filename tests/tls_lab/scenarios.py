# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The catalogue of the bench: scenarios.json, read and built (version 0.8.0, PR-A).

Each scenario says what a server answers to one offer, and what a correct reading of that answer is. It is
the oracle any prober will be held to (the prototype of PR-A2, the prober of PR-C):

- ``offer``: what the prober offered (versions, categories of suites, groups). Its ``offer_class`` is
  ``modern`` when everything offered is what a recent client could offer, ``legacy`` as soon as one element
  belongs to old protocols or weak suites (precision 2 of the review of R1: the standard level of the audit
  never sends a legacy offer; the extended level does, only to the domains listed by the administrator).
- ``reply``: the behaviour of the responder and the recipe of the bytes it sends. The bytes are built by
  wire.py from fixed values; ``sha256`` pins them, so the catalogue is the same on every run and machine.
- ``expected``: the facts the strict reader must find (``facts``), or ``null`` when the bytes are not
  readable (``cause`` then says why), and the level of evidence the facts support:

  - ``announced``: a ServerHello or a HelloRetryRequest chose this version, suite or group, for this offer;
  - ``alert_refusal``: an alert ``handshake_failure``, ``protocol_version`` or ``insufficient_security``.
    It becomes a refusal *of this offer* only if a control offer got an announced choice from the same
    address in the same scan (R1 §3); never a definitive refusal of the version or of the suite;
  - ``inconclusive``: any other alert, a close, a reset, a silence, bytes that cannot be read.

- ``fleets``: addresses that answer the same to some offers and differently to another (precision 1 of the
  review of R1): a result is the result of the address that gave it, never copied to another address,
  however alike their other answers.

``python -m tls_lab.scenarios`` (with ``tests`` on the path) prints the fingerprints, to pin a deliberate
change of a recipe.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import wire

CATALOGUE = Path(__file__).with_name("scenarios.json")
EVIDENCE = ("announced", "alert_refusal", "inconclusive")
CLASSES = ("modern", "legacy")
REFUSALS = frozenset({"handshake_failure", "protocol_version", "insufficient_security"})


def _int(value: Any) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


def _message(spec: list, version: int) -> bytes:
    """One handshake message of a recipe; ``version`` is the version the ServerHello chose."""
    name, args = spec[0], (spec[1] if len(spec) > 1 else {})
    if name == "server_hello":
        return wire.server_hello(_int(args["suite"]), version=_int(args.get("version", 0x0303)))
    if name == "server_hello_13":
        return wire.server_hello_13(_int(args["suite"]), _int(args["group"]))
    if name == "hello_retry_request":
        return wire.hello_retry_request(_int(args["suite"]), _int(args["group"]))
    if name == "certificate":
        return wire.certificate(wire.fixed("certificate", 600))
    if name == "ecdhe":
        return wire.ecdhe_key_exchange(_int(args["group"]), int(args["point"]), version)
    if name == "dhe":
        return wire.dhe_key_exchange(int(args["bits"]), signed=bool(args.get("signed", True)), version=version)
    if name == "done":
        return wire.server_hello_done()
    raise ValueError(f"unknown message {name}")


def build(reply: dict[str, Any], catalogue: dict[str, dict] | None = None) -> bytes:
    """The bytes of a reply recipe."""
    if "messages" in reply:
        version = _int(reply.get("record_version", 0x0303))
        chosen = next((_int(m[1].get("version", 0x0303)) for m in reply["messages"] if m[0] == "server_hello"), 0x0303)
        return wire.flight(*(_message(m, chosen) for m in reply["messages"]), version=version,
                           split=int(reply.get("split", 0)))
    if "alert" in reply:
        code = {name: code for code, name in wire.ALERTS.items()}[reply["alert"]]
        return wire.alert(code, level=int(reply.get("level", 2)))
    if "ascii" in reply:
        return reply["ascii"].encode("ascii")
    if "oversize" in reply:
        return wire.record(wire.HANDSHAKE, b"\x02" + wire.fixed("oversize", int(reply["oversize"]) - 1))
    if "record" in reply:  # a record of another type
        return wire.record(_int(reply["record"]), bytes.fromhex(reply.get("hex", "01")))
    if "of" in reply:      # derived from another scenario: truncated, patched, extended
        assert catalogue is not None
        base = build(catalogue[reply["of"]]["reply"], catalogue)
        if "keep" in reply:
            base = base[: int(reply["keep"])]
        if "patch" in reply:
            at, data = int(reply["patch"][0]), bytes.fromhex(reply["patch"][1])
            base = base[:at] + data + base[at + len(data):]
        if "append" in reply:
            base += bytes.fromhex(reply["append"])
        return base
    if reply.get("behaviour") in ("close", "reset", "silence"):
        return b""
    raise ValueError(f"unknown reply {reply}")


@dataclass(frozen=True)
class Scenario:
    id: str
    family: str
    offer: dict[str, Any]
    offer_class: str
    behaviour: str
    reply: dict[str, Any]
    expected: dict[str, Any]
    sha256: str
    data: bytes

    def facts(self) -> dict[str, Any] | None:
        return self.expected.get("facts")


def load() -> tuple[list[Scenario], list[dict[str, Any]]]:
    raw = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    by_id = {s["id"]: s for s in raw["scenarios"]}
    scenarios = []
    for s in raw["scenarios"]:
        data = build(s["reply"], by_id)
        scenarios.append(Scenario(s["id"], s["family"], s["offer"], s["offer_class"],
                                  s["reply"].get("behaviour", "reply"), s["reply"], s["expected"], s["sha256"], data))
    return scenarios, raw["fleets"]


def classify(offer: dict[str, Any]) -> str:
    """modern or legacy, from what the offer holds (precision 2)."""
    legacy = (set(offer.get("versions", [])) & wire.LEGACY_VERSIONS
              or set(offer.get("categories", [])) & wire.LEGACY_CATEGORIES
              or set(offer.get("groups", [])) & wire.LEGACY_GROUPS)
    return "legacy" if legacy else "modern"


def facts_of(facts: wire.Facts) -> dict[str, Any]:
    """The reader's facts in the vocabulary of the catalogue."""
    out: dict[str, Any] = {"kind": facts.kind}
    if facts.version:
        out["version"] = facts.version
    if facts.kind != "alert" and facts.suite is not None:
        out["suite"] = f"0x{facts.suite:04X}"
    if facts.group is not None:
        out["group"] = f"0x{facts.group:04X}"
    if facts.dh_bits is not None:
        out["dh_bits"] = facts.dh_bits
    if facts.alert:
        out["alert"] = facts.alert
        out["level"] = facts.alert_level
    return out


def fingerprint(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":  # print the fingerprints of the recipes
    found, _ = load()
    for scenario in found:
        actual = fingerprint(scenario.data)
        mark = "" if actual == scenario.sha256 else "  <- differs from the catalogue"
        sys.stdout.write(f"{scenario.id} {actual}{mark}\n")
