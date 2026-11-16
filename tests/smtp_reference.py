# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A reference corpus of SMTP worlds, and what the check decided on each (version 0.7, correction 2).

Recorded on integration/v0.7.0 at 0042c80, before the evidence of mail.smtp_starttls was bounded, into
tests/data/smtp-evidence-reference.json (``python tests/smtp_reference.py`` writes it again). The test
of the correction compares, world by world and field by field, what the check decides now with what it
decided then: the bounding is a matter of what the evidence keeps, never of the verdict.

The worlds: one per line of F05 and state of F06, then a hundred drawn with a fixed seed (MX, invalid
names, addresses, outcomes, certificates, policies, aliases), then the large ones of the review (4,000
addresses, a certificate of 1,001 names on 16 addresses, hundreds of silent MX, the MX named by F05.08
after MX beyond the sample, several collections at their limits at once). :func:`observed` reads what
is compared from a stored outcome, whatever the shape of its evidence (before or after the bounding).
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from worlds import DOMAIN, changed, healthy

DATA = Path(__file__).parent / "data" / "smtp-evidence-reference.json"
URL = f"https://mta-sts.{DOMAIN}/.well-known/mta-sts.txt"
CHECK = "mail.smtp_starttls"
REASONS = ["tls_verified", "tls_verified", "tls_verified", "starttls_absent", "certificate_refused", "timeout",
           "no_ipv6", "unreachable", "refused", "banner_refused", "ehlo_refused", "esmtp_altered",
           "starttls_temporary", "starttls_unavailable", "tls_handshake_error", "tls_version_refused",
           "malformed_reply", "closed", "deadline@banner", "timeout@ehlo", "policy"]


def mta_sts(names: list[str], mode: str | None) -> dict[str, Any]:
    """The answers of a policy in ``mode`` covering ``names`` ("missing": no record; "invalid": a faulty field;
    "unavailable": the file answers 404)."""
    if mode == "missing":
        return {"drop": True}
    if mode == "unavailable":
        return {URL: {"status": 404, "body": ""}}
    if mode == "invalid":
        return {URL: {"status": 200, "body": "version: STSv1\nmode: sometimes\nmx: *\nmax_age: 604800\n"}}
    lines = "".join(f"mx: {n}\n" for n in names)
    return {URL: {"status": 200, "body": f"version: STSv1\nmode: {mode}\n{lines}max_age: 604800\n"}}


def build(mx: list[tuple[int, str]], addresses: dict[str, list[str]], smtp: dict[str, dict],
          policy: str | None = "enforce", covered: list[str] | None = None, **dns: Any) -> dict:
    """The healthy domain with these MX records (preference, name), their addresses, what each answers, and
    a policy covering ``covered`` (every MX by default)."""
    records: dict[str, Any] = {f"{DOMAIN} MX": [f"{p} {n}." for p, n in mx]}
    for name, found in addresses.items():
        records[f"{name} A"] = [a for a in found if ":" not in a]
        records[f"{name} AAAA"] = [a for a in found if ":" in a]
    data = changed(healthy(), dns={**records, **dns})
    data["smtp"] = smtp
    answers = mta_sts(covered if covered is not None else [n for _, n in mx], policy)
    if answers.pop("drop", False):
        data["dns"].pop(f"_mta-sts.{DOMAIN} TXT")
    data["http"].update(answers)
    return data


def v4(i: int) -> str:
    return f"198.{18 + i // 65536}.{i // 256 % 256}.{i % 256}"


def v6(i: int) -> str:
    return f"2001:db8:ffff:ffff:ffff:ffff:{i // 65536:x}:{i % 65536:x}"


def certificate(days: int = 60, names: list[str] | None = None, reason: str = "tls_verified") -> dict:
    values: dict[str, Any] = {"expires_in_days": days}
    if names is not None:
        values["names"] = names
    return {"reason": reason, "certificate": values}


def refused_read() -> dict:
    return {"verify": {"reason": "certificate_refused", "verify_code": 62, "verify_message": "Hostname mismatch"},
            "read_certificate": "tls_unverified"}


def fixed() -> list[tuple[str, dict, bool]]:
    """One world per line of F05 and state of F06 (name, world, probe on)."""
    one = [(10, "mx.example.net")]
    a1 = {"mx.example.net": ["192.0.2.25"]}
    worlds: list[tuple[str, dict, bool]] = [
        ("F05.01 probe off", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}}), False),
        ("F05.02 no MX", build([], {}, {}, policy="missing"), True),
        ("F05.02 null MX", build([(0, "")], {}, {}, policy="missing", **{f"{DOMAIN} MX": ["0 ."]}), True),
        ("F05.03 STARTTLS absent", build(one, a1, {"mx.example.net": {"192.0.2.25": "starttls_absent"}}), True),
        ("F05.04 refused, enforce", build(one, a1, {"mx.example.net": {"192.0.2.25": refused_read()}}), True),
        ("F05.06 refused, testing", build(one, a1, {"mx.example.net": {"192.0.2.25": refused_read()}},
                                          policy="testing"), True),
        ("F05.06 refused, no policy", build(one, a1, {"mx.example.net": {"192.0.2.25": refused_read()}},
                                            policy="missing"), True),
        ("F05.07 expiring", build(one, a1, {"mx.example.net": {"192.0.2.25": certificate(15)}}), True),
        ("F05.07 urgent", build(one, a1, {"mx.example.net": {"192.0.2.25": certificate(4)}}), True),
        ("F05.08 timeout", build(one, a1, {"mx.example.net": {"192.0.2.25": "timeout"}}), True),
        ("F05.08 altered", build(one, a1, {"mx.example.net": {"192.0.2.25": "esmtp_altered"}}), True),
        ("F05.08 invalid MX", build([(10, "bad_name_.example")], {}, {}), True),
        ("F05.08 MX without address", build(one, {"mx.example.net": []}, {}), True),
        ("F05.09 IPv6 without route", build(one, {"mx.example.net": ["192.0.2.25", "2001:db8::25"]},
                                            {"mx.example.net": {"192.0.2.25": "tls_verified",
                                                                "2001:db8::25": "no_ipv6"}}), True),
        ("F05.10 OK enforce", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}}), True),
        ("F05.10 OK testing", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}},
                                    policy="testing"), True),
        ("F06 policy none", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}}, policy="none"), True),
        ("F06 policy invalid", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}},
                                     policy="invalid"), True),
        ("F06 policy unavailable", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}},
                                         policy="unavailable"), True),
        ("F06 MX uncovered", build([(10, "mx.example.net"), (20, "mx2.example.net")],
                                   {"mx.example.net": ["192.0.2.25"], "mx2.example.net": ["192.0.2.26"]},
                                   {"mx.example.net": {"192.0.2.25": "tls_verified"},
                                    "mx2.example.net": {"192.0.2.26": "tls_verified"}},
                                   covered=["mx.example.net"]), True),
        ("F06 MX alias", build(one, a1, {"mx.example.net": {"192.0.2.25": "tls_verified"}},
                               **{"mx.example.net CNAME": ["relay.example.org."]}), True),
    ]
    return worlds


def drawn(count: int = 100, seed: int = 20261109) -> list[tuple[str, dict, bool]]:
    """Worlds drawn with a fixed seed: MX (some invalid, some beyond the sample), addresses, outcomes,
    certificates expiring or not, policies of every mode, aliases."""
    rng = random.Random(seed)  # noqa: S311 - a fixed draw of test worlds, not a secret
    worlds = []
    for n in range(count):
        size = rng.choice([1, 1, 2, 2, 3, 4, 5, 8, 9, 12, 20])
        mx, addresses, smtp, dns = [], {}, {}, {}
        k = 0
        for i in range(size):
            if rng.random() < 0.12:
                mx.append((rng.randint(0, 50), f"bad{n}_{i}_.example"))
                continue
            name = f"mx{i}.w{n}.example.net"
            mx.append((rng.randint(0, 50), name))
            found = [v4(1000 * n + k + j) for j in range(rng.choice([0, 1, 1, 1, 2, 3]))]
            found += [v6(1000 * n + k + j) for j in range(rng.choice([0, 0, 1, 2]))]
            k += 10
            addresses[name] = found
            outcomes = {}
            for a in found:
                pick = rng.random()
                if pick < 0.08:
                    outcomes[a] = certificate(rng.choice([3, 12, 25, 90]))
                elif pick < 0.14:
                    outcomes[a] = refused_read()
                else:
                    outcomes[a] = rng.choice(REASONS)
            smtp[name] = outcomes
            if rng.random() < 0.06:
                dns[f"{name} CNAME"] = [f"relay{i}.w{n}.example.org."]
        policy = rng.choice(["enforce", "enforce", "testing", "none", "missing", "invalid", "unavailable"])
        names = [m for _, m in mx]
        covered = names if rng.random() < 0.8 else names[: max(1, len(names) // 2)]
        worlds.append((f"drawn {n}", build(mx, addresses, smtp, policy=policy, covered=covered, **dns), True))
    return worlds


def large() -> list[tuple[str, dict, bool]]:
    """The volumes of the review of the framing: each collection beyond its limit, alone and together."""
    mx1 = "mx.example.net"
    many = [v4(i) for i in range(4000)]
    sixteen = [v4(50000 + i) for i in range(16)]
    sans = [mx1] + [f"san{i:04d}.hosting.example" for i in range(1000)]
    silent = [(i + 1, f"silent{i:03d}_.example") for i in range(300)]
    resolved = {f"m{i}.example.net": [v4(60000 + i)] for i in range(8)}
    return [
        ("4,000 addresses on one MX", build([(10, mx1)], {mx1: many},
                                            {mx1: {a: "tls_verified" if a == many[0] else "timeout"
                                                   for a in many[:40]}}), True),
        ("1,001 certificate names on 16 addresses", build([(10, mx1)], {mx1: sixteen},
                                                          {mx1: {a: certificate(60, sans) for a in sixteen}}), True),
        ("300 silent MX", build([*silent, (500, mx1)], {mx1: ["192.0.2.25"]},
                                {mx1: {"192.0.2.25": "tls_verified"}}), True),
        ("F05.08 named after the sample", build(
            [(i + 1, f"m{i}.example.net") for i in range(8)] + [(9 + i, f"s{i}.example.net") for i in range(30)]
            + [(50, "bad_name_.example")], resolved,
            {name: {a: "deadline@banner" for a in found} for name, found in resolved.items()}), True),
        ("several limits at once", build(
            [(1, mx1)] + [(i + 2, f"x{i}_.example") for i in range(200)] + [(300 + i, f"far{i}.example.net")
                                                                          for i in range(40)],
            {mx1: sixteen + many[:500]},
            {mx1: {a: certificate(5, sans) if i % 2 else refused_read() for i, a in enumerate(sixteen)}},
            policy="testing", covered=[mx1] + [f"far{i}.example.net" for i in range(40)],
            **{f"{mx1} CNAME": [f"alias{i}.example.org." for i in range(10)]}), True),
    ]


def corpus() -> list[tuple[str, dict, bool]]:
    return fixed() + drawn() + large()


def observed(outcome: dict[str, Any]) -> dict[str, Any]:
    """What the reference compares of one stored outcome (``Finding.outcome_json()``), whatever the shape of
    its evidence: the verdict, F06, the real counts, and every attempt with what it showed."""
    evidence = outcome.get("evidence", {})
    readiness = evidence.get("readiness") or {}
    policy = readiness.get("policy") or {}
    rows = [(m.get("name"), a) for m in evidence.get("mx", []) for a in m.get("addresses", [])]
    counts = (evidence.get("counts") or {}).get("addresses")
    seen = ({k: counts.get(k, 0) for k in ("verified", "starttls_absent", "certificate_refused", "unmeasured")}
            if isinstance(counts, dict) else
            {k: sum(a.get("seen") == k for _, a in rows)
             for k in ("verified", "starttls_absent", "certificate_refused", "unmeasured")})
    attempted = sorted([name, a.get("address"), a.get("seen"), a.get("unmeasured", ""),
                        [o.get("purpose") for o in a.get("observations", [])]]
                       for name, a in rows if a.get("observations") or a.get("interrupted"))
    silent = evidence.get("silent_mx")

    def total(key: str) -> int | None:
        found = policy.get(key)
        return None if found is None else len(found) + int(policy.get(f"{key}_omitted", 0))

    return {
        "status": outcome.get("status"), "summary": outcome.get("summary"), "params": outcome.get("params"),
        "remedy": outcome.get("remedy"), "signals": outcome.get("signals", []), "rule": evidence.get("rule"),
        "probe_enabled": evidence.get("probe_enabled"),
        "readiness": {"state": readiness.get("state"), "causes": readiness.get("causes"),
                      "policy": policy.get("state")},
        "policy_lists": {k: total(k) for k in ("covered", "uncovered", "mx_patterns")},
        "exhaustivity": evidence.get("exhaustivity"), "seen": seen, "attempted": attempted,
        "silent_mx": None if silent is None else len(silent) + int(evidence.get("silent_mx_omitted", 0)),
        "notes": [[n.get("key"), (n.get("params") or {}).get("n")] for n in evidence.get("notes", [])],
    }


def outcome_of(world: dict, probe: bool) -> dict[str, Any]:
    from worlds import scan_smtp

    findings, _ = scan_smtp(world, CHECK, probe=probe)
    finding = findings[CHECK]
    return {"status": finding.status.value, **finding.outcome_json()}


def scored(world: dict, probe: bool) -> dict[str, Any]:
    """The whole scan of a world: the score, the grade, the status of every check and the measurement scope."""
    from posture_cockpit.core import scoring
    from posture_cockpit.core.compare import measurement_scope
    from worlds import scan_smtp

    findings, _ = scan_smtp(world, probe=probe)
    result = scoring.assess(list(findings.values()))
    return {"score": result.score, "grade": result.grade, "statuses": {k: f.status.value for k, f in findings.items()},
            "scope": measurement_scope(findings[CHECK].outcome.evidence, internal=False)}


def record() -> dict[str, Any]:
    worlds = {name: observed(outcome_of(world, probe)) for name, world, probe in corpus()}
    scans = {name: scored(world, probe) for name, world, probe in fixed()}
    return {"recorded_on": "0042c801e0e093683067c94ad9990a3cbd9c7024", "worlds": worlds, "scans": scans}


def write(reference: dict[str, Any]) -> None:
    """One line per world, so that a change shows as the lines of the worlds it changes."""
    lines = [f' "recorded_on": {json.dumps(reference["recorded_on"])}']
    for section in ("worlds", "scans"):
        entries = [f"  {json.dumps(k)}: {json.dumps(v, sort_keys=True)}" for k, v in sorted(reference[section].items())]
        lines.append(f' {json.dumps(section)}: {{\n' + ",\n".join(entries) + "\n }")
    DATA.write_text("{\n" + ",\n".join(lines) + "\n}\n")


if __name__ == "__main__":
    write(record())
    found = json.loads(DATA.read_text())
    print(f"{DATA}: {len(found['worlds'])} worlds, {len(found['scans'])} scans")
