# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Reading the mail records the checks look at: SPF, DMARC, DKIM, MTA-STS, TLS-RPT.

Pure functions, without network: each one says what a record means and what
in it breaks its RFC. The checks (mail.py) decide what that is worth.

A word on strictness. Where an RFC says a receiver must reject the record
(an unknown SPF mechanism, a DMARC record that does not start with
``v=DMARC1``), the record is reported as invalid. Where it says a faulty value
is ignored and the default used (DMARC ``pct=abc``), the record still works,
but the fault is reported so that it can be fixed.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from ipaddress import ip_network
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key


def tags(record: str) -> list[tuple[str, str]]:
    """``"v=DMARC1; p=none"`` → ``[("v", "DMARC1"), ("p", "none")]``: names in lower case, in order.

    The tag-list syntax shared by DMARC, DKIM, MTA-STS and TLS-RPT records."""
    found = []
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if sep and name.strip():
            found.append((name.strip().lower(), value.strip()))
    return found


# ======================================================================== SPF
# RFC 7208. https://www.rfc-editor.org/rfc/rfc7208
SPF_MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
SPF_DNS_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})  # each costs a DNS lookup (§4.6.4)
_MODIFIER = re.compile(r"[a-z][a-z0-9_.-]*=", re.IGNORECASE)
_CIDR = re.compile(r"(?://\d{1,3}|/\d{1,2}(?://\d{1,3})?)?")


def is_spf(record: str) -> bool:
    return record.lower() == "v=spf1" or record.lower().startswith("v=spf1 ")


@dataclass(frozen=True)
class SpfTerm:
    qualifier: str   # "+", "-", "~" or "?" for mechanisms; "" for modifiers
    name: str        # mechanism or modifier name, lower case
    value: str       # what follows ":" (mechanism) or "=" (modifier)
    modifier: bool


@dataclass(frozen=True)
class Spf:
    terms: tuple[SpfTerm, ...]
    errors: tuple[str, ...]  # terms that make every receiver answer "permerror"

    @property
    def all_qualifier(self) -> str | None:
        """Qualifier of the "all" mechanism ("-", "~", "?", "+"), None when there is none."""
        return next((t.qualifier for t in self.terms if not t.modifier and t.name == "all"), None)

    @property
    def redirect(self) -> str | None:
        """The redirect target; ignored by receivers when the record has an "all" mechanism."""
        if self.all_qualifier is not None:
            return None
        return next((t.value for t in self.terms if t.modifier and t.name == "redirect"), None)

    @property
    def includes(self) -> list[str]:
        return [t.value for t in self.terms if not t.modifier and t.name == "include"]

    @property
    def lookups(self) -> int:
        """DNS lookups this record needs by itself, not counting the records it includes."""
        return sum(1 for t in self.terms if not t.modifier and t.name in SPF_DNS_MECHANISMS) + bool(self.redirect)

    @property
    def uses_ptr(self) -> bool:
        return any(not t.modifier and t.name == "ptr" for t in self.terms)


def parse_spf(record: str) -> Spf:
    """The terms of an SPF record (which must start with ``v=spf1``), and its syntax errors."""
    terms: list[SpfTerm] = []
    errors: list[str] = []
    seen_modifiers: set[str] = set()
    for text in record.split()[1:]:
        if _MODIFIER.match(text):
            name, _, value = text.partition("=")
            name = name.lower()
            if name in ("redirect", "exp"):
                if name in seen_modifiers or not value:
                    errors.append(text)  # §6: each at most once, and with a domain
                seen_modifiers.add(name)
            terms.append(SpfTerm("", name, value, modifier=True))  # unknown modifiers are ignored (§6)
            continue
        qualifier, body = (text[0], text[1:]) if text[0] in "+-~?" else ("+", text)
        match = re.fullmatch(r"([a-z0-9]+)([:/].*)?", body, re.IGNORECASE)
        name, rest = (match.group(1).lower(), match.group(2) or "") if match else (body.lower(), "?")
        if name not in SPF_MECHANISMS or not _mechanism_value_ok(name, rest):
            errors.append(text)  # §5: an unknown mechanism, or a bad argument, is a permerror
            continue
        terms.append(SpfTerm(qualifier, name, rest[1:] if rest.startswith(":") else rest, modifier=False))
    return Spf(tuple(terms), tuple(errors))


def _mechanism_value_ok(name: str, rest: str) -> bool:
    """Whether what follows a mechanism name (``":domain/24"``, ``""``…) is acceptable (§5)."""
    if name == "all":
        return rest == ""
    if name in ("include", "exists"):
        return rest.startswith(":") and len(rest) > 1
    if name == "ptr":
        return rest == "" or (rest.startswith(":") and len(rest) > 1)
    if name in ("a", "mx"):
        domain, slash, cidr = rest.partition("/")
        if domain and (not domain.startswith(":") or len(domain) == 1):
            return False
        return bool(_CIDR.fullmatch(slash + cidr))
    if name in ("ip4", "ip6"):
        if not rest.startswith(":"):
            return False
        try:
            network = ip_network(rest[1:], strict=False)
        except ValueError:
            return False
        return network.version == (4 if name == "ip4" else 6)
    return False


# ====================================================================== DMARC
# RFC 9989, §4.7 and §4.10 (tags and discovery). https://www.rfc-editor.org/rfc/rfc9989
DMARC_POLICIES = ("none", "quarantine", "reject")
_URI = re.compile(r"[a-z][a-z0-9+.-]*:\S+", re.IGNORECASE)


@dataclass(frozen=True)
class Dmarc:
    tags: dict[str, str]
    starts_right: bool                    # the record begins with v=DMARC1 (otherwise it is discarded)
    policy: str | None                    # p: none, quarantine, reject; absent defaults to none
    subdomain_policy: str | None          # sp, or p when sp is absent
    pct: int                              # 100 when absent or invalid; see below
    rua: tuple[str, ...]
    errors: tuple[tuple[str, str], ...]   # (tag, value) that do not follow the RFC
    psd: str = "u"                        # y: public suffix; n: explicitly organizational; u: unspecified
    non_existent_policy: str | None = None  # np, when given; None means use sp/p
    testing: bool = False                 # t=y: requested reduced enforcement


def is_dmarc_candidate(record: str) -> bool:
    """A TXT record at _dmarc that tries to be a DMARC record, well-formed or not."""
    return "v=dmarc1" in record.replace(" ", "").lower()


def parse_dmarc(record: str) -> Dmarc:
    pairs = tags(record)
    values = dict(pairs)
    starts_right = bool(pairs) and pairs[0] == ("v", "DMARC1")
    errors: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, value in pairs:
        if name in seen:
            errors.append((name, value))
        seen.add(name)

    def policy_tag(name: str) -> str | None:
        value = values.get(name)
        if value is None:
            return None
        if value.lower() in DMARC_POLICIES:
            return value.lower()
        errors.append((name, value))
        return None

    # RFC 9989 §4.7: an omitted p tag means monitoring, not invalid syntax.
    policy = policy_tag("p") if "p" in values else "none"
    subdomain_policy = policy_tag("sp") if "sp" in values else policy
    non_existent_policy = policy_tag("np") if "np" in values else None
    psd = values.get("psd", "u").lower()
    if psd not in ("y", "n", "u"):
        errors.append(("psd", values["psd"]))
        psd = "u"
    testing = values.get("t", "n").lower() == "y"
    if values.get("t", "n").lower() not in ("y", "n"):
        errors.append(("t", values["t"]))

    # pct (RFC 7489 §6.3) was removed by RFC 9989, which replaces it with t=y. Receivers that
    # still follow RFC 7489 apply it, so it is read: a value below 100 means a partial policy
    # for them, and a value that is not an integer from 0 to 100 is a faulty record.
    pct = 100
    if "pct" in values:
        raw = values["pct"]
        if raw.isascii() and raw.isdigit() and len(raw) <= 3 and int(raw) <= 100:  # 1*3DIGIT
            pct = int(raw)
        else:
            errors.append(("pct", raw))

    for name, allowed in (("adkim", ("r", "s")), ("aspf", ("r", "s"))):
        if name in values and values[name].lower() not in allowed:
            errors.append((name, values[name]))
    if "fo" in values and not all(token.strip().lower() in ("0", "1", "d", "s") for token in values["fo"].split(":")):
        errors.append(("fo", values["fo"]))

    rua: list[str] = []
    for name in ("rua", "ruf"):
        for uri in (u.strip() for u in values.get(name, "").split(",") if u.strip()):
            if not _URI.fullmatch(uri) or (uri.lower().startswith("mailto:") and "@" not in uri):
                errors.append((name, uri))
            elif name == "rua":
                rua.append(uri)
    return Dmarc(values, starts_right, policy, subdomain_policy, pct, tuple(rua), tuple(errors),
                 psd, non_existent_policy, testing)


# ======================================================================= DKIM
# RFC 6376 §3.6.1 (key records), RFC 8463 (Ed25519), RFC 8301 (key sizes).
@dataclass(frozen=True)
class DkimKey:
    key_type: str     # "rsa" or "ed25519" (or the unknown value of k=)
    bits: int         # key size; 0 when unreadable
    revoked: bool     # "p=" empty: the key was withdrawn on purpose
    readable: bool    # the key data decodes to a key of the announced type


def parse_dkim(record: str) -> DkimKey | None:
    """The key published in a DKIM record, or None when the record is not a DKIM key record."""
    pairs = tags(record)
    values = dict(pairs)
    if "p" not in values:
        return None
    if "v" in values and (pairs[0][0] != "v" or values["v"] != "DKIM1"):
        return DkimKey(values.get("k", "rsa").lower(), 0, revoked=False, readable=False)
    key_type = values.get("k", "rsa").lower()
    data = re.sub(r"\s", "", values["p"])
    if not data:
        return DkimKey(key_type, 0, revoked=True, readable=False)
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error):
        return DkimKey(key_type, 0, revoked=False, readable=False)
    if key_type == "ed25519":
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            return DkimKey(key_type, 0, revoked=False, readable=False)
        return DkimKey(key_type, 256, revoked=False, readable=True)
    if key_type != "rsa":
        return DkimKey(key_type, 0, revoked=False, readable=False)
    try:
        key = load_der_public_key(raw)  # SubjectPublicKeyInfo, or a bare RSAPublicKey
    except (ValueError, TypeError):
        return DkimKey(key_type, 0, revoked=False, readable=False)
    if not isinstance(key, rsa.RSAPublicKey):
        return DkimKey(key_type, 0, revoked=False, readable=False)
    return DkimKey(key_type, key.key_size, revoked=False, readable=True)


# ==================================================================== MTA-STS
# RFC 8461 §3.1 (TXT record), §3.2 (policy file), §4.1 (MX matching).
MTA_STS_MODES = ("enforce", "testing", "none")
MTA_STS_MAX_AGE = 31_557_600


_STS_SEP = r"[ \t]*;[ \t]*"                                                    # sts-sep
_STS_FIELD = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]+"      # sts-id or sts-extension


def mta_sts_record_ok(record: str) -> bool:
    """§3.1: ``v=STSv1`` first (case matters), then ``;``-separated fields: exactly one ``id`` of
    1 to 32 letters and digits, and any extension fields (``name=value``), which senders ignore."""
    if not re.fullmatch(rf"v=STSv1(?:{_STS_SEP}{_STS_FIELD})+(?:{_STS_SEP})?", record):
        return False
    fields = [field.partition("=") for field in re.split(_STS_SEP, record)[1:] if field]
    ids = [value for name, _sep, value in fields if name == "id"]
    return len(ids) == 1 and bool(re.fullmatch(r"[A-Za-z0-9]{1,32}", ids[0]))


@dataclass(frozen=True)
class MtaStsPolicy:
    mode: str                 # "" when missing or invalid
    mx: tuple[str, ...]       # patterns: "mx.example.org" or "*.example.org"
    max_age: int | None
    errors: tuple[str, ...]   # names of the fields that are missing or invalid


def parse_mta_sts_policy(body: str) -> MtaStsPolicy:
    fields: dict[str, list[str]] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    errors = []
    if fields.get("version") != ["STSv1"]:
        errors.append("version")
    mode = fields.get("mode", [""])[0].lower()
    if len(fields.get("mode", [])) != 1 or mode not in MTA_STS_MODES:
        errors.append("mode")
        mode = ""
    max_age = None
    raw_age = fields.get("max_age", [""])
    if len(raw_age) == 1 and raw_age[0].isdigit() and int(raw_age[0]) <= MTA_STS_MAX_AGE:
        max_age = int(raw_age[0])
    else:
        errors.append("max_age")
    mx = tuple(p.lower().rstrip(".") for p in fields.get("mx", []))
    hostname = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
    if (mode in ("enforce", "testing") and not mx) or any(
        not re.fullmatch(r"(?:\*\.)?" + hostname, pattern) for pattern in mx
    ):
        errors.append("mx")
    return MtaStsPolicy(mode, mx, max_age, tuple(errors))


def mx_matches(pattern: str, host: str) -> bool:
    """§4.1: an exact name, or ``*.`` standing for exactly one leftmost label."""
    host = host.lower().rstrip(".")
    if pattern.startswith("*."):
        label, _, rest = host.partition(".")
        return bool(label) and rest == pattern[2:]
    return host == pattern


# ==================================================================== TLS-RPT
# RFC 8460 §3.
def tls_rpt_problems(record: str) -> list[str]:
    """Validate the DNS TLS-RPT policy syntax (RFC 8460 §3).

    An unrelated TXT at the reserved name is ignored by the caller, but
    malformed TLSRPT candidates are never silently treated as absent.
    RFC 8460 explicitly permits unknown *valid* extension fields and
    multiple rua destinations.
    """
    problems: list[str] = []
    parts = record.split(";")
    if parts and not parts[-1].strip():
        parts.pop()  # one optional final field delimiter
    if not parts or parts[0].rstrip(" \t") != "v=TLSRPTv1":  # field-delim = *WSP ";" *WSP
        problems.append("v")
    if not parts or any(not part.strip() for part in parts):
        problems.append("syntax")

    destinations: list[str] = []
    version_count = 0
    rua_count = 0
    for part in parts:
        name, separator, value = part.strip().partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", name):
            problems.append("syntax")
            continue
        if name == "v":
            version_count += 1
            if value != "TLSRPTv1":
                problems.append("v")
        elif name == "rua":
            rua_count += 1
            destinations.extend(item.strip() for item in value.split(","))
        elif not value or re.search(r"[\x00-\x20;=]", value):
            # Unknown extensions are allowed, but must be syntactically valid.
            problems.append(name)

    if version_count != 1:
        problems.append("v")
    if not rua_count or not destinations or any(not item for item in destinations):
        problems.append("rua")

    for uri in destinations:
        # RFC 8460 §3: commas, exclamation marks and semicolons in URI
        # components must be percent-encoded, not embedded literally.
        if not uri or re.search(r"[\x00-\x20,!;]", uri):
            problems.append("rua")
            continue
        try:
            parsed = urlsplit(uri)
        except ValueError:
            problems.append("rua")
            continue
        if parsed.scheme == "mailto":
            address = uri[len("mailto:"):]
            if not re.fullmatch(r"[^@/?#\s]+@[^@/?#\s]+", address):
                problems.append("rua")
        elif parsed.scheme == "https":
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                problems.append("rua")
        else:
            problems.append("rua")
    return list(dict.fromkeys(problems))
