# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""One SMTP dialogue up to TLS, on a connection already open to one address of a published MX (version 0.7).

What it is for
--------------
A sending mail server that applies MTA-STS (RFC 8461) connects to port 25 of a
published MX host, asks for TLS with ``STARTTLS``, and checks the certificate
against the MX name. :func:`run_dialogue` asks exactly that, once, and records
what happened step by step in an :class:`Attempt`.

An :class:`Attempt` is an *observation*: where the dialogue stopped
(:class:`Stage`), why (:class:`Reason`), and the evidence read on the way. It is
never a verdict. Turning observations into a status (OK, WARN, FAIL, ERROR, NA)
belongs to the one decision function of the SMTP check (matrix F05 of the
specification), and to nothing here.

The steps, in this order, with the same names in the code, the evidence and the
messages (specification, F02 and Q03)::

    BANNER  ->  EHLO  ->  STARTTLS  ->  TLS  ->  QUIT

- ``BANNER``: read the whole greeting, every ``220-`` line up to the final
  ``220 `` line, before saying anything. Some servers (postscreen, for one)
  delay their greeting on purpose and treat a client that speaks first as a
  spammer (RFC 5321 §3.1 and §4.2).
- ``EHLO``: introduce the probe with the name the administrator configured
  (``POSTURE_COCKPIT_SMTP_EHLO_NAME``, checked at start) and read the
  extensions the server announces (RFC 5321 §4.1.1.1). ``STARTTLS`` is sent only
  if announced (RFC 3207 §2).
- ``STARTTLS``: RFC 3207 §4 defines three replies (220, 501, 454); every reply
  is put in one of the categories of table R3 (decision D2b).
- ``TLS``: negotiate with :func:`public_smtp_context`, the MX name as SNI and as
  the name the certificate must carry; a failure is put in one of the
  categories of table R1 (decision D1b).
- ``QUIT``: say goodbye, at once. After TLS the probe does not send ``EHLO``
  again: RFC 3207 §4.2 asks it of a client that *continues* the session, §4.1
  asks a client that stops to send ``QUIT`` right after the negotiation, and the
  probe stops there (R10).

A dialogue is *nominal* when the greeting is a complete ``220``, the reply to
``EHLO`` a well-formed ``250``, the extensions show no sign of alteration, and
every reply follows the grammar of RFC 5321 §4.2. Only a nominal dialogue may
end with :attr:`Reason.STARTTLS_ABSENT`, the one observation that may later be
judged a failure of the server.

Why the probe stays passive
---------------------------
It sends ``EHLO``, ``STARTTLS`` and ``QUIT``, and nothing else: no ``AUTH``,
``MAIL``, ``RCPT`` or ``DATA``. It never tries to deliver, relay, authenticate or
discover recipients (specification, S04). One function writes to the server,
:meth:`_Dialogue._send`, and it takes a :class:`Command`, not a text.

Why no socket is opened here
----------------------------
This module receives a connection, it does not make one. The network layer
opens it to an address it has checked against its own rules (published MX of
the audited domain, public address, port 25), then hands it over; that layer
also bounds the connection itself (5 seconds, R11). So nothing here can be
pointed at another destination, and the dialogue can be tested against a
server on the loopback address without any network rule.

Bounds
------
Every limit is a named constant below, with the reason for its value. Each
stage reads its whole reply within its own time limit (R11), itself capped by
the ``deadline`` the caller gives: the dialogue returns its observation before
that instant, whatever the server does. Replies are read line by line into a
buffer that never holds more than :data:`MAX_LINE_BYTES`. What is kept as
evidence is short and cleaned (:data:`EVIDENCE_LINES`, :data:`EVIDENCE_CHARS`,
printable ASCII only): a greeting is text chosen by the remote server, and it
ends up in pages, reports and logs.

References
----------
- RFC 5321, SMTP: §2.3.8 (lines end with CR LF), §3.1 (the greeting; a 554
  greeting still waits for ``QUIT``), §4.1.1.1 (``EHLO`` and its reply),
  §4.1.1.10 (``QUIT``), §4.2 (reply grammar: a code, ``-`` on every line but the
  last, the same code on every line), §4.5.3.1.5 (512 octets per reply line),
  §4.5.3.2 (client timeouts, minutes long: far beyond what a scan can wait).
- RFC 3207, STARTTLS: §2 (the ``STARTTLS`` keyword), §4 (replies 220, 501 and
  454), §4.1 (``QUIT`` right after the negotiation), §4.2 (session reset after
  TLS), §6 (what was learnt before TLS may have been altered).
- RFC 3463, enhanced status codes: §2 (``class.subject.detail``), §3.8 (``X.7.Y``,
  security or policy).
- RFC 8461, MTA-STS: §4.1 (MX host validation: a chain to a trusted root, not
  expired, a subject alternative name DNS-ID matching the MX host).
- RFC 6125: §6.4.3 (wildcards, leftmost label only), §6.4.4 (the common name is
  not used when a DNS-ID is required).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
from dataclasses import dataclass
from enum import StrEnum

# Shared rather than copied: host names are checked by the rule the configuration applies at start,
# and the certificate is read exactly as the HTTPS checks read theirs.
from ..config import check_host_name
from .network import Certificate, _parse_certificate

# ------------------------------------------------------------------ time limits (R11)
# Each one bounds a whole stage, its write and its complete reply, and is itself capped by the
# caller's deadline, which the caller derives from the check's time limit: min(12 s, CHECK_TIMEOUT - 2 s) (F02).
BANNER_SECONDS = 10.0  # the whole greeting: postscreen and similar delay it by about 6 s on purpose (F02)
REPLY_SECONDS = 5.0    # the complete reply to EHLO, and to STARTTLS
TLS_SECONDS = 5.0      # the TLS negotiation
QUIT_SECONDS = 2.0     # the reply to QUIT, best effort: the probe owes the server a QUIT, not a wait

# ------------------------------------------------------------------ size limits
# Twice the 512 octets of RFC 5321 §4.5.3.1.5, CR LF included: tolerant of servers that exceed the
# standard a little, still small. The read buffer never holds more than this.
MAX_LINE_BYTES = 1024
# Lines of one reply. An EHLO reply has about 10 to 20 in practice; a reply longer than this is
# not an SMTP server answering a probe. With MAX_LINE_BYTES, it bounds a reply to 32 KiB.
MAX_REPLY_LINES = 32
EVIDENCE_LINES = 4     # lines of a reply kept in the observation (the EHLO keywords are kept apart)
EVIDENCE_CHARS = 200   # characters kept of each line, and of a technical detail

# ------------------------------------------------------------------ reply grammar (RFC 5321 §4.2)
_CODE = re.compile(rb"[2-5][0-5][0-9]")  # Reply-code = %x32-35 %x30-35 %x30-39
# Enhanced status code at the start of the text (RFC 3463 §2): class.subject.detail.
_ENHANCED = re.compile(rb"([245])\.([0-9]{1,3})\.([0-9]{1,3})(?=[ \t]|$)")
# An extension keyword made of X's, maybe with one last letter: "XXXXXXXA" is how some inspecting
# firewalls (Cisco ESMTP inspection, for one) mask STARTTLS. It points to an inspection on the path,
# not to a given product, and keywords that merely start with X (XCLIENT, XFORWARD) do not match.
_MASKED = re.compile(r"X{4,}[A-Z]?")

# ------------------------------------------------------------------ TLS failures (R1, D1b)
# The server refused TLS 1.2 and 1.3: an alert "protocol version", or a reply in an older version.
_VERSION_REFUSED = frozenset({"TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL", "VERSION_TOO_LOW"})
# What came back is not TLS at all: usually an SMTP reply in the clear, read as a TLS record.
_NOT_TLS = frozenset({"WRONG_VERSION_NUMBER"})
_EOF = frozenset({"UNEXPECTED_EOF_WHILE_READING"})
# OpenSSL's X509_V_FLAG_NO_CHECK_TIME (x509_vfy.h), which Python does not name: certificate dates not
# checked. A context with it does not verify what RFC 8461 §4.1 requires (a certificate not expired).
_NO_CHECK_TIME = 0x200000

__all__ = [
    "BANNER_SECONDS", "EVIDENCE_CHARS", "EVIDENCE_LINES", "MAX_LINE_BYTES", "MAX_REPLY_LINES", "QUIT_SECONDS",
    "REPLY_SECONDS", "TLS_SECONDS", "Attempt", "Command", "Reason", "Reply", "Stage", "proves_trust",
    "public_smtp_context", "run_dialogue", "starttls_refusal", "tls_failure",
]


class Stage(StrEnum):
    """The steps of the dialogue, in their order (Q03)."""

    BANNER = "banner"
    EHLO = "ehlo"
    STARTTLS = "starttls"
    TLS = "tls"
    QUIT = "quit"


class Command(StrEnum):
    """Everything the probe may say to a server (S04)."""

    EHLO = "EHLO"
    STARTTLS = "STARTTLS"
    QUIT = "QUIT"


class Reason(StrEnum):
    """How a dialogue ended: an observation, never a verdict.

    Each reason belongs to the stage where it is observed (:attr:`Attempt.stage`);
    the last six can happen at any stage."""

    # The dialogue went through: TLS negotiated, then QUIT.
    TLS_VERIFIED = "tls_verified"        # with a verifying context: chain and MX name checked
    TLS_UNVERIFIED = "tls_unverified"    # with a context that verifies nothing: TLS works, trust unknown
    # BANNER
    BANNER_REFUSED = "banner_refused"    # a greeting other than 220: 421, 554… (F02 bis)
    # EHLO
    EHLO_REFUSED = "ehlo_refused"        # a reply other than 250
    ESMTP_ALTERED = "esmtp_altered"      # masked extensions (XXXXXXXA): STARTTLS not sent
    STARTTLS_ABSENT = "starttls_absent"  # nominal dialogue, STARTTLS not announced
    # STARTTLS (table R3, decision D2b)
    STARTTLS_TEMPORARY = "starttls_temporary"            # 4xx, 454 included
    STARTTLS_POLICY_REFUSAL = "starttls_policy_refusal"  # 5.7.x, 530, 550, 554: a refusal of the prober
    STARTTLS_UNAVAILABLE = "starttls_unavailable"        # 500 or 502, although announced
    STARTTLS_DIALOGUE_ERROR = "starttls_dialogue_error"  # 501, 503, 504, any other code, a malformed reply
    # TLS (table R1, decision D1b)
    CERTIFICATE_REFUSED = "certificate_refused"  # chain, dates or name refused: verify_code, verify_message
    TLS_VERSION_REFUSED = "tls_version_refused"  # TLS 1.2 and 1.3 refused; older ones are never offered
    TLS_DIALOGUE_ERROR = "tls_dialogue_error"    # bytes that are not TLS (a reply in the clear)
    TLS_HANDSHAKE_ERROR = "tls_handshake_error"  # any other alert or failure of the negotiation
    # Any stage
    MALFORMED_REPLY = "malformed_reply"    # outside the grammar of RFC 5321 §4.2
    REPLY_TOO_LARGE = "reply_too_large"    # beyond MAX_LINE_BYTES or MAX_REPLY_LINES
    UNSOLICITED_DATA = "unsolicited_data"  # the server sent more than the reply asked for
    CLOSED = "closed"                      # the server closed the connection (or reset it)
    TIMEOUT = "timeout"                    # the stage's own time limit (R11) ran out
    DEADLINE = "deadline"                  # the caller's deadline came first


@dataclass(frozen=True)
class Reply:
    """One complete SMTP reply, as kept in the evidence: bounded and cleaned."""

    code: int
    text: tuple[str, ...]  # the first EVIDENCE_LINES lines, without their code
    lines: int             # how many lines the reply had
    enhanced: str = ""     # enhanced status code of the last line ("5.7.1"), when it starts with one


@dataclass(frozen=True)
class Attempt:
    """What one dialogue with one address observed: facts only (see the module documentation).

    ``stage`` is the stage where the dialogue stopped, :attr:`Stage.QUIT` when it went
    through. Fields of the stages not reached keep their default value."""

    mx_name: str                          # the published MX host: SNI and name the certificate must carry
    stage: Stage
    reason: Reason
    banner: Reply | None = None
    ehlo: Reply | None = None
    capabilities: tuple[str, ...] = ()    # EHLO keywords, upper case, in the server's order
    altered: tuple[str, ...] = ()         # keywords that look masked on the path (XXXXXXXA)
    starttls: Reply | None = None         # the reply to STARTTLS
    tls_version: str = ""                 # negotiated, e.g. "TLSv1.3"
    tls_cipher: str = ""
    certificate: Certificate | None = None  # read once negotiated; trusted only with a verifying context
    verify_code: int | None = None        # OpenSSL's code when the certificate was refused (10: expired…)
    verify_message: str = ""
    detail: str = ""                      # technical detail of the stop: OpenSSL reason, rule broken…
    partial: tuple[str, ...] = ()         # lines of a reply cut short (closed, timeout, deadline, malformed)
    quit_reply: int | None = None         # code of the reply to QUIT, when one came

    @property
    def starttls_offered(self) -> bool:
        return Command.STARTTLS.value in self.capabilities


def public_smtp_context() -> ssl.SSLContext:
    """The TLS context of the SMTP probe: what a sending server applying MTA-STS checks (RFC 8461 §4.1).

    - The system's public certificate authorities, and only them. It takes no argument: the
      perimeter's own authority (``trusted_ca``) is never added, because the question is whether
      senders on the Internet would trust this MX, not whether this network does.
    - A certificate is required, and checked against the name given as SNI, which the caller
      sets to the published MX host (never the target of a CNAME).
    - ``hostname_checks_common_name = False``: the name must be a DNS-ID of the subject alternative
      name, as RFC 8461 §4.1 requires. Python accepts the common name by default, so a certificate
      naming the MX in its CN only would otherwise pass (RFC 6125 §6.4.4).
    - TLS 1.2 at least. TLS 1.0 and 1.1 are never offered by the probe, not even to confirm that a
      server speaks nothing newer (decision D1b): a refusal of 1.2 and 1.3 is observed as such.

    The flags :func:`ssl.create_default_context` sets by version (Python 3.13 adds strict checks)
    are those of the HTTPS checks, kept as they are."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.hostname_checks_common_name = False
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def starttls_refusal(reply: Reply) -> Reason | None:
    """The category of a complete reply to STARTTLS (table R3, decision D2b); None when ready (220).

    RFC 3207 §4 defines three replies: 220, 501 and 454. Anything else is outside that grammar.
    An explicit security or policy code (RFC 3463 §3.8) is read before the basic code, because it
    says more: a server that refuses the prober by policy, whatever it says about the command."""
    code = reply.code
    if code == 220:
        return None
    if 400 <= code < 500:
        return Reason.STARTTLS_TEMPORARY
    if code >= 500 and (reply.enhanced.startswith("5.7.") or code in (530, 550, 554)):
        return Reason.STARTTLS_POLICY_REFUSAL
    if code in (500, 502):
        return Reason.STARTTLS_UNAVAILABLE  # announced, then "unknown command" or "not implemented"
    return Reason.STARTTLS_DIALOGUE_ERROR   # 501, 503, 504, another 5xx, a 2xx or 3xx other than 220


def tls_failure(error: BaseException) -> tuple[Reason, str]:
    """The category of a failed TLS negotiation (table R1, decision D1b), and its technical detail.

    A timeout is not handled here: the stage decides between its own limit and the deadline."""
    if isinstance(error, ssl.SSLCertVerificationError):
        return Reason.CERTIFICATE_REFUSED, _cut(error.verify_message or str(error))
    if isinstance(error, ssl.SSLError):
        reason = getattr(error, "reason", None) or ""
        if isinstance(error, ssl.SSLEOFError | ssl.SSLZeroReturnError) or reason in _EOF:
            return Reason.CLOSED, "closed during the TLS negotiation"
        if reason in _VERSION_REFUSED:
            return Reason.TLS_VERSION_REFUSED, reason.lower()
        if reason in _NOT_TLS:
            return Reason.TLS_DIALOGUE_ERROR, reason.lower()
        return Reason.TLS_HANDSHAKE_ERROR, _cut(reason.lower() or str(error))
    if isinstance(error, (ConnectionError, EOFError)):  # reset, aborted, broken pipe, incomplete read
        # asyncio reports a server that closes during the negotiation as a reset without errno.
        return Reason.CLOSED, "closed during the TLS negotiation"
    return Reason.TLS_HANDSHAKE_ERROR, _cut(f"{error.__class__.__name__} {error}".strip())


def proves_trust(context: ssl.SSLContext) -> bool:
    """Whether a negotiation with ``context`` proves the certificate (True) or only reads it (False).

    Two kinds of context are accepted, and nothing in between (F03):

    - one that verifies what MTA-STS requires (RFC 8461 §4.1): a certificate required
      (``CERT_REQUIRED``), its chain and dates checked, and the MX name checked
      (``check_hostname``) as a DNS-ID of the subject alternative name only
      (``hostname_checks_common_name = False``). :func:`public_smtp_context` is one;
    - one that verifies nothing (``CERT_NONE``, no name check), to read a certificate already
      refused. A negotiation with it never claims trust: :attr:`Reason.TLS_UNVERIFIED`.

    A context halfway (the common name accepted, a certificate optional, dates not checked, no
    name check) would make a certificate that MTA-STS refuses, one naming the MX in its CN only
    for instance, look verified: it raises ValueError. So does any context that would accept a
    version older than TLS 1.2 (decision D1b). Which authorities a context trusts is the caller's
    choice: :func:`public_smtp_context` takes the system's only."""
    if context.minimum_version < ssl.TLSVersion.TLSv1_2:
        raise ValueError("SMTP dialogue: the TLS context must not offer versions older than TLS 1.2")
    if (context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            and not context.hostname_checks_common_name and not context.verify_flags & _NO_CHECK_TIME):
        return True
    if context.verify_mode == ssl.CERT_NONE and not context.check_hostname:
        return False
    raise ValueError("SMTP dialogue: the TLS context must verify as MTA-STS does (certificate required, "
                     "dates and name checked, no common name) or verify nothing")


async def run_dialogue(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, mx_name: str,
                       ehlo_name: str, tls_context: ssl.SSLContext, deadline: float) -> Attempt:
    """One dialogue on a connection already open to port 25 of one address of ``mx_name``.

    ``mx_name``: the published MX host, as the DNS gives it; it is the TLS SNI and the name the
    certificate must carry, never replaced by the target of a CNAME. ``ehlo_name``: the probe's
    configured name. Both are checked by :func:`~posture_cockpit.config.check_host_name` (a fully
    qualified ASCII host name) and used in lower case, without the root's dot; the caller can run
    the same check on an MX name before connecting. ``tls_context``: one of the two kinds
    :func:`proves_trust` accepts. ``deadline``: an instant of the running loop's clock
    (``loop.time()``); the observation is returned before it.

    The connection belongs to the dialogue from now on: it is always closed when this returns.
    Raises ValueError, before anything is sent, for an invalid name or context. A cancellation is
    not caught."""
    try:
        name = check_host_name(mx_name, "SMTP dialogue, MX name")
        ehlo = check_host_name(ehlo_name, "SMTP dialogue, EHLO name")
        verifies = proves_trust(tls_context)
        return await _Dialogue(reader, writer, name, ehlo, tls_context, verifies, deadline).run()
    finally:
        # No close_notify, no wait for the server: the dialogue is over, and the deadline holds.
        writer.transport.abort()


# ------------------------------------------------------------------ the dialogue itself
class _Stop(Exception):
    """The dialogue stops here, for ``reason``. ``quit``: the connection is still in a clean
    state in the clear, after a complete reply, so a QUIT may be sent before closing."""

    def __init__(self, reason: Reason, detail: str = "", *, quit: bool = False):
        super().__init__(reason.value)
        self.reason, self.detail, self.quit = reason, _cut(detail), quit


@dataclass
class _Received:
    """A complete reply, before it is cut down to evidence."""

    code: int
    texts: list[bytes]

    def evidence(self) -> Reply:
        match = _ENHANCED.match(self.texts[-1])
        # The class of an enhanced code must be the first digit of the reply code to mean anything.
        enhanced = match.group(0).decode("ascii") if match and int(match.group(1)) == self.code // 100 else ""
        return Reply(self.code, tuple(_clean(t) for t in self.texts[:EVIDENCE_LINES]), len(self.texts), enhanced)


class _Dialogue:
    """The state of one dialogue: the connection, the read buffer, and what was observed so far."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, mx_name: str, ehlo_name: str,
                 tls_context: ssl.SSLContext, verifies: bool, deadline: float):
        self._reader, self._writer = reader, writer
        self._mx_name, self._ehlo_name = mx_name, ehlo_name
        self._context, self._deadline = tls_context, deadline
        self._verifies = verifies  # proves_trust(tls_context): trust is claimed only when it was checked
        self._loop = asyncio.get_running_loop()
        self._buffer = bytearray()          # bytes read, not yet made into lines
        self._partial: list[bytes] = []     # lines of the reply being read
        self.stage = Stage.BANNER
        self.banner: Reply | None = None
        self.ehlo: Reply | None = None
        self.capabilities: tuple[str, ...] = ()
        self.altered: tuple[str, ...] = ()
        self.starttls: Reply | None = None
        self.tls_version = self.tls_cipher = ""
        self.certificate: Certificate | None = None
        self.verify_code: int | None = None
        self.verify_message = ""
        self.quit_reply: int | None = None

    async def run(self) -> Attempt:
        try:
            await self._steps()
        except _Stop as stop:
            partial = tuple(_clean(line) for line in self._partial[:EVIDENCE_LINES])
            if stop.quit:
                await self._quit()
            return self._attempt(self.stage, stop.reason, stop.detail, partial)
        await self._quit()  # over TLS (R10: QUIT right after the negotiation, no EHLO)
        return self._attempt(Stage.QUIT, Reason.TLS_VERIFIED if self._verifies else Reason.TLS_UNVERIFIED)

    async def _steps(self) -> None:
        """BANNER -> EHLO -> STARTTLS -> TLS, top to bottom; each refusal stops at its own stage."""
        banner = await self._exchange(Stage.BANNER, BANNER_SECONDS, None)
        self.banner = banner.evidence()
        self._lockstep()
        if banner.code != 220:
            # 421 or 554 instead of 220 (RFC 5321 §3.1): a refusal of the prober, which says nothing of TLS.
            # After a 554 the server waits for QUIT; after a 421 it closes, and QUIT costs nothing.
            raise _Stop(Reason.BANNER_REFUSED, quit=True)

        ehlo = await self._exchange(Stage.EHLO, REPLY_SECONDS, Command.EHLO)
        self.ehlo = ehlo.evidence()
        self._lockstep()
        if ehlo.code != 250:
            raise _Stop(Reason.EHLO_REFUSED, quit=True)
        self.capabilities, self.altered = _capabilities(ehlo.texts)
        if self.altered:
            # Something on the path rewrote the extensions: neither the presence nor the absence of
            # STARTTLS can be read from them (RFC 3207 §6). STARTTLS is not sent: what would answer
            # it might be the inspecting device, not the server.
            raise _Stop(Reason.ESMTP_ALTERED, ", ".join(self.altered), quit=True)
        if Command.STARTTLS.value not in self.capabilities:
            raise _Stop(Reason.STARTTLS_ABSENT, quit=True)

        try:
            reply = await self._exchange(Stage.STARTTLS, REPLY_SECONDS, Command.STARTTLS)
            self.starttls = reply.evidence()
            self._lockstep()
        except _Stop as stop:
            if stop.reason in (Reason.MALFORMED_REPLY, Reason.REPLY_TOO_LARGE, Reason.UNSOLICITED_DATA):
                # Table R3: a malformed reply to STARTTLS is a dialogue error. Bytes after a 220
                # are worse than malformed: they would be read as if they came over TLS (RFC 3207 §6).
                raise _Stop(Reason.STARTTLS_DIALOGUE_ERROR, stop.detail) from None
            raise
        refusal = starttls_refusal(self.starttls)
        if refusal is not None:
            raise _Stop(refusal, quit=True)

        await self._negotiate()

    async def _exchange(self, stage: Stage, seconds: float, command: Command | None) -> _Received:
        """One stage in the clear or over TLS: the command, if any, then its complete reply, in ``seconds``."""
        self.stage = stage
        limit, capped = self._limit(seconds)
        try:
            async with asyncio.timeout(limit):
                if command is not None:
                    await self._send(command)
                received = await self._read_reply()
        except TimeoutError:  # before OSError: TimeoutError is one of them
            raise _Stop(Reason.DEADLINE if capped else Reason.TIMEOUT, f"no complete reply within {limit:.1f} s")\
                from None
        except (OSError, EOFError) as e:  # reset while writing or reading
            raise _Stop(Reason.CLOSED, e.__class__.__name__) from None
        return received

    def _lockstep(self) -> None:
        """Nothing may follow a complete reply: SMTP is one reply per command (RFC 5321 §4.2), and
        bytes the server sent unasked would be read as its reply to the next command."""
        if self._buffer:
            raise _Stop(Reason.UNSOLICITED_DATA, f"{len(self._buffer)} bytes after the reply: {_clean(self._buffer)}")

    async def _send(self, command: Command) -> None:
        """Writes one command: the only place in this module that sends anything to the server.

        It takes a :class:`Command`, never a text: EHLO, STARTTLS and QUIT are all the probe may
        say, so it can neither deliver, relay nor authenticate (S04). The EHLO argument is the
        configured name, checked at start and again in :func:`run_dialogue`, so no space, CR or LF
        can reach the wire."""
        text = f"{command.value} {self._ehlo_name}" if command is Command.EHLO else command.value
        self._writer.write(text.encode("ascii") + b"\r\n")
        await self._writer.drain()

    async def _read_reply(self) -> _Received:
        """Every line of one reply, up to its last one (RFC 5321 §4.2), within MAX_REPLY_LINES."""
        self._partial = []
        texts: list[bytes] = []
        code = 0
        while True:
            line = await self._read_line()
            self._partial.append(line)
            number, last, text = _parse_line(line)
            if texts and number != code:
                raise _Stop(Reason.MALFORMED_REPLY, f"code {number} after {code} in one reply (RFC 5321 §4.2)")
            code = number
            texts.append(text)
            if last:
                self._partial = []
                return _Received(code, texts)
            if len(texts) >= MAX_REPLY_LINES:
                raise _Stop(Reason.REPLY_TOO_LARGE, f"more than {MAX_REPLY_LINES} lines in one reply")

    async def _read_line(self) -> bytes:
        """One line, its CR LF removed. The buffer never holds more than MAX_LINE_BYTES of it."""
        while (end := self._buffer.find(b"\n")) < 0:
            room = MAX_LINE_BYTES - len(self._buffer)
            if room <= 0:
                raise _Stop(Reason.REPLY_TOO_LARGE, f"a reply line longer than {MAX_LINE_BYTES} bytes")
            data = await self._reader.read(room)
            if not data:
                if self._buffer:
                    self._partial.append(bytes(self._buffer))
                raise _Stop(Reason.CLOSED, "closed in the middle of a reply" if self._partial
                            else "closed before replying")
            self._buffer += data
        line = bytes(self._buffer[:end + 1])
        del self._buffer[:end + 1]
        if not line.endswith(b"\r\n"):
            self._partial.append(line)
            raise _Stop(Reason.MALFORMED_REPLY, "a reply line ends without CR LF (RFC 5321 §2.3.8)")
        return line[:-2]

    async def _negotiate(self) -> None:
        """The TLS negotiation, the MX name as SNI and as the name to check (RFC 8461 §4.1)."""
        self.stage = Stage.TLS
        limit, capped = self._limit(TLS_SECONDS)
        try:
            async with asyncio.timeout(limit):
                await self._writer.start_tls(self._context, server_hostname=self._mx_name)
        except TimeoutError:
            raise _Stop(Reason.DEADLINE if capped else Reason.TIMEOUT, f"no negotiation within {limit:.1f} s")\
                from None
        except (OSError, EOFError) as e:  # ssl.SSLError is an OSError
            if isinstance(e, ssl.SSLCertVerificationError):
                self.verify_code, self.verify_message = e.verify_code, _cut(e.verify_message or "")
            reason, detail = tls_failure(e)
            # After a failed negotiation, nothing more is said, not even QUIT: the connection is in no
            # known state, and a command in the clear would go where TLS was expected.
            raise _Stop(reason, detail) from None
        ssl_object = self._writer.get_extra_info("ssl_object")
        self.tls_version = ssl_object.version() or ""
        self.tls_cipher = (ssl_object.cipher() or ("",))[0]
        der = ssl_object.getpeercert(binary_form=True)
        if der:
            with contextlib.suppress(ValueError):  # a certificate cryptography cannot read: none kept
                self.certificate = _parse_certificate(self._mx_name, der, self.tls_version, trusted=self._verifies)

    async def _quit(self) -> None:
        """QUIT, best effort: never past the deadline, and its outcome changes nothing observed before."""
        limit = min(QUIT_SECONDS, self._deadline - self._loop.time())
        if limit <= 0:
            return
        with contextlib.suppress(_Stop, OSError, EOFError):  # TimeoutError and ssl.SSLError are OSErrors
            async with asyncio.timeout(limit):
                await self._send(Command.QUIT)
                self.quit_reply = (await self._read_reply()).code

    def _limit(self, seconds: float) -> tuple[float, bool]:
        """The time a stage may take, and whether the deadline is what limits it."""
        remaining = self._deadline - self._loop.time()
        if remaining <= 0:
            raise _Stop(Reason.DEADLINE, "the deadline came before this stage")
        return min(seconds, remaining), remaining < seconds

    def _attempt(self, stage: Stage, reason: Reason, detail: str = "", partial: tuple[str, ...] = ()) -> Attempt:
        return Attempt(
            mx_name=self._mx_name, stage=stage, reason=reason, banner=self.banner, ehlo=self.ehlo,
            capabilities=self.capabilities, altered=self.altered, starttls=self.starttls,
            tls_version=self.tls_version, tls_cipher=self.tls_cipher, certificate=self.certificate,
            verify_code=self.verify_code, verify_message=self.verify_message, detail=detail, partial=partial,
            quit_reply=self.quit_reply)


# ------------------------------------------------------------------ pure helpers
def _parse_line(line: bytes) -> tuple[int, bool, bytes]:
    """(code, is the last line, text) of one reply line without its CR LF (RFC 5321 §4.2)."""
    if not _CODE.fullmatch(line[:3]):
        raise _Stop(Reason.MALFORMED_REPLY, f"not a reply line: {_clean(line)}")
    separator, text = line[3:4], line[4:]
    if separator == b"-":
        last = False
    elif separator in (b" ", b""):  # "250" alone ends a reply too: clients must accept it (§4.2)
        last = True
    else:
        raise _Stop(Reason.MALFORMED_REPLY, f"no space or hyphen after the code: {_clean(line)}")
    # textstring is tabs and printable characters. Control characters are refused: they have no
    # place in a reply and only serve to forge log lines. Bytes above 127 are tolerated (some
    # greetings carry an accent, and SMTPUTF8 servers may send UTF-8); the evidence replaces them.
    if any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in text):
        raise _Stop(Reason.MALFORMED_REPLY, "a control character in a reply line")
    return int(line[:3]), last, text


def _capabilities(texts: list[bytes]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The extension keywords of an EHLO reply, and those that look masked (RFC 5321 §4.1.1.1).

    The first line names the server; each other line starts with a keyword, case-insensitive.
    The keyword grammar is not enforced: old servers still announce "AUTH=LOGIN"."""
    keywords = tuple(_clean(text.split()[0]).upper() for text in texts[1:] if text.split())
    return keywords, tuple(keyword for keyword in keywords if _MASKED.fullmatch(keyword))


def _clean(raw: bytes | bytearray) -> str:
    """Printable ASCII only, cut to EVIDENCE_CHARS: what a remote server wrote, made safe to keep."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else " " if b == 0x09 else "?" for b in raw[:EVIDENCE_CHARS])


def _cut(text: str) -> str:
    return text[:EVIDENCE_CHARS]
