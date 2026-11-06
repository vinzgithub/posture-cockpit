# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The SMTP dialogue of the probe (core/smtp.py, version 0.7), against fake servers on this machine.

Every test talks to the fake server of :mod:`smtp_servers`, on the loopback address:
no test reaches the Internet or a public MX. The server fails a test on any
command other than EHLO, STARTTLS and QUIT.

The TLS tests negotiate for real. A certificate of the test authority (:class:`TestPki`)
can only be verified by a context that trusts it, so the "lab" context is
:func:`~posture_cockpit.core.smtp.public_smtp_context` itself, plus that authority:
the same checks (certificate required, name, no common name, TLS 1.2 at least), a
chain that ends here. The production context is tested on its own, as it is.

These tests check observations only: which stage, which reason, which evidence.
The verdicts drawn from them (matrix F05) are tested with the decision function.

Each docstring names the requirement it covers: specification 0.7 revision 3
(T01, T02, F02, F02 bis, F03, S04, S05, Q02, Q03, Q06) and the development plan
(R1, R3, R10, R11, decisions D1b and D2b).
"""

import ast
import asyncio
import dataclasses
import datetime as dt
import inspect
import re
import ssl
import warnings
from dataclasses import dataclass
from pathlib import Path

import pytest

from local_servers import LOOPBACK, TestPki
from posture_cockpit import config
from posture_cockpit.core import smtp
from posture_cockpit.core.smtp import Command, Reason, Reply, Stage
from smtp_servers import CLOSE, MX, SILENT, Record, Script, Session, ehlo, smtp_server

EHLO_NAME = "probe.example.org"
SOURCE = Path(smtp.__file__)
PLAIN_START = [(False, f"EHLO {EHLO_NAME}"), (False, "STARTTLS")]  # what a client says before TLS


# ------------------------------------------------------------------ helpers
@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> TestPki:
    return TestPki(tmp_path_factory.mktemp("smtp-pki"))


def lab_context(pki: TestPki) -> ssl.SSLContext:
    """The production context, plus the test authority (see the module documentation)."""
    context = smtp.public_smtp_context()
    context.load_verify_locations(cadata=pki.pem)
    return context


@dataclass
class Talk:
    attempt: smtp.Attempt
    record: Record
    elapsed: float  # seconds run_dialogue took
    closed: bool    # the connection was closed when run_dialogue returned

    @property
    def session(self) -> Session:
        return self.record.sessions[0]

    @property
    def commands(self) -> list[tuple[bool, str]]:
        return self.session.commands


def talk(script: Script, context: ssl.SSLContext | None = None, *, mx: str = MX, ehlo_name: str = EHLO_NAME,
         seconds: float = 20.0) -> Talk:
    """One dialogue with a fake server playing ``script``, the deadline ``seconds`` from now."""

    async def main() -> Talk:
        async with smtp_server(script) as (record, port):
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            loop = asyncio.get_running_loop()
            start = loop.time()
            attempt = await smtp.run_dialogue(reader, writer, mx_name=mx, ehlo_name=ehlo_name,
                                              tls_context=context or smtp.public_smtp_context(),
                                              deadline=start + seconds)
            elapsed = loop.time() - start
            closed = writer.transport.is_closing()
        return Talk(attempt, record, elapsed, closed)

    return asyncio.run(main())


def tls_script(server: ssl.SSLContext, **changes) -> Script:
    return dataclasses.replace(Script(tls=server), **changes)


def legacy_server(pki: TestPki, version: ssl.TLSVersion) -> ssl.SSLContext:
    """A server that speaks TLS 1.0 or 1.1 only (test side only: the probe never offers them)."""
    context = pki.server_context(MX)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pytest.skip("this machine's OpenSSL cannot serve TLS 1.0 or 1.1")
    return context


def refused_before_sending(*, match: str, mx_name: str = MX, ehlo_name: str = EHLO_NAME,
                           tls_context: ssl.SSLContext | None = None) -> None:
    """run_dialogue raises ValueError matching ``match``, the server received nothing, the connection is closed."""

    async def main() -> tuple[Record, bool]:
        async with smtp_server(Script()) as (record, port):
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            with pytest.raises(ValueError, match=match):
                await smtp.run_dialogue(reader, writer, mx_name=mx_name, ehlo_name=ehlo_name,
                                        tls_context=tls_context or smtp.public_smtp_context(),
                                        deadline=asyncio.get_running_loop().time() + 5)
            closed = writer.transport.is_closing()
        return record, closed

    record, closed = asyncio.run(main())
    assert all(session.commands == [] and session.early == b"" for session in record.sessions) and closed


def refused_certificate(result: Talk, code: int) -> None:
    """The negotiation stopped on the certificate, and nothing was tried around it."""
    attempt = result.attempt
    assert (attempt.stage, attempt.reason, attempt.verify_code) == (Stage.TLS, Reason.CERTIFICATE_REFUSED, code)
    assert attempt.verify_message and attempt.certificate is None
    assert result.commands == PLAIN_START  # nothing after the failed negotiation, not even QUIT
    assert result.record.connections == 1  # no second connection to read the certificate anyway


# ------------------------------------------------------------------ T01: the protocol
def test_a_simple_greeting_leads_to_a_verified_tls_session(pki):
    """T01 (simple 220), T02 (valid certificate), R10: the whole dialogue, in order, then QUIT over TLS."""
    result = talk(tls_script(pki.server_context(MX)), lab_context(pki))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.QUIT, Reason.TLS_VERIFIED)
    assert result.commands == [*PLAIN_START, (True, "QUIT")]
    assert attempt.banner == Reply(220, (f"{MX} ESMTP ready",), 1)
    assert attempt.capabilities == ("PIPELINING", "SIZE", "8BITMIME", "STARTTLS") and attempt.starttls_offered
    assert attempt.starttls == Reply(220, ("2.0.0 Ready to start TLS",), 1, "2.0.0")
    assert attempt.tls_version == result.session.tls_version == "TLSv1.3" and attempt.tls_cipher
    assert attempt.certificate is not None and attempt.certificate.trusted
    assert attempt.certificate.names == (MX,) and attempt.certificate.host == MX
    assert attempt.quit_reply == 221 and attempt.detail == "" and attempt.partial == ()
    assert result.closed


def test_a_multiline_greeting_is_read_to_its_last_line(pki):
    """T01 (220- lines then the final 220 line), Q02: EHLO only once the greeting is complete."""
    banner = (f"220-{MX} ESMTP", "220-Unsolicited mail is not welcome here", f"220 {MX} ready")
    result = talk(tls_script(pki.server_context(MX), banner=banner), lab_context(pki))
    assert result.attempt.reason is Reason.TLS_VERIFIED
    assert result.attempt.banner == Reply(220, (f"{MX} ESMTP", "Unsolicited mail is not welcome here",
                                                f"{MX} ready"), 3)
    assert result.session.early == b""


def test_a_greeting_delayed_six_seconds_is_waited_for_in_silence(pki):
    """T01 (greeting delayed 6 s, as postscreen does; silence before the final 220 line), Q02, R11: the
    probe says nothing until the last line, then goes on."""
    banner = (f"220-{MX} ESMTP", 6.0, f"220 {MX} ready")
    result = talk(tls_script(pki.server_context(MX), banner=banner), lab_context(pki))
    assert result.session.early == b""  # nothing sent during the six seconds
    assert result.attempt.reason is Reason.TLS_VERIFIED and result.attempt.banner.lines == 2
    assert 6.0 <= result.elapsed < smtp.BANNER_SECONDS


def test_a_greeting_without_its_last_line_ends_at_the_stage_limit(monkeypatch):
    """T01 (no final line), R11: the stage's own limit ends it; the lines received are kept."""
    monkeypatch.setattr(smtp, "BANNER_SECONDS", 0.5)
    result = talk(Script(banner=(f"220-{MX} first line", SILENT)))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.BANNER, Reason.TIMEOUT)
    assert attempt.partial == (f"220-{MX} first line",) and attempt.banner is None
    assert result.commands == [] and result.session.early == b""  # never spoke
    assert result.closed


def test_the_greeting_is_refused_with_421_or_554():
    """F02 bis, T03 (greeting 421 or 554): a refusal of the prober at the greeting, kept with its code.
    QUIT follows: after a 554 the server waits for it (RFC 5321 §3.1)."""
    for line in ("421 4.7.0 mx.lab.example closing, too many connections",
                 "554 5.7.1 mx.lab.example no SMTP service for you"):
        result = talk(Script(banner=(line,)))
        attempt = result.attempt
        assert (attempt.stage, attempt.reason) == (Stage.BANNER, Reason.BANNER_REFUSED)
        assert attempt.banner is not None and attempt.banner.code == int(line[:3])
        assert attempt.banner.enhanced == line[4:9]
        assert result.commands == [(False, "QUIT")] and attempt.quit_reply == 221


def test_the_ehlo_reply_lines_give_the_extensions():
    """T01 (250- lines then 250): the keywords, upper case, in order; old forms such as AUTH=LOGIN kept."""
    lines = ehlo("size 10240000", "AUTH=LOGIN PLAIN", "8BITMIME", "ENHANCEDSTATUSCODES")
    attempt = talk(Script(ehlo=lines)).attempt
    assert attempt.capabilities == ("SIZE", "AUTH=LOGIN", "8BITMIME", "ENHANCEDSTATUSCODES")
    assert attempt.ehlo == Reply(250, (MX, "size 10240000", "AUTH=LOGIN PLAIN", "8BITMIME"), 5)


@pytest.mark.parametrize("line", ["550 5.7.1 Client host rejected", "501 5.5.4 Invalid domain name",
                                  "421 4.3.2 Service shutting down"])
def test_a_refused_ehlo_stops_the_dialogue(line):
    """T01 (EHLO rejected), F02 bis: the refusal is kept at the EHLO stage; no STARTTLS, then QUIT."""
    result = talk(Script(ehlo=(line,)))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.EHLO, Reason.EHLO_REFUSED)
    assert attempt.ehlo is not None and attempt.ehlo.code == int(line[:3])
    assert result.commands == [(False, f"EHLO {EHLO_NAME}"), (False, "QUIT")]


def test_starttls_not_announced_is_observed_after_a_complete_ehlo():
    """T01 (STARTTLS absent), basis of F05.03: a nominal dialogue whose EHLO does not announce STARTTLS.
    STARTTLS is never sent unannounced (RFC 3207 §2)."""
    result = talk(Script(ehlo=ehlo("PIPELINING", "8BITMIME")))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.EHLO, Reason.STARTTLS_ABSENT)
    assert not attempt.starttls_offered and attempt.altered == ()
    assert result.commands == [(False, f"EHLO {EHLO_NAME}"), (False, "QUIT")]


def test_a_single_line_ehlo_announces_no_extension():
    """T01: "250 name" alone is a complete EHLO reply with no extension (RFC 5321 §4.1.1.1)."""
    attempt = talk(Script(ehlo=(f"250 {MX}",))).attempt
    assert attempt.reason is Reason.STARTTLS_ABSENT and attempt.capabilities == ()


def test_altered_capabilities_take_precedence():
    """R3 (last row), F02 bis, T03 (XXXXXXXA): masked extensions stop the dialogue at EHLO, STARTTLS
    announced or not: neither its presence nor its absence can be read, and it is not sent."""
    for lines, masked in ((ehlo("PIPELINING", "XXXXXXXA"), "XXXXXXXA"), (ehlo("XXXXXXXB", "STARTTLS"), "XXXXXXXB")):
        result = talk(Script(ehlo=lines))
        attempt = result.attempt
        assert (attempt.stage, attempt.reason) == (Stage.EHLO, Reason.ESMTP_ALTERED)
        assert attempt.altered == (masked,) and attempt.detail == masked
        assert result.commands == [(False, f"EHLO {EHLO_NAME}"), (False, "QUIT")]


def test_keywords_that_merely_start_with_x_are_not_altered():
    """F02 bis: local extensions start with X (RFC 5321 §2.2.2); only a keyword made of X's is a mask."""
    attempt = talk(Script(ehlo=ehlo("XCLIENT NAME ADDR", "XFORWARD NAME", "X-EXPS GSSAPI"))).attempt
    assert attempt.reason is Reason.STARTTLS_ABSENT and attempt.altered == ()


# ------------------------------------------------------------------ R3: the reply to STARTTLS
def test_starttls_220_proceeds_to_tls(pki):
    """R3 (220, starttls_ready): the negotiation follows at once, nothing said in between."""
    result = talk(tls_script(pki.server_context(MX), starttls=("220 Ready",)), lab_context(pki))
    assert result.attempt.starttls == Reply(220, ("Ready",), 1)
    assert result.attempt.reason is Reason.TLS_VERIFIED and result.commands == [*PLAIN_START, (True, "QUIT")]


@pytest.mark.parametrize("line", ["454 4.7.0 TLS not available due to temporary reason",
                                  "421 4.3.2 Service not available", "451 4.3.0 Try again later"])
def test_starttls_4xx_is_temporary(line):
    """R3 (4xx, 454 included: starttls_temporary): kept at the STARTTLS stage, then QUIT in the clear."""
    result = talk(Script(starttls=(line,)))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.STARTTLS, Reason.STARTTLS_TEMPORARY)
    assert attempt.starttls is not None and attempt.starttls.code == int(line[:3])
    assert result.commands == [*PLAIN_START, (False, "QUIT")]


@pytest.mark.parametrize("line", ["501 5.5.4 Syntax error (no parameters allowed)", "503 5.5.1 Bad sequence",
                                  "504 5.5.4 Not implemented", "552 5.3.4 Message too big", "250 2.0.0 OK",
                                  "354 Go ahead"])
def test_starttls_dialogue_errors(line):
    """R3 (501, 503, 504, any other code: starttls_dialogue_error): a reply outside RFC 3207 §4."""
    result = talk(Script(starttls=(line,)))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.STARTTLS, Reason.STARTTLS_DIALOGUE_ERROR)
    assert result.commands == [*PLAIN_START, (False, "QUIT")]


@pytest.mark.parametrize("raw", [b"220 Ready\n", b"2x0 Ready\r\n", b"220-Ready\r\n250 Ready\r\n",
                                 b"220 Ready\r\n250 2.0.0 injected\r\n"])
def test_a_malformed_reply_to_starttls_is_a_dialogue_error(raw):
    """R3 (malformed reply: starttls_dialogue_error), RFC 3207 §6: a bare LF, a bad code, two codes, or bytes
    after the 220 that would be read as if they came over TLS. Nothing more is sent, TLS not tried."""
    result = talk(Script(starttls=(raw,)))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.STARTTLS, Reason.STARTTLS_DIALOGUE_ERROR)
    assert result.attempt.detail
    assert result.commands == PLAIN_START and result.session.tls_version == ""


@pytest.mark.parametrize("line", ["550 5.7.1 Access denied", "554 5.7.1 Rejected", "530 5.7.0 Not for you",
                                  "550 Not here", "554 Go away", "502 5.7.0 Not for your address"])
def test_starttls_policy_refusal(line):
    """R3 (5.7.x, 530, 550, 554: starttls_policy_refusal): a refusal of the prober, not of TLS. A security
    or policy code (RFC 3463 §3.8) is read before the basic code, 502 included."""
    result = talk(Script(starttls=(line,)))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.STARTTLS, Reason.STARTTLS_POLICY_REFUSAL)
    assert result.commands == [*PLAIN_START, (False, "QUIT")]


@pytest.mark.parametrize("line", ["500 5.5.1 Unrecognized command", "502 5.5.1 Command not implemented",
                                  "502 Not implemented"])
def test_starttls_500_502_after_announce_is_unavailable_d2b(line):
    """R3, decision D2b (500 or 502 although announced: starttls_unavailable): kept as such, never taken
    for STARTTLS absent, which needs a nominal EHLO without the keyword."""
    result = talk(Script(starttls=(line,)))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.STARTTLS, Reason.STARTTLS_UNAVAILABLE)
    assert result.attempt.starttls_offered


@pytest.mark.parametrize(("code", "enhanced", "reason"), [
    (220, "", None), (220, "2.0.0", None),
    (454, "4.7.0", Reason.STARTTLS_TEMPORARY), (421, "", Reason.STARTTLS_TEMPORARY),
    (500, "5.7.0", Reason.STARTTLS_POLICY_REFUSAL), (502, "5.7.1", Reason.STARTTLS_POLICY_REFUSAL),
    (501, "5.7.0", Reason.STARTTLS_POLICY_REFUSAL), (530, "", Reason.STARTTLS_POLICY_REFUSAL),
    (550, "5.1.1", Reason.STARTTLS_POLICY_REFUSAL), (554, "", Reason.STARTTLS_POLICY_REFUSAL),
    (500, "5.5.1", Reason.STARTTLS_UNAVAILABLE), (502, "", Reason.STARTTLS_UNAVAILABLE),
    (501, "5.5.4", Reason.STARTTLS_DIALOGUE_ERROR), (503, "", Reason.STARTTLS_DIALOGUE_ERROR),
    (504, "", Reason.STARTTLS_DIALOGUE_ERROR), (552, "5.3.4", Reason.STARTTLS_DIALOGUE_ERROR),
    (250, "", Reason.STARTTLS_DIALOGUE_ERROR), (354, "", Reason.STARTTLS_DIALOGUE_ERROR),
])
def test_the_categories_of_a_reply_to_starttls(code, enhanced, reason):
    """R3, decision D2b: the whole table, in the order it is applied (policy code, then 500/502, then the rest)."""
    assert smtp.starttls_refusal(Reply(code, (), 1, enhanced)) is reason


def test_an_enhanced_code_counts_only_with_the_class_of_the_reply():
    """R3, RFC 3463 §2: the class of an enhanced code is the first digit of its reply; "4.7.0" on a 502 is
    not a policy code, and the 502 is read as such."""
    attempt = talk(Script(starttls=("502 4.7.0 odd",))).attempt
    assert attempt.starttls is not None and attempt.starttls.enhanced == ""
    assert attempt.reason is Reason.STARTTLS_UNAVAILABLE


# ------------------------------------------------------------------ R1: TLS
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_1_2_and_1_3_are_negotiated(pki, version):
    """T01 (handshake in TLS 1.2 and in TLS 1.3): both are what the probe offers."""
    server = pki.server_context(MX)
    server.minimum_version = server.maximum_version = version
    result = talk(tls_script(server), lab_context(pki))
    name = {ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[version]
    assert result.attempt.reason is Reason.TLS_VERIFIED and result.attempt.tls_version == name
    assert result.session.tls_version == name


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
def test_tls_version_refused_d1b(pki, version):
    """R1, decision D1b (alert protocol_version: tls_version_refused): a server that speaks only TLS 1.0
    or 1.1. One connection, no older version tried to confirm it, nothing said after the failure."""
    result = talk(tls_script(legacy_server(pki, version)), lab_context(pki))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.TLS, Reason.TLS_VERSION_REFUSED)
    assert attempt.detail == "tlsv1_alert_protocol_version"
    assert result.session.tls_error == "UNSUPPORTED_PROTOCOL"  # the server's side of it
    assert result.commands == PLAIN_START and result.record.connections == 1


def test_wrong_version_number_is_dialogue_error(pki):
    """R1 (bytes that are not TLS, WRONG_VERSION_NUMBER: tls_dialogue_error): the server answers the
    ClientHello in the clear. Nothing is sent in the clear afterwards."""
    result = talk(Script(tls=(b"500 5.5.1 Still speaking in the clear\r\n", SILENT)), lab_context(pki))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason, attempt.detail) == (Stage.TLS, Reason.TLS_DIALOGUE_ERROR,
                                                               "wrong_version_number")
    assert result.commands == PLAIN_START


def test_other_tls_failures(pki, monkeypatch):
    """R1 (handshake_failure, another alert, a close, a silence: tls_handshake_error, closed, timeout),
    T01 (TLS interrupted, failed negotiation): never a version refusal, nothing said afterwards."""
    no_shared_cipher = pki.server_context(MX)
    no_shared_cipher.maximum_version = ssl.TLSVersion.TLSv1_2
    no_shared_cipher.set_ciphers("AES128-SHA")  # RSA key exchange, with an EC key: nothing in common
    monkeypatch.setattr(smtp, "TLS_SECONDS", 0.5)
    cases = [
        (tls_script(no_shared_cipher), Reason.TLS_HANDSHAKE_ERROR, "sslv3_alert_handshake_failure"),
        (Script(tls=(b"\x16\x03\x01\x00\x05hello", SILENT)), Reason.TLS_HANDSHAKE_ERROR, "unexpected_message"),
        (Script(tls=(CLOSE,)), Reason.CLOSED, "closed during the TLS negotiation"),
        (Script(tls=(SILENT,)), Reason.TIMEOUT, "no negotiation within 0.5 s"),
    ]
    for script, reason, detail in cases:
        result = talk(script, lab_context(pki))
        assert (result.attempt.stage, result.attempt.reason, result.attempt.detail) == (Stage.TLS, reason, detail)
        assert result.commands == PLAIN_START and result.closed


def test_no_legacy_reconnection_d1b(pki):
    """R1, decision D1b: the dialogue never offers TLS 1.0 or 1.1, not even through the context it is
    given, and nothing in the module can build such a context."""
    old = smtp.public_smtp_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old.minimum_version = ssl.TLSVersion.TLSv1
    with pytest.raises(ValueError, match=r"older than TLS 1\.2"):
        talk(tls_script(pki.server_context(MX)), old)
    unset = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unset.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED  # what some builds leave by default
    with pytest.raises(ValueError, match=r"older than TLS 1\.2"):
        talk(tls_script(pki.server_context(MX)), unset)
    source = SOURCE.read_text()
    assert "legacy_tls" not in source and "SECLEVEL" not in source and "TLSv1_1" not in source


@pytest.mark.parametrize(("error", "reason"), [
    (ssl.SSLEOFError(8, "EOF occurred in violation of protocol"), Reason.CLOSED),
    (ssl.SSLZeroReturnError(6, "TLS/SSL connection has been closed (EOF)"), Reason.CLOSED),
    (ConnectionResetError("Connection lost"), Reason.CLOSED),
    (asyncio.IncompleteReadError(b"", 5), Reason.CLOSED),
    (BrokenPipeError(32, "Broken pipe"), Reason.CLOSED),
])
def test_a_close_during_the_negotiation(error, reason):
    """R1 (a close: closed), however the system reports it."""
    assert smtp.tls_failure(error)[0] is reason


@pytest.mark.parametrize("name", ["UNSUPPORTED_PROTOCOL", "VERSION_TOO_LOW", "TLSV1_ALERT_PROTOCOL_VERSION"])
def test_every_report_of_an_old_server_is_a_version_refusal_d1b(name):
    """R1, decision D1b: OpenSSL reports a server that answers in TLS 1.0 or 1.1 in several ways (a reply in
    an old version, a version too low, the server's alert); all are the same observation."""
    error = ssl.SSLError(1, name.lower())
    error.reason = name
    assert smtp.tls_failure(error) == (Reason.TLS_VERSION_REFUSED, name.lower())


# ------------------------------------------------------------------ T02: certificates
def test_a_certificate_of_an_unknown_authority_is_refused(pki, tmp_path):
    """T02 (unknown authority), F03: refused by the first, verifying, negotiation; no bypass."""
    other = TestPki(tmp_path, "Other CA")
    refused_certificate(talk(tls_script(other.server_context(MX)), lab_context(pki)), 20)


def test_an_incomplete_chain_is_refused(pki):
    """T02 (incomplete chain): without its intermediate authority the chain ends nowhere; with it, it is valid."""
    refused_certificate(talk(tls_script(pki.server_context(MX, intermediate=True, send_chain=False)),
                             lab_context(pki)), 20)
    complete = talk(tls_script(pki.server_context(MX, intermediate=True)), lab_context(pki))
    assert complete.attempt.reason is Reason.TLS_VERIFIED


@pytest.mark.parametrize(("days", "valid_from_days", "code"), [(-3, -30, 10), (60, 5, 9)])
def test_an_expired_or_not_yet_valid_certificate_is_refused(pki, days, valid_from_days, code):
    """T02 (expired, not yet valid), RFC 8461 §4.1: OpenSSL's codes 10 and 9 are kept for the decision."""
    server = pki.server_context(MX, days=days, valid_from_days=valid_from_days)
    refused_certificate(talk(tls_script(server), lab_context(pki)), code)


def test_a_common_name_without_subject_alternative_name_is_refused(pki):
    """T02 (no SAN, correct CN only), Q02 (hostname_checks_common_name = False), RFC 8461 §4.1."""
    refused_certificate(talk(tls_script(pki.server_context(MX, san=False)), lab_context(pki)), 62)


def test_a_subject_alternative_name_for_another_name_is_refused(pki):
    """T02 (SAN not matching the published MX), RFC 8461 §4.1: a correct CN does not make up for it."""
    server = pki.server_context("other.lab.example", common_name=MX)
    refused_certificate(talk(tls_script(server), lab_context(pki)), 62)


@pytest.mark.parametrize(("names", "valid"), [(("*.lab.example",), True), (("*.example",), False),
                                              (("m*.lab.example",), False)])
def test_wildcards_cover_one_leftmost_label(pki, names, valid):
    """T02 (wildcard valid and invalid), RFC 6125 §6.4.3: "*.lab.example" covers mx.lab.example; "*.example"
    (two labels away) and a partial wildcard do not."""
    result = talk(tls_script(pki.server_context(*names)), lab_context(pki))
    if valid:
        assert result.attempt.reason is Reason.TLS_VERIFIED and result.attempt.certificate.names == names
    else:
        refused_certificate(result, 62)


def test_the_published_mx_name_is_the_sni_and_the_identity(pki):
    """T02 (SNI observable; MX pointing to a CNAME whose target has the certificate), F01, F03: the name
    sent and checked is the published MX, never the CNAME target."""
    result = talk(tls_script(pki.server_context("host.provider.example")), lab_context(pki), mx=f"{MX}.")
    refused_certificate(result, 62)
    assert result.session.sni == [MX] and result.attempt.mx_name == MX
    assert MX in result.attempt.verify_message


def test_the_production_context_does_not_trust_a_perimeter_authority(pki):
    """T02 (validation outside the perimeter's trusted_ca), S05, Q02: a certificate valid for an internal
    authority is refused by the production context, which takes no authority of its own."""
    refused_certificate(talk(tls_script(pki.server_context(MX)), smtp.public_smtp_context()), 20)
    assert inspect.signature(smtp.public_smtp_context).parameters == {}


def test_the_production_context_settings():
    """F03, Q02, decision D1b: certificate required, name checked, no common name, TLS 1.2 at least, no
    ceiling, and the system's authorities only."""
    context = smtp.public_smtp_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.hostname_checks_common_name is False
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == ssl.TLSVersion.MAXIMUM_SUPPORTED
    assert context.cert_store_stats() == ssl.create_default_context().cert_store_stats()
    assert smtp.public_smtp_context() is not context  # a new one each time: nothing shared to alter


@pytest.mark.parametrize("days", [21, 20, 10])
def test_the_expiry_date_is_kept_for_the_decision(pki, days):
    """T02, R2: a valid certificate close to its end is verified, and its date kept; how many days remain is
    computed by the decision, from the time of the scan."""
    attempt = talk(tls_script(pki.server_context(MX, days=days)), lab_context(pki)).attempt
    assert attempt.reason is Reason.TLS_VERIFIED and attempt.certificate is not None
    expected = dt.datetime.now(dt.UTC) + dt.timedelta(days=days)
    assert abs((attempt.certificate.not_after - expected).total_seconds()) < 120


def test_a_context_that_verifies_nothing_never_claims_trust(pki, tmp_path):
    """F03 (diagnostic reconnection: reading a refused certificate never makes it trusted): with a context
    that checks nothing, the negotiation succeeds, the certificate is read, and stays untrusted."""
    reader = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    reader.check_hostname = False
    reader.verify_mode = ssl.CERT_NONE
    # Set, not assumed: some builds (Ubuntu's Python 3.12) leave the minimum to the system, which can mean
    # TLS 1.0, and the dialogue refuses such a context (decision D1b).
    reader.minimum_version = ssl.TLSVersion.TLSv1_2
    other = TestPki(tmp_path, "Other CA")
    attempt = talk(tls_script(other.server_context(MX)), reader).attempt
    assert (attempt.stage, attempt.reason) == (Stage.QUIT, Reason.TLS_UNVERIFIED)
    assert attempt.certificate is not None and not attempt.certificate.trusted
    assert attempt.certificate.issuer == "Other CA"


# ------------------------------------------------------------------ R10: nothing after TLS but QUIT
def test_no_ehlo_after_tls_r10(pki):
    """R10, RFC 3207 §4.1 and §4.2: over TLS the probe says QUIT and nothing else."""
    result = talk(tls_script(pki.server_context(MX)), lab_context(pki))
    assert [line for secure, line in result.commands if secure] == ["QUIT"]


def test_quit_is_best_effort(pki, monkeypatch):
    """F02 (QUIT best effort, within the deadline), R10: a server that does not answer QUIT changes nothing."""
    monkeypatch.setattr(smtp, "QUIT_SECONDS", 0.3)
    result = talk(tls_script(pki.server_context(MX), quit=(SILENT,)), lab_context(pki))
    assert result.attempt.reason is Reason.TLS_VERIFIED and result.attempt.quit_reply is None
    assert result.elapsed < 2 and result.closed


# ------------------------------------------------------------------ R11: time limits
def test_the_stage_time_limits_r11():
    """R11: greeting 10 s, EHLO or STARTTLS reply 5 s, TLS negotiation 5 s (the connection's 5 s belong to the
    network layer, which opens it)."""
    assert (smtp.BANNER_SECONDS, smtp.REPLY_SECONDS, smtp.TLS_SECONDS) == (10.0, 5.0, 5.0)
    assert smtp.QUIT_SECONDS <= 2.0


def silent_at(stage: Stage) -> Script:
    return {Stage.EHLO: Script(ehlo=(SILENT,)), Stage.STARTTLS: Script(starttls=(SILENT,)),
            Stage.TLS: Script(tls=(SILENT,))}[stage]


@pytest.mark.parametrize("stage", [Stage.EHLO, Stage.STARTTLS, Stage.TLS])
def test_each_stage_has_its_own_time_limit(pki, monkeypatch, stage):
    """R11, T01: a server silent at one stage ends the dialogue at that stage, by that stage's limit."""
    for name in ("REPLY_SECONDS", "TLS_SECONDS"):
        monkeypatch.setattr(smtp, name, 0.3)
    result = talk(silent_at(stage), lab_context(pki))
    assert (result.attempt.stage, result.attempt.reason) == (stage, Reason.TIMEOUT)
    assert result.elapsed < 2


@pytest.mark.parametrize("stage", [Stage.EHLO, Stage.STARTTLS, Stage.TLS])
def test_the_deadline_caps_every_stage(pki, stage):
    """R11, F02 (deadline): the caller's deadline comes before the stage's own limit, and the observation is
    returned in time, marked deadline rather than timeout."""
    result = talk(silent_at(stage), lab_context(pki), seconds=0.5)
    assert (result.attempt.stage, result.attempt.reason) == (stage, Reason.DEADLINE)
    assert result.elapsed < 0.5 + 0.5  # returned at the deadline, give or take scheduling


def test_a_deadline_already_past_sends_nothing():
    """R11, F02: with no time left, nothing is sent and nothing is waited for."""
    result = talk(Script(), seconds=-1)
    assert (result.attempt.stage, result.attempt.reason) == (Stage.BANNER, Reason.DEADLINE)
    assert result.commands == [] and result.session.early == b"" and result.closed


def test_a_trickling_greeting_is_bounded_as_a_whole(monkeypatch):
    """R11, Q03: the limit bounds the whole reply, not each line: a server sending one line at a time,
    slowly, cannot hold the probe."""
    monkeypatch.setattr(smtp, "BANNER_SECONDS", 0.5)
    banner = [item for n in range(20) for item in (f"220-line {n}", 0.1)]
    result = talk(Script(banner=banner))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.BANNER, Reason.TIMEOUT)
    assert result.attempt.partial[0] == "220-line 0" and len(result.attempt.partial) <= smtp.EVIDENCE_LINES
    assert result.elapsed < 1.5


# ------------------------------------------------------------------ Q03, S04: bounded reading, clean evidence
@pytest.mark.parametrize("raw", [b"220 bare line feed\n", b"600 no such code\r\n", b"22 short\r\n",
                                 b"220x no separator\r\n", b"220-first\r\n250 second code\r\n",
                                 b"220 a bell\x07 in the text\r\n", b"220 a\rcarriage return\r\n"])
def test_a_malformed_greeting(raw):
    """Q03, RFC 5321 §4.2 and §2.3.8: a reply outside the grammar is observed as such, the faulty line kept
    in the evidence, cleaned; nothing is sent to a server that does not follow it, not even QUIT."""
    result = talk(Script(banner=(raw,)))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.BANNER, Reason.MALFORMED_REPLY)
    assert attempt.detail and attempt.partial
    assert all(re.fullmatch(r"[ -~]*", line) for line in attempt.partial)
    assert result.commands == []


def test_bytes_above_127_are_tolerated_and_cleaned():
    """Q03, S04: an accent in a greeting does not stop the dialogue; the evidence keeps printable ASCII only."""
    result = talk(Script(banner=("220 Café de la poste ESMTP",), ehlo=ehlo("PIPELINING")))
    assert result.attempt.reason is Reason.STARTTLS_ABSENT
    assert result.attempt.banner is not None and result.attempt.banner.text == ("Caf? de la poste ESMTP",)


def test_a_reply_line_too_long():
    """Q03, S04 (hostile greeting): a line beyond MAX_LINE_BYTES stops the reading; the buffer never grew past it."""
    result = talk(Script(banner=(b"220 " + b"x" * 10_000 + b"\r\n",)))
    attempt = result.attempt
    assert (attempt.stage, attempt.reason) == (Stage.BANNER, Reason.REPLY_TOO_LARGE)
    assert str(smtp.MAX_LINE_BYTES) in attempt.detail and result.commands == []


def test_a_reply_with_too_many_lines():
    """Q03: a reply beyond MAX_REPLY_LINES lines stops the reading at its stage."""
    lines = ehlo(*(f"EXTENSION{n}" for n in range(smtp.MAX_REPLY_LINES + 5)))
    result = talk(Script(ehlo=lines))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.EHLO, Reason.REPLY_TOO_LARGE)


def test_a_hostile_greeting_is_kept_short_and_clean():
    """S04 (bounded and expunged greetings), Q03: a few lines, each cut to EVIDENCE_CHARS, printable only."""
    long = "<script>alert(1)</script>" + "x" * 900
    banner = [*(f"220-{long}" for _ in range(9)), "220 end"]
    attempt = talk(Script(banner=banner, ehlo=ehlo("PIPELINING"))).attempt
    assert attempt.banner is not None and attempt.banner.lines == 10
    assert len(attempt.banner.text) == smtp.EVIDENCE_LINES
    assert all(len(text) == smtp.EVIDENCE_CHARS for text in attempt.banner.text)


def test_bytes_sent_unasked_after_the_greeting():
    """Q03, RFC 5321 §4.2: one reply per command; bytes after the greeting would be read as the next reply."""
    result = talk(Script(banner=(b"220 ready\r\n250 2.0.0 unasked\r\n",)))
    assert (result.attempt.stage, result.attempt.reason) == (Stage.BANNER, Reason.UNSOLICITED_DATA)
    assert result.attempt.banner is not None and result.attempt.banner.code == 220
    assert result.commands == []


def test_a_close_is_observed_at_its_stage():
    """T03 (refusal, close), Q03: a close is kept at the stage where it happened, with any partial reply."""
    cases = [(Script(banner=(CLOSE,)), Stage.BANNER, ()),
             (Script(ehlo=(CLOSE,)), Stage.EHLO, ()),
             (Script(ehlo=(f"250-{MX}", CLOSE)), Stage.EHLO, (f"250-{MX}",)),
             (Script(ehlo=(b"250-unfinished", CLOSE)), Stage.EHLO, ("250-unfinished",))]
    for script, stage, partial in cases:
        attempt = talk(script).attempt
        assert (attempt.stage, attempt.reason, attempt.partial) == (stage, Reason.CLOSED, partial)


def test_an_attempt_cannot_be_changed():
    """F05 (typed observations): an Attempt is frozen once returned."""
    attempt = talk(Script(ehlo=ehlo("PIPELINING"))).attempt
    with pytest.raises(dataclasses.FrozenInstanceError):
        attempt.reason = Reason.TLS_VERIFIED  # type: ignore[misc]


# ------------------------------------------------------------------ S04: what the probe may say
def test_the_fake_server_fails_a_test_on_any_other_command():
    """S04, Q06: the guard of every test here works: a client that says MAIL fails the test."""

    async def main() -> None:
        async with smtp_server(Script()) as (_, port):
            reader, writer = await asyncio.open_connection(LOOPBACK, port)
            await reader.readline()
            writer.write(b"MAIL FROM:<probe@example.org>\r\n")
            await writer.drain()
            await reader.readline()
            writer.close()

    with pytest.raises(AssertionError, match="MAIL FROM"):
        asyncio.run(main())


def test_three_commands_and_one_function_that_writes():
    """S04, Q02, Q03: EHLO, STARTTLS and QUIT are the only commands, and _send the only code that writes."""
    assert {c.value for c in Command} == {"EHLO", "STARTTLS", "QUIT"}
    tree = ast.parse(SOURCE.read_text())
    writers = []
    for function in ast.walk(tree):
        if isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                        "write", "writelines", "sendall", "send", "sock_sendall"):
                    writers.append(function.name)
    assert writers == ["_send"]


INVALID_NAMES = [
    "localhost", "mx..example.org", "mx_foo.example.org", "mx.-bad.example.org", "mx.bad-.example.org",
    ".mx.example.org", "192.0.2.25", f"{'a' * 64}.example.org", ("a" * 60 + ".") * 5 + "org", "mx.exämple.org",
    "", ".", f"{EHLO_NAME}\r\nMAIL FROM:<>", f"{EHLO_NAME} x", "probe\x00.example.org",
]


@pytest.mark.parametrize("field", ["mx_name", "ehlo_name"])
@pytest.mark.parametrize("name", INVALID_NAMES)
def test_an_invalid_name_is_refused_before_anything_is_sent(field, name):
    """F02 bis, S04 (CR LF injection), F03: the MX name and the EHLO name are fully qualified ASCII host names,
    labels of 1 to 63 letters, digits and hyphens, no underscore, no hyphen at either end, no empty label, not
    an address; anything else is refused before a byte is sent, and the connection is closed."""
    label = {"mx_name": "MX", "ehlo_name": "EHLO"}[field]
    refused_before_sending(match=f"SMTP dialogue, {label} name: ", **{field: name})


def test_names_are_used_in_lower_case_without_the_final_dot(pki):
    """F02 bis, F03: the names given are used as given, only normalised (lower case, no root dot): the EHLO
    argument, the SNI and the name checked; the MX is never replaced by another name."""
    result = talk(tls_script(pki.server_context(MX)), lab_context(pki), mx="MX.Lab.Example.",
                  ehlo_name="Probe.Example.ORG.")
    assert result.attempt.reason is Reason.TLS_VERIFIED and result.attempt.mx_name == MX
    assert result.session.sni == [MX] and result.commands[0] == (False, f"EHLO {EHLO_NAME}")


def test_one_rule_for_host_names():
    """F02 bis, S04, Q03: the dialogue checks names with the rule the configuration applies at start, not a
    copy of it; the EHLO name gets the same answer from both."""
    assert smtp.check_host_name is config.check_host_name
    assert config.validate_ehlo_name("Probe.Example.org.") == config.check_host_name("Probe.Example.org.", "x")


def test_the_module_opens_no_connection():
    """S01, S02 (belong to the network layer): this module receives a connection and opens none."""
    tree = ast.parse(SOURCE.read_text())
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported == {"__future__", "asyncio", "contextlib", "re", "ssl", "dataclasses", "enum", "config",
                        "network"}
    called = {node.func.attr for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not called & {"open_connection", "create_connection", "sock_connect", "start_server", "connect"}


# ------------------------------------------------------------------ Q06: every SMTP test names its requirement
REFERENCE = re.compile(r"\b(T0[1-9]|F0[1-8](\.[0-9]{2})?|S0[1-5]|R1[0-3]|R[1-9]|Q0[1-8]|D[1-5][ab])\b")


def test_every_smtp_test_names_its_requirement():
    """Q06: each test of the SMTP probe says, in its docstring, which requirement it covers."""
    missing = []
    for path in sorted(Path(__file__).parent.glob("test_v070_smtp_*.py")):
        missing += [f"{path.name}::{node.name}" for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
                    and not REFERENCE.search(ast.get_docstring(node) or "")]
    assert missing == []
