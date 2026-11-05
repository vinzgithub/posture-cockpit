# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version 0.7.0, PR-A: the settings of the SMTP probe and their way to the checks.

What is checked here, with the requirement of the specification 0.7.0 (revision 3) each test covers:

- the probe is off unless the operator writes ``on`` (decision A1a, §2);
- with the probe on, an EHLO name is required, checked as a fully qualified ASCII host name, and
  never replaced by a default or by the host name (F02 bis, S04, decision R9);
- with the probe on, CHECK_TIMEOUT must leave the probe some time (F02, T03);
- the engine and the scanner hand these settings and the check time limit to every check, for
  scans and rechecks alike.

No check uses these settings yet: the SMTP check arrives with PR-C. Nothing here opens a socket.
"""

import asyncio

import pytest

from posture_cockpit.config import SMTP_CHECK_MARGIN, Config, validate_ehlo_name
from posture_cockpit.core import engine
from posture_cockpit.core.extension import CheckContext, Extension, SmtpSettings
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Outcome, info
from posture_cockpit.core.registry import Registry
from posture_cockpit.scanner import Scanner

SMTP_VARIABLES = ("POSTURE_COCKPIT_SMTP_PROBE", "POSTURE_COCKPIT_SMTP_EHLO_NAME", "POSTURE_COCKPIT_CHECK_TIMEOUT")


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Sets POSTURE_COCKPIT_* variables for Config.from_env(), starting from none of the SMTP ones."""
    for name in SMTP_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))

    def set_variables(**values: str) -> None:
        for name, value in values.items():
            monkeypatch.setenv(f"POSTURE_COCKPIT_{name}", value)

    return set_variables


# ------------------------------------------------------------------ the switch
def test_the_probe_is_off_unless_the_operator_turns_it_on(env, tmp_path):
    """A1a, §2: without POSTURE_COCKPIT_SMTP_PROBE, or with it empty, the probe is off and needs no name."""
    assert Config.from_env().smtp_probe is False
    assert Config.from_env().smtp_ehlo_name is None
    env(SMTP_PROBE="")
    assert Config.from_env().smtp_probe is False
    assert Config(data_dir=tmp_path).smtp_probe is False


@pytest.mark.parametrize(("written", "expected"), [("off", False), ("on", True), ("ON", True), (" on ", True),
                                                    ("Off", False)])
def test_the_switch_reads_off_and_on(env, written, expected):
    """§2: only the words off and on, in any case, around spaces aside."""
    env(SMTP_PROBE=written, SMTP_EHLO_NAME="probe.example.org")
    assert Config.from_env().smtp_probe is expected


@pytest.mark.parametrize("written", ["true", "1", "yes", "enabled", "onn", "no", "of"])
def test_any_other_word_stops_the_start(env, written):
    """§2: ports 25 of other people's servers are reached only on an unambiguous choice."""
    env(SMTP_PROBE=written, SMTP_EHLO_NAME="probe.example.org")
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SMTP_PROBE"):
        Config.from_env()


# ----------------------------------------------------------- the EHLO name
@pytest.mark.parametrize("name", [None, "", "   "])
def test_the_probe_on_requires_an_ehlo_name(env, name):
    """F02 bis, S04: no default, no fallback on the host name of the container. A blank value counts as
    absent, as for every POSTURE_COCKPIT_* variable, so it is refused as missing."""
    env(SMTP_PROBE="on")
    if name is not None:
        env(SMTP_EHLO_NAME=name)
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SMTP_EHLO_NAME: required"):
        Config.from_env()


@pytest.mark.parametrize(("written", "sent"), [
    ("probe.example.org", "probe.example.org"),
    ("Probe.Example.ORG.", "probe.example.org"),     # lower case, without the root's dot
    ("  probe.example.org  ", "probe.example.org"),  # spaces around, as an editor may leave them
    ("xn--caf-dma.example.fr", "xn--caf-dma.example.fr"),
    ("a.b", "a.b"),
    ("a" * 63 + ".example.org", "a" * 63 + ".example.org"),
])
def test_a_fully_qualified_name_is_accepted(env, written, sent):
    """F02 bis: a fully qualified ASCII host name, sent in lower case."""
    env(SMTP_PROBE="on", SMTP_EHLO_NAME=written)
    assert Config.from_env().smtp_ehlo_name == sent


INVALID_NAMES = {
    "single label": "localhost",
    "short name": "probe",
    "IPv4 address": "192.0.2.10",
    "address literal": "[192.0.2.10]",
    "IPv6 address": "2001:db8::1",
    "numeric last label": "example.123",
    "CR LF injection": "probe.example.org\r\nMAIL FROM:<a@example.org>",
    "trailing line feed": "probe.example.org\n",
    "tab": "probe\t.example.org",
    "space inside": "probe .example.org",
    "leading hyphen": "-probe.example.org",
    "trailing hyphen": "probe-.example.org",
    "underscore": "probe_1.example.org",
    "empty label": "probe..example.org",
    "label of 64": "a" * 64 + ".example.org",
    "name over 253": ".".join(["a" * 63] * 4) + ".org",
    "not ASCII (R9)": "sondé.example.fr",
}


@pytest.mark.parametrize("name", INVALID_NAMES.values(), ids=INVALID_NAMES.keys())
def test_an_invalid_ehlo_name_stops_the_start(env, name):
    """F02 bis, S04, T03, R9: refused at start with the variable's name, before any connection."""
    env(SMTP_PROBE="on", SMTP_EHLO_NAME=name)
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SMTP_EHLO_NAME"):
        Config.from_env()


def test_an_injection_attempt_is_refused_whatever_the_rest_of_the_value():
    """S04: the name goes into the EHLO command as it is; a CR or LF anywhere would add a command.

    Checked on the function itself too: a NUL byte cannot reach it through the environment (the
    operating system refuses it), but Config may be built directly."""
    for value in ("\rprobe.example.org", "probe.example.org\r", "probe.\nexample.org", "probe\x00.example.org"):
        with pytest.raises(ValueError, match="control characters"):
            validate_ehlo_name(value)


def test_the_ehlo_name_is_checked_even_with_the_probe_off(env):
    """F02 bis: a name given with the probe off is still checked; no name at all is fine."""
    env(SMTP_EHLO_NAME="localhost")
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SMTP_EHLO_NAME"):
        Config.from_env()
    env(SMTP_EHLO_NAME="probe.example.org")
    assert Config.from_env().smtp_ehlo_name == "probe.example.org"


# -------------------------------------------------------- the check time limit
@pytest.mark.parametrize("seconds", ["2", "1", "0.5"])
def test_the_probe_on_needs_more_than_the_engine_margin(env, seconds):
    """F02, T03: with CHECK_TIMEOUT ≤ 2 s the probe's deadline min(12, CHECK_TIMEOUT − 2) would be ≤ 0."""
    env(SMTP_PROBE="on", SMTP_EHLO_NAME="probe.example.org", CHECK_TIMEOUT=seconds)
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_CHECK_TIMEOUT"):
        Config.from_env()


def test_a_short_time_limit_is_accepted_when_it_leaves_the_probe_some_time(env):
    """T03: a positive deadline, however short, starts; it gives inconclusive measures, never a false OK."""
    env(SMTP_PROBE="on", SMTP_EHLO_NAME="probe.example.org", CHECK_TIMEOUT="2.5")
    assert Config.from_env().check_timeout == 2.5
    assert SMTP_CHECK_MARGIN == 2.0


def test_a_short_time_limit_is_unchanged_with_the_probe_off(env):
    """§2, A1a: the probe off, CHECK_TIMEOUT keeps the meaning and the accepted values of v0.6.1."""
    env(CHECK_TIMEOUT="2")
    assert Config.from_env().check_timeout == 2.0


def test_a_config_built_directly_is_checked_too(tmp_path):
    """F02 bis: the tests and the command line build Config directly; the same rules apply."""
    with pytest.raises(ValueError, match="POSTURE_COCKPIT_SMTP_EHLO_NAME: required"):
        Config(data_dir=tmp_path, smtp_probe=True)
    config = Config(data_dir=tmp_path, smtp_probe=True, smtp_ehlo_name="Probe.Example.org")
    assert config.smtp_ehlo_name == "probe.example.org"


def test_enabled_settings_never_lack_a_name():
    """S04: a second guard behind the configuration; the probe never invents an EHLO name."""
    assert SmtpSettings() == SmtpSettings(enabled=False, ehlo_name=None)
    with pytest.raises(ValueError):
        SmtpSettings(enabled=True)


# ---------------------------------------------- from the instance to the checks
def capturing_extension() -> tuple[Extension, list[CheckContext]]:
    """An extension whose only check records the context it receives, and answers INFO."""
    seen: list[CheckContext] = []
    extension = Extension("capture", name="Capture", version="1")

    @extension.check("context", category="dns", weight=1)
    async def context(ctx: CheckContext) -> Outcome:
        seen.append(ctx)
        return info("capture.context")

    return extension, seen


def test_the_engine_hands_settings_and_time_limit_to_the_checks():
    """F02: a check reads ctx.check_timeout to compute its own deadline; ctx.smtp says whether to probe."""
    extension, seen = capturing_extension()
    settings = SmtpSettings(enabled=True, ehlo_name="probe.example.org")
    asyncio.run(engine.scan("example.org", extension.checks, FixtureNetwork({}), timeout=7, smtp=settings))
    asyncio.run(engine.scan("example.org", extension.checks, FixtureNetwork({})))
    assert (seen[0].smtp, seen[0].check_timeout) == (settings, 7)
    assert (seen[1].smtp, seen[1].check_timeout) == (SmtpSettings(), engine.CHECK_TIMEOUT)


def test_the_scanner_hands_the_instance_settings_to_scans_and_rechecks(tmp_path):
    """A1a, §5: scans, scheduled scans and rechecks all go through Scanner, with the instance's settings."""
    extension, seen = capturing_extension()
    config = Config(data_dir=tmp_path, smtp_probe=True, smtp_ehlo_name="probe.example.org", check_timeout=9)
    scanner = Scanner(Registry([extension]), config, network_factory=lambda domain: FixtureNetwork({}))
    asyncio.run(scanner.scan("example.org"))
    asyncio.run(scanner.recheck_group("example.org", "capture.context"))
    expected = SmtpSettings(enabled=True, ehlo_name="probe.example.org")
    assert [(ctx.smtp, ctx.check_timeout) for ctx in seen] == [(expected, 9), (expected, 9)]


def test_a_scanner_with_the_default_configuration_does_not_probe(tmp_path):
    """A1a: an instance without SMTP settings scans exactly as v0.6.1, the probe off."""
    extension, seen = capturing_extension()
    scanner = Scanner(Registry([extension]), Config(data_dir=tmp_path), network_factory=lambda d: FixtureNetwork({}))
    asyncio.run(scanner.scan("example.org"))
    assert seen[0].smtp == SmtpSettings()
