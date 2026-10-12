# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Internal perimeters: who may define them, see their domains and scan them; the audit log.

The network is recorded data (FixtureNetwork): these tests are about the rules
of the application. The network rule itself is tested in test_egress.py.
"""

import asyncio
import json
import re
from ipaddress import ip_network
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import PASSWORD, log_in, post, setup_account
from local_servers import TestPki
from posture_cockpit.config import Config
from posture_cockpit.core import engine
from posture_cockpit.core.egress import INTERNET
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.core.model import Status
from posture_cockpit.core.network import LiveNetwork
from posture_cockpit.core.registry import Registry
from posture_cockpit.i18n import LOCALES, interface_texts
from posture_cockpit.report import render_html
from posture_cockpit.scanner import InternalScansDisabled, Scanner
from posture_cockpit.security import hash_password, new_token, token_hash
from posture_cockpit.storage import PerimeterError
from posture_cockpit.storage.perimeters import Perimeter, parse_form
from posture_cockpit.web.app import create_app
from worlds import NOW, healthy

INTRANET = "intranet.example"
USER_PASSWORD = "another good password"


def intranet_world() -> dict:
    """The recorded answers of example.org, renamed: an intranet site as the internal DNS sees it."""
    return json.loads(json.dumps(healthy()).replace("example.org", INTRANET))


@pytest.fixture
def internal_app(tmp_path, world):
    world[INTRANET] = intranet_world()

    def network(domain):
        return FixtureNetwork(world.get(domain, {"dns": {f"{domain} SOA": None}}))

    return create_app(Config(data_dir=tmp_path, internal_scans=True), network_factory=network)


@pytest.fixture
def admin(internal_app):
    with TestClient(internal_app) as client:
        setup_account(client)
        post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
        yield client


def services(client):
    return client.app.state.services


def create_perimeter(client, **fields):
    data = {"name": "Siège", "networks": "10.20.0.0/16", "nameservers": "10.20.0.53", "ports": "443 8443",
            "ca_pem": "", **fields}
    return post(client, "/admin/perimeters", "/admin/perimeters/new", **data)


def add_internal_domain(client, perimeter_id=1, name=INTRANET):
    return post(client, f"/admin/perimeters/{perimeter_id}/domains", f"/admin/perimeters/{perimeter_id}", domain=name)


@pytest.fixture
def user(internal_app, admin):
    """A second account, without administration rights, signed in."""
    services(admin).accounts.create("steph", hash_password(USER_PASSWORD))
    with TestClient(internal_app) as client:
        log_in(client, "steph", USER_PASSWORD)
        yield client


def actions(client, prefix=""):
    return [e["action"] for e in services(client).audit.latest(100, prefix)]


# ------------------------------------------------------------------ the form
def test_a_valid_perimeter_is_normalized():
    form = parse_form(" Siège ", "10.20.0.0/16, fd00:20::/64\n192.168.1.7", "10.20.0.53", "8443 443 443", "")
    assert form.name == "Siège"
    assert form.networks.splitlines() == ["10.20.0.0/16", "fd00:20::/64", "192.168.1.7/32"]
    assert form.ports == "443 8443"
    assert parse_form("x", "10.0.0.0/8", "", "", "").ports == "80 443"  # the defaults


@pytest.mark.parametrize(("fields", "error_field"), [
    ({"name": ""}, "name"),
    ({"networks": ""}, "networks"),
    ({"networks": "0.0.0.0/0"}, "networks"),
    ({"networks": "127.0.0.0/8"}, "networks"),
    ({"networks": "169.254.169.254/32"}, "networks"),
    ({"networks": "8.8.8.0/24"}, "networks"),
    ({"networks": "10.0.0.0/8 " * 51}, "networks"),
    ({"nameservers": "dns.example.org"}, "nameservers"),
    ({"nameservers": "169.254.169.254"}, "nameservers"),
    ({"nameservers": "10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5"}, "nameservers"),
    ({"ports": "443 99999"}, "ports"),
    ({"ports": "https"}, "ports"),
    ({"ca_pem": "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"}, "ca_pem"),
    ({"ca_pem": "hello"}, "ca_pem"),
])
def test_an_invalid_perimeter_is_refused(fields, error_field):
    values = {"name": "Siège", "networks": "10.20.0.0/16", "nameservers": "", "ports": "", "ca_pem": "", **fields}
    with pytest.raises(PerimeterError) as caught:
        parse_form(**values)
    assert caught.value.field == error_field


def test_an_internal_ca_is_accepted_and_shown(tmp_path):
    pki = TestPki(tmp_path)
    form = parse_form("Siège", "10.20.0.0/16", "", "", pki.pem)
    perimeter = Perimeter(1, form.name, (), (), frozenset({443}), form.ca_pem, "")
    assert perimeter.ca_subjects == ["O=Lab Internal CA,CN=Lab Internal CA"]


# ----------------------------------------------------------- the scanner
def test_the_scanner_uses_the_rule_of_the_perimeter(tmp_path):
    pki = TestPki(tmp_path)
    form = parse_form("Siège", "10.20.0.0/16", "10.20.0.53", "443 8443", pki.pem)
    perimeter = Perimeter(1, form.name, tuple(ip_network(n) for n in form.networks.split()),
                          ("10.20.0.53",), frozenset({443, 8443}), form.ca_pem, "")
    scanner = Scanner(Registry.discover(), Config(data_dir=tmp_path, internal_scans=True))
    net = scanner.network_for(INTRANET, perimeter)
    assert isinstance(net, LiveNetwork)
    assert net.policy == perimeter.policy() and net.policy.internal and net.policy.name == "Siège"
    assert [str(n) for n in net._resolver.nameservers] == ["10.20.0.53"]
    assert net._verified_context().get_ca_certs()  # the internal CA is loaded, verification stays on
    internet = scanner.network_for("example.org")
    assert isinstance(internet, LiveNetwork) and internet.policy == INTERNET

    off = Scanner(Registry.discover(), Config(data_dir=tmp_path))
    with pytest.raises(InternalScansDisabled):
        off.network_for(INTRANET, perimeter)


def test_internet_only_checks_do_not_apply_to_an_internal_scan():
    registry = Registry.discover()
    net = FixtureNetwork(intranet_world(), NOW)
    result = asyncio.run(engine.scan(INTRANET, registry.checks(), net, now=NOW, internal=True))
    by_status = {f.check_id: f.status for f in result.findings}
    for check in registry.checks():
        if check.category in ("mail", "dns") or check.id == "web.security_txt":
            assert by_status[check.id] is Status.NA, check.id
        else:
            assert by_status[check.id] is not Status.NA, check.id
    assert not any(q.startswith("dns _dmarc") for q in net.asked)  # not even asked


# -------------------------------------------------------- the administration
def test_perimeters_stay_closed_until_the_operator_opens_them(client):
    setup_account(client)
    post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
    page = client.get("/admin").text
    assert "POSTURE_COCKPIT_INTERNAL_SCANS=1" in page and "Nouveau périmètre" not in page
    r = post(client, "/admin/perimeters", "/admin", name="Siège", networks="10.20.0.0/16")
    assert r.status_code == 403
    assert services(client).perimeters.all() == []


def test_an_administrator_creates_a_perimeter_and_scans_an_intranet_site(admin):
    r = create_perimeter(admin)
    assert r.status_code == 303 and r.headers["location"] == "/admin/perimeters/1"
    page = admin.get("/admin/perimeters/1").text
    assert "10.20.0.0/16" in page and "8443" in page

    r = add_internal_domain(admin)
    assert r.headers["location"] == f"/domains/{INTRANET}"
    plan = admin.get(f"/domains/{INTRANET}").text
    assert "Audit interne · Siège" in plan
    assert INTRANET in admin.get("/admin/perimeters/1").text
    listing = admin.get("/domains").text
    assert INTRANET in listing and 'class="tag-internal"' in listing

    scan = services(admin).scans.latest(services(admin).scans.domain(INTRANET)["id"])
    statuses = {f.check_id: f.status for f in scan.findings}
    assert statuses["mail.dmarc"] is Status.NA and statuses["tls.certificate"] is Status.OK
    assert actions(admin)[:3] == ["scan.internal", "domain.added", "perimeter.created"]
    entry = services(admin).audit.latest(1)[0]
    assert entry["detail"]["perimeter"] == "Siège" and entry["target"] == INTRANET
    assert scan.perimeter == "Siège"

    report = render_html(services(admin).catalog, "fr", scan)
    assert "Diffusion restreinte" in report and "Périmètre interne : Siège" in report
    assert admin.get(f"/domains/{INTRANET}/report.pdf").status_code == 200
    assert actions(admin)[0] == "report.internal"


def test_a_perimeter_is_checked_and_its_name_is_unique(admin):
    r = create_perimeter(admin, networks="0.0.0.0/0")
    assert r.status_code == 400 and "plages privées" in r.text
    assert services(admin).perimeters.all() == []
    create_perimeter(admin)
    r = create_perimeter(admin, name="siège", networks="10.30.0.0/16")
    assert r.status_code == 400 and "porte déjà ce nom" in r.text


def test_a_perimeter_in_use_cannot_be_deleted(admin):
    create_perimeter(admin)
    add_internal_domain(admin)
    r = post(admin, "/admin/perimeters/1/delete", "/admin/perimeters/1")
    assert r.status_code == 400
    post(admin, f"/domains/{INTRANET}/delete", f"/domains/{INTRANET}")
    r = post(admin, "/admin/perimeters/1/delete", "/admin/perimeters/1")
    assert r.status_code == 303 and services(admin).perimeters.all() == []
    assert actions(admin)[:2] == ["perimeter.deleted", "domain.deleted"]


def test_an_internal_name_cannot_be_added_again_from_the_internet(admin):
    create_perimeter(admin)
    add_internal_domain(admin)
    r = post(admin, "/domains", "/domains", domain=INTRANET)
    assert r.status_code == 400 and "périmètre interne" in r.text
    scans = services(admin).scans
    assert len(scans.history(scans.domain(INTRANET)["id"])) == 1  # nothing scanned from the Internet
    r = add_internal_domain(admin)
    assert r.status_code == 400 and "déjà suivi" in r.text


# --------------------------------------------- what other accounts can do
def test_other_accounts_never_see_internal_domains(admin, user):
    create_perimeter(admin)
    add_internal_domain(admin)
    assert INTRANET not in user.get("/domains").text
    for path in (f"/domains/{INTRANET}", f"/domains/{INTRANET}/details", f"/domains/{INTRANET}/report.pdf"):
        assert user.get(path).status_code == 404, path
    for path in (f"/domains/{INTRANET}/scan", f"/domains/{INTRANET}/verify/tls.certificate",
                 f"/domains/{INTRANET}/dns-host", f"/domains/{INTRANET}/delete"):
        assert post(user, path, dns_host="ovh").status_code == 404, path
    assert user.get("/admin/perimeters/1").status_code == 403
    assert post(user, "/admin/perimeters", name="Mine", networks="10.0.0.0/8").status_code == 403
    assert post(user, "/admin/perimeters/1/domains", domain="other.example").status_code == 403
    scans = services(admin).scans
    assert len(scans.history(scans.domain(INTRANET)["id"])) == 1
    assert scans.domain(INTRANET) is not None


def test_the_api_follows_the_rights_of_the_key_owner(admin, user):
    create_perimeter(admin)
    add_internal_domain(admin)
    s = services(admin)
    user_key, admin_key = new_token(), new_token()
    s.accounts.add_token(s.accounts.by_name("steph")["id"], "cron", token_hash(user_key))
    s.accounts.add_token(1, "cron", token_hash(admin_key))
    as_user = {"Authorization": f"Bearer {user_key}"}
    as_admin = {"Authorization": f"Bearer {admin_key}"}
    assert user.get("/api/v1/domains", headers=as_user).json() == {"domains": []}
    assert user.post(f"/api/v1/domains/{INTRANET}/scan", headers=as_user).status_code == 404
    listed = admin.get("/api/v1/domains", headers=as_admin).json()["domains"]
    assert [d["domain"] for d in listed] == [INTRANET]
    assert admin.post(f"/api/v1/domains/{INTRANET}/scan", headers=as_admin).status_code == 200
    entry = s.audit.latest(1)[0]
    assert (entry["action"], entry["detail"]["via"], entry["username"]) == ("scan.internal", "api", "vincent")


def test_internal_domains_wait_while_internal_scans_are_off(internal_app, admin, tmp_path, world):
    create_perimeter(admin)
    add_internal_domain(admin)
    # The operator restarts the instance without the variable: the domain stays, its scans stop.
    off = create_app(Config(data_dir=tmp_path, internal_scans=False),
                     network_factory=lambda domain: FixtureNetwork(world[domain]))
    with TestClient(off) as client:
        log_in(client)
        assert INTRANET in client.get("/domains").text
        r = post(client, f"/domains/{INTRANET}/scan", f"/domains/{INTRANET}")
        assert r.status_code == 303
        assert "désactivées" in client.get(r.headers["location"]).text
        key = new_token()
        services(client).accounts.add_token(1, "cron", token_hash(key))
        r = client.post(f"/api/v1/domains/{INTRANET}/scan", headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 403
        scans = services(client).scans
        assert len(scans.history(scans.domain(INTRANET)["id"])) == 1


# --------------------------------------------------------------- audit log
def test_sign_ins_are_logged_without_secrets(internal_app, admin):
    with TestClient(internal_app) as other:
        log_in(other, "vincent", "a wrong password")
        log_in(other, "nobody", "whatever it is")
        log_in(other, "vincent", PASSWORD)
    entries = services(admin).audit.latest(10, "login")
    assert [(e["action"], e["target"]) for e in entries[:3]] == [
        ("login.ok", "vincent"), ("login.failed", "nobody"), ("login.failed", "vincent")]
    raw = json.dumps(services(admin).audit.latest(100))
    assert "a wrong password" not in raw and PASSWORD not in raw


def test_the_audit_log_is_for_administrators(admin, user):
    create_perimeter(admin)
    page = admin.get("/admin/audit?action=perimeter").text
    assert "Périmètre créé" in page and "Siège" in page
    assert "Journal d&#39;audit" in admin.get("/admin").text
    assert user.get("/admin/audit").status_code == 403


def test_every_audit_action_has_a_text():
    root = Path(__file__).resolve().parents[1] / "src" / "posture_cockpit"
    # The first argument of audit(request, "…") and record("…"), including "a" if … else "b".
    call = re.compile(r'(?:audit|record)\(\s*(?:request,\s*)?("[a-z_.]+"(?:\s+if\s+[^"]+?\s+else\s+"[a-z_.]+")?)')
    found = set()
    for path in (root / "web").rglob("*.py"):
        for first_argument in call.findall(path.read_text(encoding="utf-8")):
            found |= set(re.findall(r'"([a-z_.]+)"', first_argument))
    assert {"login.failed", "scan.internal", "scan", "perimeter.created", "token.created"} <= found
    for lang in LOCALES:
        assert sorted(a for a in found if f"audit.action.{a}" not in interface_texts(lang)) == [], lang
