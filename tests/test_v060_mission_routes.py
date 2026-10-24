# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Phase 2: real server routes, synthetic measurements, no Internet scans."""
import re
from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import https_worlds as H
from helpers import PASSWORD, log_in, post, setup_account
from posture_cockpit.core import engine, scoring
from posture_cockpit.core.model import Outcome, Status
from posture_cockpit.security import hash_password
from worlds import DOMAIN, NOW, changed, healthy, run

ROOT = "web.https_redirect"
URL = f"/domains/{DOMAIN}/mission-control"


def seed(client, data=None):
    setup_account(client)
    s = client.app.state.services
    fs = list(run(data if data is not None else healthy()).values())
    did = s.scans.add_domain(DOMAIN, None)
    sid = s.scans.save(did, engine.ScanResult(DOMAIN, NOW, 1, fs), "0.5.0", None)
    return s, did, sid, fs


def selection(s, sid, checks=()):
    return [("scan_id", str(sid)), ("state_id", str(s.scans.current_state(sid)["id"]))] + [
        ("check", c) for c in checks]


def test_first_observation_and_bilingual_server_render(client):
    seed(client)
    page = client.get(URL)
    assert page.status_code == 200
    assert "Première observation" in page.text and "Aucune nouvelle transition" in page.text
    assert "État mesuré courant" in page.text and "100/100" in page.text
    assert "Aucune remédiation actuellement sélectionnable" in page.text
    assert "no-store" in page.headers["cache-control"]
    post(client, "/lang", URL, lang="en", back=URL)
    page = client.get(URL)
    assert "What changed" in page.text and "First observation" in page.text
    assert "No remediation is currently selectable" in page.text


def test_t23_first_step_and_t12_fifty_http_simulations_are_read_only(client, monkeypatch):
    s, _, sid, _ = seed(client, changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []}))
    before = list(s.db._conn.iterdump())
    scan = Mock(side_effect=AssertionError("real scan forbidden"))
    monkeypatch.setattr(s.scanner, "scan", scan)
    monkeypatch.setattr(s.scanner, "recheck_group", scan)
    params = selection(s, sid, ["mail.dmarc"])
    for _ in range(50):
        response = client.get(URL + "/simulate", params=params)
        assert response.status_code == 200
        assert "88/100" in response.text and "94/100" in response.text
        assert "100/100" not in response.text
    assert list(s.db._conn.iterdump()) == before
    assert not scan.called
    assert "Statut supposé après cette étape" in response.text
    assert 'method="get"' in response.text and 'class="btn btn-secondary mc-simulate"' in response.text
    assert f'action="/domains/{DOMAIN}/verify/' not in response.text


def test_t24_real_blocked_dependencies_conditional_bounds_and_fallback(client, monkeypatch):
    s, _, sid, _ = seed(client, H.site({H.V4A: H.REFUSED}))
    params = selection(s, sid, [ROOT])
    page = client.get(URL + "/simulate", params=params)
    assert page.status_code == 200
    assert "66/100" in page.text and "100/100" in page.text
    assert "ces bornes ne garantissent pas la prochaine note" in page.text
    assert "Mesures dépendantes de HTTPS" in page.text
    get = s.registry.get
    monkeypatch.setattr(s.registry, "get", lambda cid: None if cid == "tls.key" else get(cid))
    assert "FAIL est une hypothèse pessimiste de repli" in client.get(URL + "/simulate", params=params).text


def test_t25_active_plan_includes_new_fail_and_completed_root_is_separate(client):
    s, _, sid, _ = seed(client, H.site({H.V4A: H.REFUSED}))
    group = [f for f in run(H.site({H.V4A: {"versions": {"TLSv1": True}}})).values() if f.family == "https"]
    s.scans.save_rechecks(sid, group)
    page = client.get(f"/domains/{DOMAIN}").text
    assert 'data-task="tls.protocols"' in page
    assert 'class="completed-tasks"' in page
    assert 'class="task-card is-done"' in page and f'data-task="{ROOT}"' in page
    mc = client.get(URL).text
    assert 'name="check" value="tls.protocols"' in mc
    assert f'name="check" value="{ROOT}"' not in mc
    assert "Actions confirmées OK (1)" in mc


@pytest.mark.parametrize(("first", "last"), [(Status.OK, Status.FAIL), (Status.FAIL, Status.OK)])
def test_t26_gap_history_does_not_change_event_lifecycle(client, first, last):
    s, _, sid, fs = seed(client)
    f = next(f for f in fs if f.check_id == "mail.dmarc")
    if first is Status.FAIL:
        s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.FAIL, "fixture")))
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.ERROR, "fixture")))
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(last, "fixture")))
    before = list(s.db._conn.iterdump())
    page = client.get(URL)
    assert page.status_code == 200
    assert "Dernier verdict antérieur concluant" in page.text
    assert "mesure(s) intermédiaire(s) indisponible(s)" in page.text
    assert "Mesure indisponible ou interrompue" in page.text
    assert "Cet écran ne résout aucun événement" in page.text
    assert list(s.db._conn.iterdump()) == before


def test_t11_recheck_makes_submitted_state_obsolete(client):
    s, _, sid, fs = seed(client, changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []}))
    params = selection(s, sid, ["mail.dmarc"])
    s.scans.save_recheck(sid, fs[0])
    response = client.get(URL + "/simulate", params=params)
    assert response.status_code == 409 and "Rafraîchir la fiche" in response.text
    assert "94/100" not in response.text and "Projection conditionnelle" not in response.text


def test_t28_new_scheduled_scan_or_write_during_calculation_requires_refresh(client, monkeypatch):
    s, did, sid, fs = seed(client, changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []}))
    params = selection(s, sid, ["mail.dmarc"])
    real_simulate = scoring.simulate
    committed = False

    def concurrent(*args, **kwargs):
        nonlocal committed
        result = real_simulate(*args, **kwargs)
        if not committed:
            committed = True
            s.scans.save(did, engine.ScanResult(DOMAIN, NOW + timedelta(days=1), 1, fs),
                         "0.5.0", None, via="schedule")
        return result

    monkeypatch.setattr(scoring, "simulate", concurrent)
    page = client.get(URL + "/simulate", params=params)
    assert page.status_code == 409 and "L’état a changé" in page.text


@pytest.mark.parametrize("changes", [
    [("check", "mail.dmarc"), ("check", "mail.dmarc")], [("check", "unknown")],
    [("check", "tls.key")], [("check", '<script>alert(1)</script>')],
    [("check", "x")] * 21, [("unexpected", "1")], [("scan_id", "1")],
])
def test_t13_t20_invalid_or_non_candidate_selection_is_rejected(client, changes):
    s, _, sid, _ = seed(client, changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []}))
    before = list(s.db._conn.iterdump())
    response = client.get(URL + "/simulate", params=selection(s, sid) + changes)
    assert response.status_code == 400
    assert "<script>alert(1)</script>" not in response.text
    assert list(s.db._conn.iterdump()) == before


@pytest.mark.parametrize("value", ["", "-1", "0", "1 OR 1=1", "999999999999999999999", "²"])
def test_invalid_state_ids_are_bounded(client, value):
    _, _, sid, _ = seed(client)
    assert client.get(URL + "/simulate", params={"scan_id": sid, "state_id": value}).status_code == 400


def test_t16_internal_domains_and_tokens_are_not_visible_to_reader(client, monkeypatch):
    s, _, _, _ = seed(client)
    s.db.execute("INSERT INTO perimeters(name,networks,created_at) VALUES('secret','10.0.0.0/8',?)", (NOW.isoformat(),))
    s.scans.add_domain("secret.example", None, 1)
    s.accounts.create("reader", hash_password(PASSWORD))
    with TestClient(client.app) as reader:
        log_in(reader, "reader", PASSWORD)
        get = Mock(side_effect=AssertionError("must authorize before scan read"))
        monkeypatch.setattr(s.scans, "latest", get)
        for path in ["/domains/secret.example/mission-control", "/domains/missing.example/mission-control",
                     "/domains/secret.example/mission-control/simulate?scan_id=1&state_id=1"]:
            response = reader.get(path)
            assert response.status_code == 404
            assert "secret.example" not in response.text and "10.0.0.0" not in response.text
        assert not get.called


def test_routes_require_authentication_and_simulation_has_no_post(client):
    seed(client)
    anonymous = TestClient(client.app)
    assert anonymous.get(URL, follow_redirects=False).status_code == 303
    assert anonymous.get(URL + "/simulate?scan_id=1&state_id=1", follow_redirects=False).status_code == 303
    assert client.post(URL + "/simulate").status_code == 405
    assert client.post(f"/domains/{DOMAIN}/verify/mail.dmarc", data={}).status_code == 403


def test_database_history_is_bounded_and_cannot_use_another_domains_anchor(client):
    s, did, sid, fs = seed(client)
    for _ in range(32):
        s.scans.save_recheck(sid, fs[0])
    anchor = s.scans.current_state(sid)["id"]
    assert len(s.scans.state_history(did, anchor)) == 30
    other = s.scans.add_domain("other.example", None)
    assert s.scans.state_history(other, anchor) == []
    with pytest.raises(ValueError):
        s.scans.state_history(did, anchor, 31)


def test_unknown_effect_does_not_render_a_none_or_a_zero_target(client):
    s, _, sid, fs = seed(client)
    f = next(f for f in fs if f.check_id == "dns.dnssec")
    from posture_cockpit.core.model import Effort, Remedy

    s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.FAIL, "dns.dnssec.broken",
                                                      remedy=Remedy(1, Effort.EASY, expect=None))))
    page = client.get(f"/domains/{DOMAIN}")
    assert page.status_code == 200 and "None" not in page.text
    assert "Effet non déterminable" in page.text
    result = client.get(URL + "/simulate", params=selection(s, sid, ["dns.dnssec"]))
    assert result.status_code == 200
    assert "Estimation non concluante" in result.text and "0/100" not in result.text


def test_t03_comparable_observations_show_exact_delta_without_rewriting_history(client):
    s, _, sid, fs = seed(client)
    before = dict(s.scans.current_state(sid))
    f = next(f for f in fs if f.check_id == "mail.dmarc")
    s.scans.save_recheck(sid, replace(f, outcome=Outcome(Status.FAIL, "fixture")))
    page = client.get(URL)
    assert page.status_code == 200
    assert "Variation comparable de la note observée : -12 points" in page.text
    assert "Statut dégradé observé" in page.text
    assert dict(s.scans.states(sid)[0]) == {k: v for k, v in before.items() if k not in {"domain_id", "perimeter"}}


def test_t04_partial_coverage_keeps_check_transitions_without_global_delta(client):
    s, _, sid, fs = seed(client)
    group = [replace(f, outcome=Outcome(Status.ERROR if f.check_id == "mail.dmarc" else Status.FAIL, "fixture"))
             for f in fs if f.check_id in {"mail.dmarc", "tls.key"}]
    s.scans.save_rechecks(sid, group)
    page = client.get(URL)
    assert page.status_code == 200
    assert "Aucune variation globale de note affirmée" in page.text
    assert "La couverture est insuffisante pour comparer globalement" in page.text
    assert "Statut dégradé observé" in page.text


def test_three_significant_changes_then_native_see_all(client):
    s, _, sid, fs = seed(client)
    group = [replace(f, outcome=Outcome(Status.WARN, "fixture")) for f in fs if f.status is Status.OK][:6]
    s.scans.save_rechecks(sid, group)
    page = client.get(URL)
    assert page.status_code == 200 and "Voir tous les changements (6)" in page.text
    first = re.search(r'<ul class="mc-transitions">(.*?)</ul>', page.text, re.S).group(1)
    assert first.count('class="mc-transition"') == 3


def test_corrupt_state_payload_is_not_a_server_error(client):
    s, _, sid, _ = seed(client)
    # Append a corrupt fixture; never disable the historical immutability trigger.
    s.db.execute("INSERT INTO scan_states(scan_id,at,origin,engine,score,grade,coverage,evaluation,metrics,checks) "
                 "SELECT scan_id,at,origin,engine,score,grade,coverage,evaluation,metrics,'[]' "
                 "FROM scan_states WHERE scan_id=? LIMIT 1", (sid,))
    assert client.get(URL).status_code == 409
