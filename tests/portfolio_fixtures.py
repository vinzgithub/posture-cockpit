# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Bulk synthetic schema-5 data for the real portfolio SQL/CPU benchmarks."""
import json
from datetime import timedelta

from posture_cockpit.core import scoring
from worlds import DOMAIN, changed, healthy, run


def populate(s, count, now, *, internal_every=10):
    findings = list(run(changed(healthy(), dns={f"_dmarc.{DOMAIN} TXT": []})).values())
    a = scoring.assess(findings)
    check_json = json.dumps({f.check_id: f.status.value for f in findings})
    healthy_checks = json.dumps({f.check_id: "info" if f.check_id == "mail.mx" else "ok" for f in findings})
    with s.db.transaction():
        if internal_every:
            s.db.execute("INSERT INTO perimeters(id,name,networks,created_at) VALUES(1,'SECRET_PERIMETER',"
                         "'10.0.0.0/8',?)", (now.isoformat(),))
        domains, scans, finding_rows, states, schedules, runs, events = [], [], [], [], [], [], []
        for n in range(1, count + 1):
            internal = bool(internal_every and n % internal_every == 0)
            name = f"{'secret' if internal else 'domain'}-{n:04}.example"
            domains.append((n, name, now.isoformat(), 1 if internal else None))
            for j in range(3):
                scan_id = (n - 1) * 3 + j + 1
                at = now - timedelta(days=2 - j)
                scans.append((scan_id, n, at.isoformat(), a.score, a.grade, a.coverage))
                for k in range(10):
                    state_at = at + timedelta(seconds=k)
                    checks = healthy_checks if k < 9 else check_json
                    states.append((scan_id, state_at.isoformat(), "scan" if k == 0 else "recheck",
                                   100 if k < 9 else a.score, "A", a.coverage, checks))
            for f in findings:
                finding_rows.append((scan_id, f.check_id, f.category, f.weight, f.status.value,
                                     json.dumps(f.outcome_json())))
            failures = 1 if n % 7 == 0 else 0
            schedules.append((n, (now - timedelta(days=3)).isoformat(),
                              (now + timedelta(hours=3 if n % 2 else -3)).isoformat(), failures))
            runs.append((n, now.strftime("%Y-%m-%dT%H:%M"), "failed" if failures else "done", f"claim-{n}",
                         (now - timedelta(days=1)).isoformat(), None if failures else scan_id))
            for k, severity in enumerate(("critical", "warning", "info")):
                events.append((n, f"fixture-{k}", severity, now.isoformat(), now.isoformat()))
        s.db.executemany("INSERT INTO domains(id,name,created_at,perimeter_id) VALUES(?,?,?,?)", domains)
        s.db.executemany("INSERT INTO scans(id,domain_id,started_at,score,grade,coverage,duration_ms,version,engine) "
                         "VALUES(?,?,?,?,?,?,1,'0.5.0',4)", scans)
        s.db.executemany("INSERT INTO findings(scan_id,check_id,category,weight,status,outcome) VALUES(?,?,?,?,?,?)",
                         finding_rows)
        s.db.executemany("INSERT INTO scan_states(scan_id,at,origin,score,grade,coverage,checks,engine,evaluation,"
                         "metrics) VALUES(?,?,?,?,?,?,?,4,'complete','{}')", states)
        s.db.executemany("INSERT INTO schedules(domain_id,updated_at,next_run_at,failures,frequency,at_minute,enabled) "
                         "VALUES(?,?,?,?,'daily',300,1)", schedules)
        s.db.executemany("INSERT INTO schedule_runs(domain_id,slot,state,claim,claimed_at,scan_id,owner,finished_at) "
                         "VALUES(?,?,?,?,?,?,'fixture',NULL)", runs)
        s.db.executemany("INSERT INTO events(domain_id,subject,severity,opened_at,updated_at,category,kind,state) "
                         "VALUES(?,?,?,?,?,'security','check','open')", events)
