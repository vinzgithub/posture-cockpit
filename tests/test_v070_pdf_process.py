# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""PDF reports laid out in a process of their own (version 0.7.0, corrective 3).

The application renders the HTML of a report and report/worker.py, a process of its own started by
report/jobs.py, lays the PDF out: never WeasyPrint in the event loop. What is checked here, in this process
(tests/test_v070_pdf_server.py checks a running server):

- the process: the files it may fetch (report.css and the fonts, by canonical path), nothing from the
  network; its limit of memory; the meaning of its exit statuses;
- make_pdf: the same PDF as before (the content of every page), the deadline, the bounded reading of the
  PDF and of the errors while the HTML is written, cancellation (once or again and again) and the stop of
  the application, never a process left behind;
- the limiter: a few at once, one per account, a refusal that takes nothing, a place given back once;
- the two routes and the unreadable scan: what they answer when the report is refused, late, failed or
  unavailable, the audit of an internal perimeter, the names of the files, the authorizations checked
  before any place is taken;
- the three settings: their defaults, their bounds, a wrong value that stops the start.
"""

import asyncio
import contextlib
import http.server
import json
import os
import re
import sys
import threading
import time
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import DEMO, PASSWORD, log_out, setup_account
from posture_cockpit import report as report_module
from posture_cockpit.config import REPORT_SETTINGS, Config, parse_report_setting
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.report import REPORT_DIR, ReportUnavailable, jobs, render_html, unreadable_html, worker
from posture_cockpit.storage import CorruptScan
from posture_cockpit.web.app import create_app
from posture_cockpit.web.limits import ReportLimiter, TooManyReports
from posture_cockpit.web.routes import report as routes
from smtp_reference import corpus
from test_v070_smtp_display import Instance
from worlds import DOMAIN

PY = sys.executable
FROZEN = datetime(2026, 11, 9, 16, 30, tzinfo=UTC)


def contents(pdf: bytes) -> list[bytes]:
    """The content of each page of a PDF: its streams of text and drawing, decompressed. Two layouts of the
    same HTML differ only in their dates, the stamp of their fonts and their offsets, never in these."""
    found = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        try:
            data = zlib.decompress(match.group(1))
        except zlib.error:
            continue
        if all(re.search(op, data) for op in (rb"\bBT\b", rb"\bTf\b", rb"\bET\b")):
            found.append(data)
    return found


def in_process(html: str) -> bytes:
    """The PDF of ``html`` laid out here, as build_pdf did before (the reference)."""
    from weasyprint import HTML

    return HTML(string=html, base_url=str(REPORT_DIR)).write_pdf()


def make(html: str = "<p>x</p>", **options) -> bytes:
    return asyncio.run(jobs.make_pdf(html, **{"timeout": 60, "memory_mb": 1024, **options}))


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return Path(f"/proc/{pid}/stat").exists() and Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"


def script(code: str) -> list[str]:
    return [PY, "-c", code]


SLEEPER = script("import time; time.sleep(60)")


# ------------------------------------------------------------------ the process and what it may read
def test_the_process_reads_the_files_of_the_report_only(tmp_path):
    """S04, S05 (corrective 3, A6): report.css and the fonts, by their canonical path under the folder of the
    report; never another file of the machine, a path that leaves the folder (``..``, a link), another kind
    of file of the folder, a folder, another scheme or another host."""
    for name in ("report.css", "fonts/newsreader-latin-400-normal.woff"):
        assert worker.report_file((REPORT_DIR / name).as_uri()) == (REPORT_DIR / name).resolve()
    outside = tmp_path / "secret.css"
    outside.write_text("body {}")
    root = tmp_path / "report"
    (root / "fonts").mkdir(parents=True)
    (root / "report.css").write_text("p {}")
    (root / "fonts" / "link.css").symlink_to(outside)
    (root / "page.html").write_text("<p>")
    assert worker.report_file((root / "report.css").as_uri(), root) == (root / "report.css").resolve()
    for url in [(root / "fonts" / "link.css").as_uri(), (root / "fonts" / ".." / ".." / "secret.css").as_uri(),
                (root / "page.html").as_uri(), (root / "fonts").as_uri(), (root / "missing.css").as_uri(),
                outside.as_uri(), "file:///etc/passwd", "file://evil.example/report.css",
                "http://127.0.0.1/report.css", "https://example.org/a.woff", "data:text/css,p{}", "ftp://x/a.css"]:
        with pytest.raises(ValueError, match="not a file of the report"):
            worker.report_file(url, root)


def test_the_process_never_fetches_from_the_network():
    """S05, S04 (corrective 3, A6): an HTML naming a stylesheet, an image and a font on a server: the PDF is
    made, and the server never receives a request."""
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    html = (f'<html><head><link rel="stylesheet" href="{base}/a.css"><style>@font-face {{ font-family: x; '
            f'src: url("{base}/f.woff"); }}</style></head><body><img src="{base}/i.png">'
            '<img src="file:///etc/passwd"><p>x</p></body></html>')
    try:
        assert make(html).startswith(b"%PDF-")
    finally:
        server.shutdown()
    assert hits == []


def test_the_same_pages_as_before(instance_for):
    """F05, T05 (corrective 3): for a usual scan, a historical one, 4,000 addresses (an evidence bounded) and an
    unreadable scan, the PDF made by the process has the same pages, with the same content, as the PDF laid
    out in the application before."""
    worlds = {name: (world, probe) for name, world, probe in corpus()}
    for name, historical in (("F05.10 OK enforce", False), ("F05.08 timeout", True),
                             ("4,000 addresses on one MX", False)):
        i = instance_for(worlds[name][0])
        scan = i.scans.get(i.scans.latest_id(i.scans.domain(DOMAIN)["id"]))
        html = render_html(i.app.state.services.catalog, "fr", scan, historical=historical)
        made, before = make(html), in_process(html)
        assert contents(made) == contents(before) and len(contents(made)) >= 5, name
    catalog = i.app.state.services.catalog
    assert contents(make(unreadable_html(catalog, "en"))) == contents(in_process(unreadable_html(catalog, "en")))


@pytest.fixture
def instance_for(tmp_path):
    made = []

    def scanned(world: dict) -> Instance:
        made.append(Instance(tmp_path / f"i{len(made)}"))
        made[-1].scan(world)
        return made[-1]

    yield scanned
    for i in made:
        i.close()


# ------------------------------------------------------------------ make_pdf: deadline, limits, cancellation
def test_the_deadline_kills_the_process():
    """R3, S04 (corrective 3, review 1 and 2): a process still running at the deadline is killed, and make_pdf
    returns once it is gone: nothing runs after it."""
    started = time.monotonic()
    with pytest.raises(jobs.ReportTimeout):
        make(timeout=0.5, command=SLEEPER)
    assert time.monotonic() - started < 1.5 and jobs.running() == 0


def test_the_pdf_is_read_within_its_limit_while_the_html_is_written():
    """S04 (corrective 3, review 1): a process that writes without end is killed once it passes the limit of
    the PDF, at once, the PDF never held whole, five times over: its pipe, left full when the reading stops, is
    read to its end once it is killed (up to Python 3.11, waiting for a process with a full pipe never ends);
    8 MiB of HTML written while the process answers 8 MiB and writes 1 MiB of errors: no side waits for the
    other."""
    endless = script("import sys\nwhile True: sys.stdout.buffer.write(b'%PDF-' * 100000)")
    for _ in range(5):
        started = time.monotonic()
        with pytest.raises(jobs.ReportFailed) as failure:
            make(command=endless, max_output=2 * 2**20, timeout=20)
        assert failure.value.reason == "too_large" and time.monotonic() - started < 5 and jobs.running() == 0
    echo = script("import sys\nsys.stdout.buffer.write(b'%PDF-')\nfor _ in range(128):\n"
                  "    sys.stderr.buffer.write(b'e' * 8192)\n    sys.stdout.buffer.write(sys.stdin.buffer.read(65536))")
    html = "h" * (8 * 2**20)
    assert make(html, command=echo, timeout=20) == b"%PDF-" + html.encode()


def test_the_errors_are_kept_to_their_end():
    """S04 (corrective 3): 5 MiB of errors then a failure: ReportFailed with the exit status, and only the last
    8 KiB of the errors, for the log."""
    noisy = script("import sys\nsys.stderr.write('x' * 5 * 2**20 + 'the end')\nsys.exit(7)")
    with pytest.raises(jobs.ReportFailed) as failure:
        make(command=noisy)
    assert failure.value.reason == "exit 7" and len(failure.value.detail) == jobs.ERROR_TAIL
    assert failure.value.detail.endswith("the end")


def test_the_exit_statuses_of_the_process():
    """S04 (corrective 3): WeasyPrint missing gives ReportUnavailable (error.pdf_unavailable, as before); HTML
    beyond its limit, too little memory, an empty answer: ReportFailed, each with its reason."""
    blocked = script("import sys, runpy\nsys.modules['weasyprint'] = None\n"
                     "sys.argv = ['worker', '1024', '60']\nrunpy.run_module('posture_cockpit.report.worker', "
                     "run_name='__main__')")
    with pytest.raises(ReportUnavailable, match="WeasyPrint unavailable"):
        make(command=blocked)
    small = script("import sys\nimport posture_cockpit.report.worker as w\nw.MAX_INPUT = 10\n"
                   "sys.exit(w.main(['1024', '60']))")
    with pytest.raises(jobs.ReportFailed, match="input_too_large"):
        make("x" * 100, command=small)
    with pytest.raises(jobs.ReportFailed) as failure:
        make(memory_mb=64)  # the real process, with 64 MiB of address space: not even WeasyPrint fits
    assert failure.value.reason == "no_memory" or failure.value.reason.startswith("exit ")
    assert jobs.running() == 0
    with pytest.raises(jobs.ReportFailed, match="empty"):
        make(command=script("pass"))


def test_the_memory_of_the_process_is_bounded_not_that_of_the_server():
    """S04 (corrective 3, A2): the limit of address space applies to the process only: a report within it is
    made, the same process with half of what it needs fails, and the server keeps its own limit."""
    import resource

    before = resource.getrlimit(resource.RLIMIT_AS)
    measure = script("import resource, sys\nsys.stdout.write('%PDF-' + str(resource.getrlimit(resource.RLIMIT_AS)[0]))")
    assert make(command=measure) == b"%PDF-" + str(before[0]).encode()  # another program: the limit it inherits
    limited = script("import sys\nimport posture_cockpit.report.worker as w\nw.bound(512, 65)\nimport resource\n"
                     "sys.stdout.write('%PDF-' + str(resource.getrlimit(resource.RLIMIT_AS)[0]))")
    assert make(command=limited) == b"%PDF-" + str(512 * 2**20).encode()
    assert resource.getrlimit(resource.RLIMIT_AS) == before


@pytest.mark.parametrize("times", [1, 3])
def test_a_cancelled_report_leaves_no_process(times):
    """R3, S04 (corrective 3, review 2, A4): a report cancelled once, or again and again while its process is
    being stopped, raises CancelledError only once its process is gone."""
    async def scenario():
        task = asyncio.ensure_future(jobs.make_pdf("x", timeout=30, memory_mb=1024, command=SLEEPER))
        await asyncio.sleep(0.5)
        pid = next(iter(jobs._running)).pid
        for _ in range(times):
            task.cancel()
            await asyncio.sleep(0)
        with pytest.raises(asyncio.CancelledError):
            await task
        return pid

    pid = asyncio.run(scenario())
    assert not alive(pid) and jobs.running() == 0


def test_the_stop_of_the_application_kills_the_reports():
    """R3 (corrective 3, review 2): stop_all kills every report in progress and waits until they are gone; the
    reports end with a failure, never left behind."""
    async def scenario():
        tasks = [asyncio.ensure_future(jobs.make_pdf("x", timeout=30, memory_mb=1024, command=SLEEPER))
                 for _ in range(2)]
        await asyncio.sleep(0.5)
        pids = [p.pid for p in jobs._running]
        await jobs.stop_all()
        outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        return pids, outcomes

    pids, outcomes = asyncio.run(scenario())
    assert len(pids) == 2 and not any(alive(p) for p in pids) and jobs.running() == 0
    assert all(isinstance(o, jobs.ReportFailed) and o.reason == "exit -9" for o in outcomes)


# ------------------------------------------------------------------ the limiter
def test_the_limiter_of_the_reports():
    """S04 (corrective 3, A2, A3): two at once on the instance and one per account by default; a refusal takes
    nothing; the place is given back once, however many times the release is called."""
    limiter = ReportLimiter()
    alice = limiter.take("user:1")
    with pytest.raises(TooManyReports) as refusal:
        limiter.take("user:1")
    assert refusal.value.reason == "account" and limiter.running == 1
    bob = limiter.take("user:2")
    with pytest.raises(TooManyReports) as refusal:
        limiter.take("user:3")
    assert refusal.value.reason == "busy" and limiter.running == 2
    alice()
    alice()
    assert limiter.running == 1
    limiter.take("user:3")
    bob()
    assert limiter.running == 1 and limiter.take("user:1")


# ------------------------------------------------------------------ the routes
@pytest.fixture
def signed_in(client):
    setup_account(client)
    return client


def scanned(client) -> int:
    from helpers import post

    post(client, "/domains", "/domains", domain=DEMO)
    s = client.app.state.services
    return s.scans.latest_id(s.scans.domain(DEMO)["id"])


@pytest.fixture
def frozen(monkeypatch):
    """The report says when it was made: the same instant for the route and for the reference."""
    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):
            return FROZEN if tz is None else FROZEN.astimezone(tz)

    monkeypatch.setattr(report_module, "datetime", Frozen)


def test_the_routes_send_the_same_reports_as_before(signed_in, frozen):
    """T05, R6 (corrective 3): the latest scan and one of the history: 200, a PDF with the same pages as the
    PDF laid out in the application, the same names of files and headers as before."""
    scan_id = scanned(signed_in)
    s = signed_in.app.state.services
    scan = s.scans.get(scan_id)
    for path, historical, name in ((f"/domains/{DEMO}/report.pdf", False, f'filename="posture-{DEMO}-'),
                                   (f"/domains/{DEMO}/history/{scan_id}/report.pdf", True,
                                    f'-scan-{scan_id}.pdf"')):
        response = signed_in.get(path)
        assert response.status_code == 200 and response.headers["content-type"] == "application/pdf"
        assert response.headers["content-disposition"].startswith("attachment; ") and name in (
            response.headers["content-disposition"])
        html = render_html(s.catalog, "fr", scan, s.settings.report_author(), s.config.timezone,
                           historical=historical)
        assert contents(response.content) == contents(in_process(html))
    assert s.report_limiter.running == 0 and jobs.running() == 0


@pytest.mark.parametrize(("failure", "message"), [
    (jobs.ReportTimeout(), "dans le délai de 60 secondes"),
    (jobs.ReportFailed("exit 1", "boom"), "sa création a échoué"),
    (ReportUnavailable("no pango"), "la bibliothèque WeasyPrint est absente"),
])
def test_a_report_late_failed_or_unavailable_goes_back_with_its_reason(signed_in, monkeypatch, failure, message):
    """T05, R5 (corrective 3): the page the report came from says why, and the place is given back."""
    scan_id = scanned(signed_in)

    async def failing(html, **_):
        raise failure

    monkeypatch.setattr(jobs, "make_pdf", failing)
    for path, back in ((f"/domains/{DEMO}/report.pdf", f"/domains/{DEMO}"),
                       (f"/domains/{DEMO}/history/{scan_id}/report.pdf", f"/domains/{DEMO}/history/{scan_id}")):
        response = signed_in.get(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"] == back
        assert message in signed_in.get(back).text
    assert signed_in.app.state.services.report_limiter.running == 0


def test_a_report_over_the_limits_is_refused_at_once_without_a_process(signed_in, monkeypatch):
    """S04, R5 (corrective 3, A3): the instance at its maximum, or this account already waiting for a report:
    refused at once, back to the page with the reason; no process is started."""
    scan_id = scanned(signed_in)
    started = []

    async def counted(html, **_):
        started.append(html)
        return b"%PDF-"

    monkeypatch.setattr(jobs, "make_pdf", counted)
    limiter = signed_in.app.state.services.report_limiter
    others = [limiter.take("user:98"), limiter.take("user:99")]
    response = signed_in.get(f"/domains/{DEMO}/report.pdf", follow_redirects=False)
    assert response.status_code == 303 and "déjà en cours de création sur cette instance" in signed_in.get(
        f"/domains/{DEMO}").text
    for release in others:
        release()
    mine = limiter.take("user:1")
    response = signed_in.get(f"/domains/{DEMO}/history/{scan_id}/report.pdf", follow_redirects=False)
    assert response.status_code == 303 and "Votre rapport PDF précédent est encore en cours" in signed_in.get(
        f"/domains/{DEMO}/history/{scan_id}").text
    mine()
    assert started == [] and signed_in.get(f"/domains/{DEMO}/report.pdf").content == b"%PDF-"


def test_refused_requests_never_take_a_place(signed_in, monkeypatch):
    """S05, P4 (corrective 3): a request refused by the authorizations (another domain, a scan of none, no
    session) never reaches the limiter."""
    scan_id = scanned(signed_in)
    taken = []
    limiter = signed_in.app.state.services.report_limiter
    real = limiter.take
    monkeypatch.setattr(limiter, "take", lambda who: taken.append(who) or real(who))
    for path in ("/domains/other.example/report.pdf", f"/domains/{DEMO}/history/{scan_id + 9}/report.pdf",
                 f"/domains/{DEMO}/history/abc/report.pdf"):
        assert signed_in.get(path).status_code == 404, path
    log_out(signed_in)
    assert signed_in.get(f"/domains/{DEMO}/report.pdf", follow_redirects=False).status_code in (302, 303)
    assert taken == []


def test_an_unreadable_scan_gives_its_pdf_through_a_process_or_the_page(signed_in, monkeypatch):
    """R5 (corrective 3, review 5): the PDF of an unreadable scan (409) is made by a process, within the
    limits of the reports; over them, or when it fails, the page of the error (409), as when WeasyPrint is
    missing."""
    scanned(signed_in)
    s = signed_in.app.state.services

    def corrupt(*_, **__):
        raise CorruptScan(1)

    monkeypatch.setattr(s.scans, "latest", corrupt)
    response = signed_in.get(f"/domains/{DEMO}/report.pdf")
    assert response.status_code == 409 and response.headers["content-type"] == "application/pdf"
    assert contents(response.content) == contents(in_process(unreadable_html(s.catalog, "fr")))
    others = [s.report_limiter.take("user:98"), s.report_limiter.take("user:99")]
    response = signed_in.get(f"/domains/{DEMO}/report.pdf")
    assert response.status_code == 409 and response.headers["content-type"].startswith("text/html")
    for release in others:
        release()
    assert s.report_limiter.running == 0


def test_the_report_of_an_internal_perimeter_is_audited_once_made(tmp_path, monkeypatch):
    """S05 (corrective 3, review 5): the audit of an internal perimeter is written once the PDF is made,
    before it is sent, as before; a report refused, late or failed writes none."""
    from test_perimeters import INTRANET, add_internal_domain, create_perimeter, intranet_world

    world = {INTRANET: intranet_world()}
    app = create_app(Config(data_dir=tmp_path, internal_scans=True),
                     network_factory=lambda d: FixtureNetwork(world.get(d, {"dns": {f"{d} SOA": None}})))
    with TestClient(app) as client:
        from helpers import post

        setup_account(client)
        post(client, "/admin/confirm", "/admin/confirm", password=PASSWORD)
        create_perimeter(client)
        add_internal_domain(client)
        s = app.state.services
        audited = lambda: [e for e in s.audit.latest(50) if e["action"] == "report.internal"]  # noqa: E731
        assert client.get(f"/domains/{INTRANET}/report.pdf").status_code == 200 and len(audited()) == 1

        async def late(html, **_):
            raise jobs.ReportTimeout()

        monkeypatch.setattr(jobs, "make_pdf", late)
        assert client.get(f"/domains/{INTRANET}/report.pdf", follow_redirects=False).status_code == 303
        others = [s.report_limiter.take("user:98"), s.report_limiter.take("user:99")]
        assert client.get(f"/domains/{INTRANET}/report.pdf", follow_redirects=False).status_code == 303
        for release in others:
            release()
        assert len(audited()) == 1


def test_a_person_who_goes_away_stops_the_report(signed_in, monkeypatch):
    """S04 (corrective 3, A4): the person went away (the server reports http.disconnect) before the PDF was
    ready: the report is cancelled, its process killed, the place given back, nothing sent."""
    scanned(signed_in)
    pids = []

    async def slow(html, **options):
        task = asyncio.ensure_future(real(html, **{**options, "command": SLEEPER}))
        await asyncio.sleep(0.3)
        pids.extend(p.pid for p in jobs._running)
        return await task

    real = jobs.make_pdf
    monkeypatch.setattr(jobs, "make_pdf", slow)

    async def gone_soon(request):
        await asyncio.sleep(0.6)

    monkeypatch.setattr(routes, "_gone", gone_soon)
    started = time.monotonic()
    response = signed_in.get(f"/domains/{DEMO}/report.pdf")
    assert response.status_code == routes.CLIENT_GONE and time.monotonic() - started < 5
    assert pids and not any(alive(p) for p in pids) and jobs.running() == 0
    assert signed_in.app.state.services.report_limiter.running == 0


# ------------------------------------------------------------------ the settings
REPORT_VARIABLES = [f"POSTURE_COCKPIT_{name}" for name in REPORT_SETTINGS]


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in REPORT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("POSTURE_COCKPIT_DATA_DIR", str(tmp_path))
    return monkeypatch


def test_the_settings_of_the_reports(env):
    """A5 (corrective 3, review 6): two reports at once, 60 seconds, 1,024 MiB by default; a blank variable keeps
    the default; any whole number within the bounds is taken as written."""
    config = Config.from_env()
    assert (config.max_concurrent_reports, config.report_timeout, config.report_memory_mb) == (2, 60, 1024)
    env.setenv("POSTURE_COCKPIT_REPORT_TIMEOUT", " ")
    assert Config.from_env().report_timeout == 60
    for name, (_, low, high) in REPORT_SETTINGS.items():
        for value in (low, high):
            env.setenv(f"POSTURE_COCKPIT_{name}", f" {value} ")
            assert parse_report_setting(name) == value


@pytest.mark.parametrize(("name", "value"), [
    ("MAX_CONCURRENT_REPORTS", "0"), ("MAX_CONCURRENT_REPORTS", "9"), ("MAX_CONCURRENT_REPORTS", "two"),
    ("REPORT_TIMEOUT", "9"), ("REPORT_TIMEOUT", "601"), ("REPORT_TIMEOUT", "60.5"), ("REPORT_TIMEOUT", "-60"),
    ("REPORT_MEMORY_MB", "255"), ("REPORT_MEMORY_MB", "8193"), ("REPORT_MEMORY_MB", "1e3"),
    ("REPORT_MEMORY_MB", "１０２４"), ("REPORT_MEMORY_MB", "99999999999"),
])
def test_a_wrong_setting_stops_the_start(env, tmp_path, name, value):
    """A5 (corrective 3, review 6): a value out of bounds or not a whole number stops the start with a message
    naming the variable and its bounds, never corrected silently; so does a Config built with one."""
    env.setenv(f"POSTURE_COCKPIT_{name}", value)
    _, low, high = REPORT_SETTINGS[name]
    with pytest.raises(ValueError, match=rf"POSTURE_COCKPIT_{name}: .* from {low} to {high}"):
        create_app()
    with pytest.raises(ValueError, match=f"POSTURE_COCKPIT_{name}"):
        Config(data_dir=tmp_path, **{name.lower(): high + 1})


def test_the_limiter_of_the_application_follows_the_setting(tmp_path):
    """A2 (corrective 3): the instance makes as many reports at once as the setting says."""
    app = create_app(Config(data_dir=tmp_path, max_concurrent_reports=5))
    assert app.state.services.report_limiter.concurrent == 5
    assert app.state.services.report_limiter.per_account == 1


def test_the_process_keeps_only_what_it_needs_of_the_environment(monkeypatch):
    """S05 (corrective 3, A6): no variable of the configuration nor any secret reaches the process; the folder of
    the code of the application comes first on its path."""
    monkeypatch.setenv("POSTURE_COCKPIT_SETUP_CODE", "SECRET-SETUP-CODE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    show = script("import json, os, sys\nsys.stdout.write('%PDF-' + json.dumps(dict(os.environ)))")
    seen = json.loads(make(command=show)[5:])
    assert not any(k.startswith("POSTURE_COCKPIT_") or "SECRET" in k for k in seen)
    assert seen["PYTHONPATH"] == str(Path(report_module.__file__).resolve().parents[2])
    assert set(seen) <= {*jobs.KEPT_ENVIRONMENT, "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}


def test_no_report_is_laid_out_in_the_application(signed_in):
    """R3 (corrective 3, criterion 1): the routes never call build_pdf, which lays a PDF out here."""
    scanned(signed_in)

    def forbidden(*_, **__):
        raise AssertionError("build_pdf in the application")

    with contextlib.ExitStack() as stack:
        mp = stack.enter_context(pytest.MonkeyPatch.context())
        mp.setattr(report_module, "build_pdf", forbidden)
        mp.setattr(report_module, "build_unreadable_pdf", forbidden)
        assert signed_in.get(f"/domains/{DEMO}/report.pdf").content.startswith(b"%PDF-")

