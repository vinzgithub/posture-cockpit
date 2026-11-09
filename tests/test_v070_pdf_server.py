# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""PDF reports on a running server (version 0.7.0, corrective 3).

tests/pdf_server.py runs an instance as a separate process, as in production: one uvicorn worker, one event
loop. example.org lists 3,000 MX names: its report, 117 pages, held that loop for six seconds before this
correction. What is checked here, from outside, as a person or a monitor sees it:

- two reports at once (alice and bob): /healthz keeps answering at once, all along; a third person and a
  second report of the same person are refused at once, without a process; a recheck runs as usual; once
  the two are made, the next report is made;
- a person who goes away: the process of the report is killed, the place given back;
- the application stopped (SIGTERM) or killed (SIGKILL) while reports are made: no process of a report left;
- WeasyPrint is never imported in the process of the application.

The thresholds of time are wide on purpose (the machines of the CI are shared): /healthz within 1 second at
most, where the report held it six; what was measured is printed with the results (-s, or -rA).
"""

from __future__ import annotations

import contextlib
import json
import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from helpers import PASSWORD
from worlds import DOMAIN

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc to count the processes")

HERE = Path(__file__).resolve().parent
LIGHT = "light.example"
WORKER = "posture_cockpit.report.worker"


class Server:
    """tests/pdf_server.py in a process of its own."""

    def __init__(self, folder: Path, mx_count: int):
        self.folder = folder
        command = [sys.executable, str(HERE / "pdf_server.py"), str(folder), str(mx_count)]
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL,  # noqa: S603 - this test's own server
                                        stderr=(folder / "log").open("w"))
        deadline = time.monotonic() + 120
        while not (folder / "port").exists():
            assert self.process.poll() is None, (folder / "log").read_text()
            assert time.monotonic() < deadline, "the server did not start"
            time.sleep(0.1)
        self.url = f"http://127.0.0.1:{(folder / 'port').read_text()}"
        while True:
            try:
                if httpx.get(self.url + "/healthz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert time.monotonic() < deadline, "the server does not answer"
            time.sleep(0.1)

    def client(self, name: str) -> httpx.Client:
        client = httpx.Client(base_url=self.url, timeout=120, trust_env=False, follow_redirects=True)
        csrf = re.search(r'name="csrf" content="([^"]+)"', client.get("/login").text).group(1)
        response = client.post("/login", data={"csrf": csrf, "username": name, "password": PASSWORD},
                               follow_redirects=False)
        assert response.status_code == 303, response.text
        return client

    def workers(self) -> list[int]:
        """The processes of reports the server started and that still run."""
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / "status").read_text()
                command = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode()
            except OSError:
                continue
            parent = int(re.search(r"PPid:\s+(\d+)", status).group(1))
            state = re.search(r"State:\s+(\w)", status).group(1)
            if WORKER in command and state != "Z" and parent in (self.process.pid, 1):
                found.append(int(entry.name))
        return found

    def stop(self, sig: int = signal.SIGTERM, wait: float = 90) -> int:
        if self.process.poll() is None:
            self.process.send_signal(sig)
        return self.process.wait(timeout=wait)


@pytest.fixture
def server(tmp_path):
    started = []

    def start(mx_count: int = 3000) -> Server:
        folder = tmp_path / f"s{len(started)}"
        folder.mkdir()
        started.append(Server(folder, mx_count))
        return started[-1]

    yield start
    for s in started:
        s.stop(signal.SIGKILL, wait=30)


def download(client: httpx.Client, path: str = f"/domains/{DOMAIN}/report.pdf") -> tuple[float, httpx.Response]:
    started = time.monotonic()
    response = client.get(path)
    return time.monotonic() - started, response


def until(condition, seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "not in time"
        time.sleep(0.05)


def test_two_heavy_reports_never_hold_the_server(server):
    """R3, S04, T05 (corrective 3, criteria 2 and 4, review 4): alice and bob download the report of 3,000 MX
    at the same time. All along, /healthz answers within 1 second (it waited six before); vincent is refused
    at once (the instance makes its two), alice too (hers is being made), and no third process starts; a
    recheck of vincent takes its usual time. Both reports arrive, then vincent gets his."""
    s = server(3000)
    alice, bob, vincent = s.client("alice"), s.client("bob"), s.client("vincent")
    results: dict[str, tuple[float, httpx.Response]] = {}
    threads = [threading.Thread(target=lambda c=c, n=n: results.__setitem__(n, download(c)))
               for n, c in (("alice", alice), ("bob", bob))]
    for thread in threads:
        thread.start()
    until(lambda: len(s.workers()) == 2)
    latencies, stop = [], threading.Event()

    def poll() -> None:
        with httpx.Client(base_url=s.url, timeout=30, trust_env=False) as monitor:
            while not stop.is_set():
                started = time.monotonic()
                assert monitor.get("/healthz").status_code == 200
                latencies.append(time.monotonic() - started)
                time.sleep(0.05)

    poller = threading.Thread(target=poll)
    poller.start()
    refused = {}
    for name, client in (("vincent", vincent), ("alice", alice)):
        started = time.monotonic()
        response = client.get(f"/domains/{DOMAIN}/report.pdf", follow_redirects=False)
        refused[name] = time.monotonic() - started
        assert response.status_code == 303 and response.headers["location"] == f"/domains/{DOMAIN}"
    csrf = re.search(r'name="csrf" content="([^"]+)"', vincent.get(f"/domains/{LIGHT}").text).group(1)
    started = time.monotonic()
    assert vincent.post(f"/domains/{LIGHT}/verify/mail.spf", data={"csrf": csrf}).status_code in (200, 303)
    recheck = time.monotonic() - started
    assert len(s.workers()) == 2  # no process for the refused ones
    for thread in threads:
        thread.join(timeout=120)
    stop.set()
    poller.join()
    for name in ("alice", "bob"):
        _, response = results[name]
        assert response.status_code == 200 and response.content.startswith(b"%PDF-"), name
        assert response.headers["content-disposition"].startswith(f'attachment; filename="posture-{DOMAIN}-')
    until(lambda: not s.workers(), 10)
    _, response = download(vincent)
    assert response.status_code == 200 and response.content.startswith(b"%PDF-")
    print(f"\nreports {results['alice'][0]:.1f} s and {results['bob'][0]:.1f} s; /healthz: {len(latencies)} calls, "
          f"max {max(latencies) * 1000:.0f} ms, median {statistics.median(latencies) * 1000:.0f} ms; refusals "
          f"{refused['vincent'] * 1000:.0f} and {refused['alice'] * 1000:.0f} ms; recheck {recheck * 1000:.0f} ms")
    assert len(latencies) >= 10 and max(latencies) < 1.0
    assert max(refused.values()) < 1.0 and recheck < 2.0


def test_the_refusals_say_why(server):
    """R5 (corrective 3, A3): the page a refused report came back to says why: the instance busy, or the
    previous report of this person still being made."""
    s = server(3000)
    alice, bob, vincent = s.client("alice"), s.client("bob"), s.client("vincent")
    threads = [threading.Thread(target=download, args=(c,)) for c in (alice, bob)]
    for thread in threads:
        thread.start()
    until(lambda: len(s.workers()) == 2)
    assert "déjà en cours de création sur cette instance" in download(vincent)[1].text
    assert "Votre rapport PDF précédent est encore en cours de création" in download(alice)[1].text
    for thread in threads:
        thread.join(timeout=120)


def test_a_person_who_goes_away_frees_the_report(server):
    """S04 (corrective 3, A4): alice asks for the report, then goes away before it is ready: its process is
    killed within a second and her place given back, so her next report is made."""
    s = server(3000)
    alice = s.client("alice")
    cookie = "; ".join(f"{k}={v}" for k, v in alice.cookies.items())
    host, port = s.url.removeprefix("http://").split(":")
    raw = socket.create_connection((host, int(port)))
    raw.sendall(f"GET /domains/{DOMAIN}/report.pdf HTTP/1.1\r\nHost: {host}\r\nCookie: {cookie}\r\n\r\n".encode())
    until(lambda: len(s.workers()) == 1)
    raw.close()
    started = time.monotonic()
    until(lambda: not s.workers(), 5)
    print(f"\nprocess gone {(time.monotonic() - started) * 1000:.0f} ms after the client")
    _, response = download(alice)
    assert response.status_code == 200 and response.content.startswith(b"%PDF-")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGKILL], ids=["SIGTERM", "SIGKILL"])
def test_no_report_outlives_the_application(server, sig):
    """R3 (corrective 3, review 2): the application stopped (SIGTERM: uvicorn lets the requests in progress end,
    then the processes left are killed) or killed (SIGKILL: the system kills the processes of the reports,
    PR_SET_PDEATHSIG): no process of a report is left."""
    s = server(3000)
    clients = [s.client("alice"), s.client("bob")]
    threads = [threading.Thread(target=lambda c=c: _quietly(download, c)) for c in clients]
    for thread in threads:
        thread.start()
    until(lambda: len(s.workers()) == 2)
    workers = s.workers()
    s.stop(sig)
    until(lambda: not any(Path(f"/proc/{pid}").exists() and _running(pid) for pid in workers), 10)
    for thread in threads:
        thread.join(timeout=30)


def test_weasyprint_is_never_imported_in_the_application(server):
    """R3 (corrective 3, criterion 1): after reports of every kind (latest, history, a heavy one), the process
    of the application has never imported WeasyPrint."""
    s = server(300)
    vincent = s.client("vincent")
    assert download(vincent)[1].content.startswith(b"%PDF-")
    history = vincent.get(f"/domains/{LIGHT}/history").text
    scan_id = re.search(rf"/domains/{re.escape(LIGHT)}/history/(\d+)", history).group(1)
    assert download(vincent, f"/domains/{LIGHT}/history/{scan_id}/report.pdf")[1].content.startswith(b"%PDF-")
    s.stop(signal.SIGTERM)
    assert json.loads((s.folder / "modules").read_text()) == {"weasyprint": False}


def _running(pid: int) -> bool:
    try:
        return re.search(r"State:\s+(\w)", Path(f"/proc/{pid}/status").read_text()).group(1) != "Z"
    except OSError:
        return False


def _quietly(function, *args) -> None:
    with contextlib.suppress(httpx.HTTPError):  # the server stopped while answering
        function(*args)

