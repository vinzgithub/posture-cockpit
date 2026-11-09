# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The robustness of the PDF processes (version 0.7.0, corrective 3, review of PR #51: R1, R2, R3).

- R1: stop_all, when the application stops, ends every report by the one way a job ends (report/jobs.py,
  _Job.reap), even when its pipes are full and the tasks that read them no longer progress, and even on
  Python 3.11, whose Process.wait() waits for every pipe; the processes still starting are not missed; the
  group of each process is killed with it; the places are given back once.
- R2: one deadline, set before the process is started, covers its start: a start slower than the deadline
  ends in ReportTimeout, the process it made stopped; a cancellation while the process starts, very early,
  or again and again, leaves no process and no place taken; the next report is made.
- R3: the process checks the result of prctl(PR_SET_PDEATHSIG), says when it is refused and goes on within
  its limits; it stops at once when the application is no longer its parent, should it have stopped while
  the process was starting; killed (SIGKILL) or stopped (SIGTERM) after that, the application takes the
  process with it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from helpers import DEMO, setup_account
from posture_cockpit.report import jobs, worker
from posture_cockpit.web.limits import ReportLimiter
from posture_cockpit.web.routes import report as routes
from test_v070_pdf_process import PY, SLEEPER, alive, make, script

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="process groups, prctl and /proc")

# Writes without end on its standard output, its standard error, or both.
FLOOD = {
    "stdout": script("import sys\nwhile True: sys.stdout.buffer.write(b'%PDF-' * 65536)"),
    "stderr": script("import sys\nwhile True: sys.stderr.buffer.write(b'e' * 65536)"),
    "both": script("import sys, threading\n"
                   "threading.Thread(target=lambda: [sys.stderr.buffer.write(b'e' * 65536) for _ in iter(int, 1)],"
                   " daemon=True).start()\nwhile True: sys.stdout.buffer.write(b'%PDF-' * 65536)"),
}


def gone(pids: list[int], seconds: float = 5) -> bool:
    deadline = time.monotonic() + seconds
    while any(alive(pid) for pid in pids):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    return True


@pytest.fixture
def stuck(monkeypatch):
    """The tasks that read the PDF and the errors never read anything: the pipes fill and stay full."""
    async def never(*_):
        await asyncio.Event().wait()

    monkeypatch.setattr(jobs, "_read", never)
    monkeypatch.setattr(jobs, "_tail", never)


@pytest.fixture
def slow_start(monkeypatch):
    """The start of the process slowed down, before or after it is created; the processes it made."""
    real = asyncio.create_subprocess_exec
    made: list[int] = []

    def slowed(before: float = 0.0, after: float = 0.0) -> list[int]:
        async def start(*args, **options):
            await asyncio.sleep(before)
            process = await real(*args, **options)
            made.append(process.pid)
            await asyncio.sleep(after)
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", start)
        return made

    return slowed


def settled() -> bool:
    """No report running nor starting."""
    return jobs.running() == 0 and not jobs._starting


# ------------------------------------------------------------------ R1: stop_all
@pytest.mark.parametrize("pipes", ["stdout", "stderr", "both"])
def test_r1_stop_all_ends_reports_whose_pipes_are_full_and_readers_stuck(stuck, pipes):
    """R1 (review of PR #51): two reports whose processes write without end on a full pipe that nobody reads:
    stop_all returns within seconds (it waited for ever on Python 3.11), both processes are gone, both reports
    end with ReportFailed("stopped"), nothing is left running."""
    async def scenario():
        tasks = [asyncio.ensure_future(jobs.make_pdf("x", timeout=60, memory_mb=1024, command=FLOOD[pipes]))
                 for _ in range(2)]
        while len(jobs.pids()) < 2:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.5)  # the pipes are full by now
        pids = jobs.pids()
        started = time.monotonic()
        await asyncio.wait_for(jobs.stop_all(), 10)
        took = time.monotonic() - started
        return pids, took, await asyncio.gather(*tasks, return_exceptions=True)

    pids, took, outcomes = asyncio.run(scenario())
    assert took < 5 and gone(pids, 1) and settled()
    assert [(type(o), getattr(o, "reason", None)) for o in outcomes] == [(jobs.ReportFailed, "stopped")] * 2


def test_r1_stop_all_waits_for_a_process_still_starting(slow_start):
    """R1, R2 (review of PR #51): the application stops while a process is being started: stop_all waits until
    it exists, then stops it with the others; the report ends with ReportFailed("stopped")."""
    made = slow_start(before=0.5)

    async def scenario():
        task = asyncio.ensure_future(jobs.make_pdf("x", timeout=60, memory_mb=1024, command=SLEEPER))
        await asyncio.sleep(0.1)
        assert jobs._starting and not made
        await asyncio.wait_for(jobs.stop_all(), 10)
        return await asyncio.gather(task, return_exceptions=True)

    [outcome] = asyncio.run(scenario())
    assert isinstance(outcome, jobs.ReportFailed) and outcome.reason == "stopped"
    assert len(made) == 1 and gone(made, 1) and settled()


def test_r1_the_group_of_the_process_goes_with_it(tmp_path):
    """R1 (review of PR #51): a process that started another, which keeps its pipes open: at the deadline both
    are killed (the process has a group of its own) and the report ends at once."""
    child = tmp_path / "child"
    command = script("import subprocess, sys, time\n"
                     f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                     f"open({str(child)!r}, 'w').write(str(p.pid))\ntime.sleep(60)")
    started = time.monotonic()
    with pytest.raises(jobs.ReportTimeout):
        make(command=command, timeout=1)
    assert time.monotonic() - started < 3
    assert gone([int(child.read_text())], 3) and settled()


def test_r1_places_are_given_back_once_when_the_application_stops(stuck):
    """R1 (review of PR #51): reports holding their places in the limiter, stopped by stop_all with their pipes
    full: each place is given back once, after its process is gone."""
    limiter = ReportLimiter()
    released: list[str] = []

    async def route(who: str) -> None:
        release = limiter.take(who)
        try:
            await jobs.make_pdf("x", timeout=60, memory_mb=1024, command=FLOOD["both"])
        except jobs.ReportFailed:
            pass
        finally:
            assert not any(alive(pid) for pid in pids)
            released.append(who)
            release()
            release()

    async def scenario():
        tasks = [asyncio.ensure_future(route(who)) for who in ("user:1", "user:2")]
        while len(jobs.pids()) < 2:
            await asyncio.sleep(0.01)
        pids.extend(jobs.pids())
        await jobs.stop_all()
        await asyncio.gather(*tasks)

    pids: list[int] = []
    asyncio.run(scenario())
    assert sorted(released) == ["user:1", "user:2"] and limiter.running == 0 and settled()


# ------------------------------------------------------------------ R2: the deadline covers the start
@pytest.mark.parametrize(("before", "after"), [(1.0, 0.0), (0.0, 1.0)], ids=["before the process", "after it"])
def test_r2_a_start_slower_than_the_deadline_ends_in_timeout(slow_start, before, after):
    """R2 (review of PR #51): the start takes 1 s, slowed before the process is created or after; the deadline
    is 0.3 s: ReportTimeout, once the start is over (it is never cancelled half-way), the process it made
    stopped; nothing left; the next report is made."""
    made = slow_start(before=before, after=after)
    started = time.monotonic()
    with pytest.raises(jobs.ReportTimeout):
        make(command=SLEEPER, timeout=0.3)
    took = time.monotonic() - started
    assert 0.9 < took < 3 and len(made) == 1 and gone(made, 1) and settled()
    assert make().startswith(b"%PDF-")


def test_r2_the_deadline_counts_from_before_the_start(slow_start):
    """R2 (review of PR #51): a start of 0.5 s within a deadline of 1 s leaves 0.5 s to the process: a process
    that sleeps ends in ReportTimeout after 1 s, not 1.5 s."""
    made = slow_start(before=0.5)
    started = time.monotonic()
    with pytest.raises(jobs.ReportTimeout):
        make(command=SLEEPER, timeout=1)
    assert time.monotonic() - started < 1.4 and gone(made, 1) and settled()


@pytest.mark.parametrize("when", ["before it runs", "while the process starts", "again and again while it starts"])
def test_r2_a_very_early_cancellation_leaves_nothing(slow_start, when):
    """R2 (review of PR #51): a report cancelled before it even runs, while its process starts, or again and
    again then: CancelledError once, no process left, no start pending; the next report is made."""
    made = slow_start(after=0.5)

    async def scenario():
        task = asyncio.ensure_future(jobs.make_pdf("x", timeout=30, memory_mb=1024, command=SLEEPER))
        if when != "before it runs":
            await asyncio.sleep(0.2)
            assert made  # the process exists, its start is not over
        for _ in range(3 if when.startswith("again") else 1):
            task.cancel()
            await asyncio.sleep(0)
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert gone(made, 1) and settled()
    assert (not made) if when == "before it runs" else len(made) == 1
    assert make().startswith(b"%PDF-")


def test_r2_a_person_gone_during_a_slow_start_and_the_next_report(client, slow_start, monkeypatch):
    """R2, A4 (review of PR #51): the person goes away while the process of the report is still starting: no
    process left, the place given back; the next report is made."""
    setup_account(client)
    from helpers import post

    post(client, "/domains", "/domains", domain=DEMO)
    made = slow_start(after=1.0)

    async def gone_soon(request):
        await asyncio.sleep(0.2)

    monkeypatch.setattr(routes, "_gone", gone_soon)
    assert client.get(f"/domains/{DEMO}/report.pdf").status_code == routes.CLIENT_GONE
    assert len(made) == 1 and gone(made, 1) and settled()
    assert client.app.state.services.report_limiter.running == 0
    monkeypatch.undo()
    response = client.get(f"/domains/{DEMO}/report.pdf")
    assert response.status_code == 200 and response.content.startswith(b"%PDF-")


# ------------------------------------------------------------------ R3: PR_SET_PDEATHSIG
def test_r3_the_result_of_prctl_is_checked():
    """R3 (review of PR #51): prctl is asked for PR_SET_PDEATHSIG and SIGKILL; its result is checked: accepted,
    "" ; refused, the reason with its error. Here, on Linux, the real call is accepted."""
    calls = []
    assert worker.die_with_parent(lambda *args: calls.append(args) or 0) == ""
    assert calls == [(worker.PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)]
    refused = worker.die_with_parent(lambda *_: -1)
    assert refused == f"prctl(PR_SET_PDEATHSIG) failed: {os.strerror(1)}"
    assert worker.die_with_parent() == ""


REFUSED = ("import os, sys\nimport posture_cockpit.report.worker as w\n"
           "w.die_with_parent = lambda: 'simulated refusal'\nsys.exit(w.main(['1024', '65', str(os.getppid())]))")


def test_r3_a_refused_prctl_is_said_and_the_report_still_made(caplog):
    """R3 (review of PR #51): prctl refused (simulated): the process says so on its standard error, goes on
    within its limits of time and memory, and makes the PDF; the application writes the notice to its log."""
    done = subprocess.run([PY, "-c", REFUSED], input=b"<p>x</p>", capture_output=True, timeout=60,  # noqa: S603
                          env={**os.environ, **jobs.worker_environment()})
    assert done.returncode == 0 and done.stdout.startswith(b"%PDF-")
    assert b"Not killed with the application (simulated refusal)" in done.stderr
    with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
        assert make(command=script(REFUSED)).startswith(b"%PDF-")
    assert "Not killed with the application (simulated refusal): bounded by" in caplog.text and settled()


def test_r3_a_process_whose_parent_is_not_the_application_stops_at_once():
    """R3 (review of PR #51): the process is told another parent than the one it has: it stops at once with
    PARENT_GONE, before reading the HTML; the report fails (parent_gone)."""
    command = [PY, "-m", "posture_cockpit.report.worker", "1024", "65", str(os.getpid() + 999_999)]
    started = time.monotonic()
    with pytest.raises(jobs.ReportFailed, match="parent_gone"):
        make("x" * 10_000_000, command=command)
    assert time.monotonic() - started < 5 and settled()


def intermediate(then: str, refused: bool = False) -> tuple[subprocess.Popen, int]:
    """A parent of its own that starts the process of a report, prints its id, then ``then``: exits at once,
    or waits. The standard input of the process is that of this test, never closed (the HTML never ends);
    ``refused``: prctl refused (simulated), the process has pipes of its parent, as with the application."""
    worker_command = (f"[sys.executable, '-c', {REFUSED!r}]" if refused else
                      "[sys.executable, '-m', 'posture_cockpit.report.worker', '1024', '65', str(os.getpid())]")
    pipes = "stdin=subprocess.PIPE, stdout=subprocess.PIPE" if refused else "stdout=subprocess.DEVNULL"
    code = ("import os, subprocess, sys, time\n"
            f"w = subprocess.Popen({worker_command}, {pipes}, stderr=subprocess.DEVNULL)\n"
            "print(w.pid, flush=True)\n" + ("os._exit(0)" if then == "exit" else "time.sleep(60)"))
    parent = subprocess.Popen([PY, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE,  # noqa: S603
                              env={**os.environ, **jobs.worker_environment()})
    assert parent.stdout is not None
    return parent, int(parent.stdout.readline())


def test_r3_a_parent_gone_while_the_process_starts():
    """R3 (review of PR #51): the parent exits at once, while its process is still starting (before it asked
    to die with it): the process sees it is no longer its child and stops, though its HTML never ends."""
    parent, pid = intermediate("exit")
    try:
        parent.wait(timeout=10)
        assert gone([pid], 10)
    finally:
        assert parent.stdin is not None
        parent.stdin.close()


def waiting(pid: int) -> None:
    """Until the process of a report, started, sleeps: it waits for its HTML, its request to prctl made."""
    deadline = time.monotonic() + 10
    while "posture_cockpit.report.worker" not in Path(f"/proc/{pid}/cmdline").read_bytes().decode(
            errors="replace") or _state(pid) != "S":
        assert time.monotonic() < deadline
        time.sleep(0.05)
    time.sleep(0.5)


@pytest.mark.parametrize("sig", [signal.SIGKILL, signal.SIGTERM], ids=["SIGKILL", "SIGTERM"])
def test_r3_a_parent_killed_or_stopped_takes_its_process_with_it(sig):
    """R3 (review of PR #51): once the process waits for its HTML, its parent is killed (SIGKILL) or stopped
    (SIGTERM): the system kills the process (PR_SET_PDEATHSIG) though its HTML never ends; none is left."""
    parent, pid = intermediate("wait")
    try:
        waiting(pid)
        parent.send_signal(sig)
        parent.wait(timeout=10)
        assert gone([pid], 3)
    finally:
        assert parent.stdin is not None
        parent.stdin.close()


@pytest.mark.parametrize("sig", [signal.SIGKILL, signal.SIGTERM], ids=["SIGKILL", "SIGTERM"])
def test_r3_prctl_refused_a_parent_killed_still_leaves_no_process(sig):
    """R3 (review of PR #51): prctl refused (simulated), the parent killed or stopped while the process waits
    for its HTML: nobody kills it, but the pipes of its parent close with it; it reads the end of its HTML, can
    no longer write its PDF, and stops; none is left."""
    parent, pid = intermediate("wait", refused=True)
    try:
        waiting(pid)
        parent.send_signal(sig)
        parent.wait(timeout=10)
        assert gone([pid], 30)
    finally:
        assert parent.stdin is not None
        parent.stdin.close()


def _state(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[2]
    except OSError:
        return "?"
