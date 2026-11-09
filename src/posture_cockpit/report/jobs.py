# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Makes a PDF in a separate process, without holding the event loop (version 0.7.0, corrective 3).

:func:`make_pdf` starts report/worker.py with the Python of the application, writes the HTML to its standard
input and reads the PDF on its standard output, while the event loop serves every other request. Writing and
reading progress together (three tasks), so that neither side waits for the other with a full pipe; the PDF
is read in chunks and the process is killed as soon as it goes beyond ``max_output``, the standard error
kept to its last :data:`ERROR_TAIL` bytes: nothing it writes can fill the memory of the server.

One deadline, set before the process is started, covers everything: the start of the process, the start of
Python, the import of WeasyPrint, the layout and the transfer. At the deadline, on a failure, or when the task
is cancelled (the client went away, the application stops), the process and its group are killed and this
function returns only once it is gone, even if it is cancelled again while it waits, and even while the
process was starting: the caller frees its place in the limiter (web/limits.py) after that, never before,
and once. :func:`stop_all` stops those still running when the application stops, by the same way.

The process receives the HTML, its limits and an environment reduced to what it needs: no secret of the
instance, no variable of its configuration. It is a hardening, not a sandbox (see report/worker.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import ReportUnavailable, worker

log = logging.getLogger("uvicorn.error")

# Bytes of a PDF read at most: beyond, the process is killed and the report fails. The heaviest report
# measured (3,000 MX, 117 pages) is 162 KB.
MAX_OUTPUT = 64 * 2**20
# Bytes of the standard error kept for the log: its end, where the error is.
ERROR_TAIL = 8192
# Bytes read or written at a time.
CHUNK = 65536
# Seconds of processor time the process may use beyond the deadline before the system stops it: a second
# guard, should this process be gone without killing it.
CPU_MARGIN = 5
# The variables the process keeps from the environment of the application: where the programs and the
# libraries are, the language, the cache of fontconfig (XDG_CACHE_HOME, /tmp/cache in the image).
KEPT_ENVIRONMENT = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "HOME", "TMPDIR", "XDG_CACHE_HOME", "FONTCONFIG_PATH",
                    "FONTCONFIG_FILE", "LD_LIBRARY_PATH")

# Seconds between two readings of the exit status of a process (see _exited): 1 ms at first, doubled each time
# up to 50 ms, so that a process that has just been killed or has closed its pipes is seen gone at once.
EXIT_POLL = (0.001, 0.05)
# Seconds allowed to read the pipes of a dead process to their end (see _gone).
DRAIN_GRACE = 5.0

# The reports running now, and the processes being started, stopped when the application stops.
_running: set[_Job] = set()
_starting: set[asyncio.Future[_Job]] = set()


class ReportTimeout(Exception):
    """The PDF was not made within the deadline; the process was killed."""


class ReportFailed(Exception):
    """The process failed: ``reason`` says how (an exit status, ``no_memory``, ``too_large``, ``empty``),
    ``detail`` holds the end of its standard error, for the log."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


def worker_command(memory_mb: int, timeout: float) -> list[str]:
    """The command of report/worker.py, with the Python of the application: its limits, and the process id of
    the application, which the process checks is still its parent once it asked to die with it."""
    return [sys.executable, "-m", "posture_cockpit.report.worker", str(memory_mb), str(int(timeout) + CPU_MARGIN),
            str(os.getpid())]


def worker_environment() -> dict[str, str]:
    """The environment of the process: :data:`KEPT_ENVIRONMENT`, and the folder of this very package first on
    PYTHONPATH, so that the process runs the code of the application, installed or not."""
    package_parent = str(Path(__file__).resolve().parents[2])
    kept = {name: os.environ[name] for name in KEPT_ENVIRONMENT if name in os.environ}
    return {**kept, "PYTHONPATH": package_parent, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}


class _Job:
    """A process of a report and the three tasks that write its HTML and read its PDF and its errors.

    :meth:`reap` is the one way a job ends, whoever asks first (make_pdf, or stop_all when the application
    stops): the tasks are stopped, the process and its group killed, and the same future, done once the process
    is gone, is given to everyone who asks."""

    def __init__(self, process: asyncio.subprocess.Process, html: bytes, max_output: int):
        self.process = process
        self.reading = asyncio.ensure_future(_read(process, max_output))
        self.errors = asyncio.ensure_future(_tail(process))
        self.writing = asyncio.ensure_future(_write(process, html))
        self.tasks: tuple[asyncio.Future[Any], ...] = (self.reading, self.errors, self.writing)
        for task in self.tasks:
            task.add_done_callback(_retrieved)
        self.stopped = False  # stopped by stop_all, not by its own make_pdf
        self._reaped: asyncio.Future[None] | None = None

    def reap(self) -> asyncio.Future[None]:
        if self._reaped is None:
            for task in self.tasks:
                task.cancel()
            _kill(self.process)
            self._reaped = asyncio.ensure_future(_gone(self.process, self.tasks))
        return self._reaped


async def make_pdf(html: str, *, timeout: float, memory_mb: int, max_output: int = MAX_OUTPUT,
                   command: Sequence[str] | None = None) -> bytes:
    """The PDF of ``html``, made by report/worker.py within ``timeout`` seconds and ``memory_mb`` MiB of
    address space. Raises ReportTimeout, ReportFailed or ReportUnavailable (WeasyPrint or one of its system
    libraries missing where the process runs); the process is gone when this function returns or raises, even
    when its task is cancelled, again and again. ``command``: another program to run, for the tests.

    One deadline, set before anything is started, covers the start of the process, the start of Python, the
    import of WeasyPrint, the layout and the transfer. The start itself is never cancelled half-way: should
    the deadline pass or a cancellation come while the process starts, this waits until it has started (or
    failed to), then stops it like any other: never a process left unknown."""
    deadline = asyncio.get_running_loop().time() + timeout
    starting = asyncio.ensure_future(_start(command or worker_command(memory_mb, timeout), html.encode("utf-8"),
                                            max_output))
    _starting.add(starting)
    starting.add_done_callback(_starting.discard)
    try:
        async with asyncio.timeout_at(deadline):
            job = await asyncio.shield(starting)
    except BaseException as interruption:  # the start failed, or the deadline or a cancellation came first
        failure = _start_failure(starting)
        if failure is not None and interruption is failure:  # the program cannot be started: nothing to stop
            raise ReportFailed("start", str(failure)) from None
        try:
            await wait_out(starting)  # never cancelled: it ends with a process, or without one
        finally:
            if _start_failure(starting) is None and starting.done() and not starting.cancelled():
                await _stop(starting.result())
        if isinstance(interruption, TimeoutError):  # TimeoutError is an OSError: told apart above
            raise ReportTimeout() from None
        raise
    try:
        try:
            async with asyncio.timeout_at(deadline):
                await asyncio.gather(*job.tasks)
                status = await _exited(job.process)
            pdf, error = job.reading.result(), job.errors.result()
        except TimeoutError:
            raise ReportTimeout() from None
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if job.stopped and not (current and current.cancelling()):  # its tasks stopped by stop_all
                raise ReportFailed("stopped") from None
            raise
    finally:
        await _stop(job)
    detail = error.decode("utf-8", "replace")
    for notice in (line for line in detail.splitlines() if line.startswith(worker.NOT_KILLED)):
        log.warning("PDF report process %d: %s", job.process.pid, notice)  # prctl refused (report/worker.py)
    if status == worker.UNAVAILABLE:
        raise ReportUnavailable(detail)
    if status != 0:
        reason = {worker.NO_MEMORY: "no_memory", worker.TOO_LARGE: "input_too_large",
                  worker.PARENT_GONE: "parent_gone"}.get(status, f"exit {status}")
        raise ReportFailed(reason, detail)
    if not pdf.startswith(b"%PDF-"):
        raise ReportFailed("empty", detail)
    return pdf


def _start_failure(starting: asyncio.Future[_Job]) -> BaseException | None:
    """Why the start failed, once it is over (an OSError: the program cannot be run), or None."""
    if not starting.done() or starting.cancelled():
        return None
    return starting.exception()


async def _start(command: Sequence[str], html: bytes, max_output: int) -> _Job:
    """Starts the process, in a session (and a process group) of its own, and its job, known to stop_all as
    soon as it exists. Never cancelled (make_pdf shields it): asyncio kills a process whose start it cancels,
    but would not wait for it."""
    process = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env=worker_environment(), start_new_session=True)
    job = _Job(process, html, max_output)
    _running.add(job)
    return job


async def _stop(job: _Job) -> None:
    """Reaps ``job`` and waits until its process is gone, even if cancelled meanwhile, then forgets it."""
    try:
        await wait_out(job.reap())
    finally:
        _running.discard(job)


def _kill(process: asyncio.subprocess.Process) -> None:
    """Kills the process and its group (anything it would have started), if it still runs."""
    if process.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        process.kill()


def _retrieved(task: asyncio.Future[Any]) -> None:
    """Reads the outcome of a task stopped after another failed, so that asyncio never reports it unread."""
    if not task.cancelled():
        task.exception()


async def _write(process: asyncio.subprocess.Process, data: bytes) -> None:
    """Writes the HTML, in chunks, then closes the standard input; a process that stops reading (it failed,
    or was killed) ends the writing without error: its status says why."""
    stdin = process.stdin
    assert stdin is not None
    try:
        for start in range(0, len(data), CHUNK):
            stdin.write(data[start:start + CHUNK])
            await stdin.drain()
        stdin.close()
        await stdin.wait_closed()
    except (BrokenPipeError, ConnectionResetError):
        pass


async def _read(process: asyncio.subprocess.Process, most: int) -> bytes:
    """The standard output, ``most`` bytes at most: beyond, the process is killed (ReportFailed)."""
    stdout = process.stdout
    assert stdout is not None
    chunks, size = [], 0
    while chunk := await stdout.read(CHUNK):
        size += len(chunk)
        if size > most:
            raise ReportFailed("too_large")
        chunks.append(chunk)
    return b"".join(chunks)


async def _tail(process: asyncio.subprocess.Process) -> bytes:
    """The end of the standard error, :data:`ERROR_TAIL` bytes at most, read as it comes."""
    stderr = process.stderr
    assert stderr is not None
    kept = b""
    while chunk := await stderr.read(CHUNK):
        kept = (kept + chunk)[-ERROR_TAIL:]
    return kept


async def _exited(process: asyncio.subprocess.Process) -> int:
    """The exit status of the process, as soon as it exits, whatever its pipes: up to Python 3.11,
    Process.wait() returns only once every pipe is closed (base_subprocess, _call_connection_lost), and a pipe
    left with unread bytes, its reading paused, would keep it waiting for ever. The status itself is known at
    once (the child watcher reaps the process); it is read again and again (:data:`EXIT_POLL`)."""
    pause, longest = EXIT_POLL
    while process.returncode is None:
        await asyncio.sleep(pause)
        pause = min(pause * 2, longest)
    return process.returncode


async def _gone(process: asyncio.subprocess.Process, tasks: Sequence[asyncio.Future[Any]]) -> None:
    """Returns once the process is gone, without Process.wait() (see :func:`_exited`): the tasks that write
    and read are let go (cancelled, they end at once, even those that no longer progress), the standard input
    closed, the exit waited for, then each pipe read to its end, which comes as soon as the process and its
    group are dead, :data:`DRAIN_GRACE` seconds at most (a pipe kept open elsewhere is left to the log)."""
    await asyncio.gather(*tasks, return_exceptions=True)
    if process.stdin is not None:
        process.stdin.close()
    await _exited(process)
    try:
        async with asyncio.timeout(DRAIN_GRACE):
            await asyncio.gather(*(_drain(stream) for stream in (process.stdout, process.stderr) if stream is not None))
    except TimeoutError:
        log.warning("A PDF report process exited with a pipe still open (pid %d)", process.pid)


async def _drain(stream: asyncio.StreamReader) -> None:
    """Reads ``stream`` to its end, keeping nothing."""
    with contextlib.suppress(Exception):
        while await stream.read(CHUNK):
            pass


async def wait_out(future: asyncio.Future[Any]) -> None:
    """Waits until ``future`` is done, whatever it ends with, even if the task that waits is cancelled
    meanwhile: a cancellation received while waiting is raised once ``future`` is done."""
    cancelled = False
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            cancelled = cancelled or not future.done()
        except Exception:  # noqa: S110 - the outcome of ``future`` is for its owner to read
            pass
    if cancelled:
        raise asyncio.CancelledError()


async def stop_all() -> None:
    """Stops every report when the application stops, by the one way a job ends (:meth:`_Job.reap`): the
    processes still starting are waited for first, so that none is missed, then every job is reaped, even if
    its tasks no longer progress or its pipes are full, and its make_pdf raises ReportFailed("stopped")."""
    await asyncio.gather(*(wait_out(start) for start in list(_starting)), return_exceptions=True)
    stopping = list(_running)
    if stopping:
        log.warning("Stopping %d PDF report(s) in progress", len(stopping))
    for job in stopping:
        job.stopped = True
    await asyncio.gather(*(wait_out(job.reap()) for job in stopping), return_exceptions=True)


def pids() -> list[int]:
    """The process ids of the reports running now (tests, log)."""
    return [job.process.pid for job in _running]


def running() -> int:
    """How many processes run now (tests, log)."""
    return len(_running)
