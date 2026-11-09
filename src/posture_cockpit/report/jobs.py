# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Makes a PDF in a separate process, without holding the event loop (version 0.7.0, corrective 3).

:func:`make_pdf` starts report/worker.py with the Python of the application, writes the HTML to its standard
input and reads the PDF on its standard output, while the event loop serves every other request. Writing and
reading progress together (three tasks), so that neither side waits for the other with a full pipe; the PDF
is read in chunks and the process is killed as soon as it goes beyond ``max_output``, the standard error
kept to its last :data:`ERROR_TAIL` bytes: nothing it writes can fill the memory of the server.

One deadline covers everything: the start of Python, the import of WeasyPrint, the layout and the transfer.
At the deadline, on a failure, or when the task is cancelled (the client went away, the application stops),
the process is killed and this function returns only once it is gone, even if it is cancelled again while
it waits: the caller frees its place in the limiter (web/limits.py) after that, never before, and once.
:func:`stop_all` kills those still running when the application stops.

The process receives the HTML, its limits and an environment reduced to what it needs: no secret of the
instance, no variable of its configuration. It is a hardening, not a sandbox (see report/worker.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
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

# The processes running now, killed when the application stops.
_running: set[asyncio.subprocess.Process] = set()


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
    """The command of report/worker.py, with the Python of the application."""
    return [sys.executable, "-m", "posture_cockpit.report.worker", str(memory_mb), str(int(timeout) + CPU_MARGIN)]


def worker_environment() -> dict[str, str]:
    """The environment of the process: :data:`KEPT_ENVIRONMENT`, and the folder of this very package first on
    PYTHONPATH, so that the process runs the code of the application, installed or not."""
    package_parent = str(Path(__file__).resolve().parents[2])
    kept = {name: os.environ[name] for name in KEPT_ENVIRONMENT if name in os.environ}
    return {**kept, "PYTHONPATH": package_parent, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"}


async def make_pdf(html: str, *, timeout: float, memory_mb: int, max_output: int = MAX_OUTPUT,
                   command: Sequence[str] | None = None) -> bytes:
    """The PDF of ``html``, made by report/worker.py within ``timeout`` seconds and ``memory_mb`` MiB of
    address space. Raises ReportTimeout, ReportFailed or ReportUnavailable (WeasyPrint or one of its system
    libraries missing where the process runs); the process is gone when this function returns or raises, even
    when its task is cancelled. ``command``: another program to run, for the tests."""
    try:
        process = await asyncio.create_subprocess_exec(
            *(command or worker_command(memory_mb, timeout)), stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=worker_environment())
    except OSError as failure:  # the program cannot be started at all
        raise ReportFailed("start", str(failure)) from None
    _running.add(process)
    # Writing the HTML, reading the PDF and the errors progress together: no side waits for the other.
    reading = asyncio.ensure_future(_read(process, max_output))
    errors = asyncio.ensure_future(_tail(process))
    writing = asyncio.ensure_future(_write(process, html.encode("utf-8")))
    tasks: tuple[asyncio.Future[Any], ...] = (reading, errors, writing)
    for task in tasks:
        task.add_done_callback(_retrieved)
    try:
        try:
            async with asyncio.timeout(timeout):
                await asyncio.gather(*tasks)
                status = await process.wait()
            pdf, error = reading.result(), errors.result()
        except TimeoutError:
            raise ReportTimeout() from None
    finally:
        for task in tasks:  # a failure of one stops the others: the process is killed below
            task.cancel()
        try:
            await _reap(process, tasks)
        finally:
            _running.discard(process)
    detail = error.decode("utf-8", "replace")
    if status == worker.UNAVAILABLE:
        raise ReportUnavailable(detail)
    if status != 0:
        reason = {worker.NO_MEMORY: "no_memory", worker.TOO_LARGE: "input_too_large"}.get(status, f"exit {status}")
        raise ReportFailed(reason, detail)
    if not pdf.startswith(b"%PDF-"):
        raise ReportFailed("empty", detail)
    return pdf


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


async def _reap(process: asyncio.subprocess.Process, tasks: Sequence[asyncio.Future[Any]]) -> None:
    """Kills the process if it still runs and waits until it is gone, even if the task is cancelled again
    meanwhile; a cancellation received while waiting is raised once the process is gone."""
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    await wait_out(asyncio.ensure_future(_gone(process, tasks)))


async def _gone(process: asyncio.subprocess.Process, tasks: Sequence[asyncio.Future[Any]]) -> None:
    """Returns once the process is gone. Up to Python 3.11, Process.wait() returns only when every pipe is
    closed (base_subprocess, _call_connection_lost): a pipe left with unread bytes, its reading paused, would
    keep it waiting for ever. So the tasks that read are let go, then each pipe is read to its end, which
    comes as soon as the process is dead."""
    await asyncio.gather(*tasks, return_exceptions=True)
    if process.stdin is not None:
        process.stdin.close()
    await asyncio.gather(*(_drain(stream) for stream in (process.stdout, process.stderr) if stream is not None))
    await process.wait()


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
    """Kills every process still running and waits until they are gone (the application stops). Their own
    make_pdf reads their pipes to the end and reaps them; this waits for that."""
    running = list(_running)
    if running:
        log.warning("Stopping %d PDF report(s) in progress", len(running))
    for process in running:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
    await asyncio.gather(*(process.wait() for process in running), return_exceptions=True)


def running() -> int:
    """How many processes run now (tests, log)."""
    return len(_running)
