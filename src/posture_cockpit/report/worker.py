# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Lays one PDF out, in a process of its own (version 0.7.0, corrective 3).

The application never runs WeasyPrint itself: WeasyPrint is synchronous, and in the one event loop of
the instance a report of 117 pages held every page, the API, /healthz and the scans in progress for
six seconds. report/jobs.py starts ``python -m posture_cockpit.report.worker MEMORY_MB CPU_SECONDS PARENT``,
writes the HTML of the report to its standard input and reads the PDF on its standard output.

Before anything else, on Linux, this process asks to be killed when the application stops
(``PR_SET_PDEATHSIG``), then checks that the application, PARENT, is still its parent: had it stopped while
this process was starting, before the request, nobody would ever send that signal, so this process stops at
once (:data:`PARENT_GONE`). Should the request fail (prctl refused, not Linux), it says so on its standard
error and goes on, still bounded below. It then bounds its address space (``RLIMIT_AS``, MEMORY_MB) and its
processor time (``RLIMIT_CPU``, a second guard behind the deadline report/jobs.py enforces): a document beyond
them stops this process, never the server. It reads at most :data:`MAX_INPUT` bytes, imports WeasyPrint and
lays the PDF out. WeasyPrint may fetch the files of the report only (:func:`local_files`): report.css and the
fonts it declares, by their canonical path under :data:`REPORT_DIR`, links resolved; nothing else of the
machine, nothing from the network.

This is a hardening, not a sandbox: the process runs as the user of the application and the system would
let it read what the application reads (the database in /data). It receives the HTML and an environment
reduced to what it needs, and fetches nothing it was not given.

The exit status says what happened; report/jobs.py reads it: 0, the PDF is on the standard output;
:data:`UNAVAILABLE`, WeasyPrint or one of its system libraries is missing (the message of
error.pdf_unavailable); :data:`TOO_LARGE`, the HTML is beyond :data:`MAX_INPUT`; :data:`NO_MEMORY`, the
address space was exhausted; :data:`PARENT_GONE`, the application was gone before this process started its
work; anything else, a failure, its message on the standard error.
"""

from __future__ import annotations

import mimetypes
import os
import resource
import signal
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

# The folder of report.html, report.css and the fonts: what WeasyPrint may read, by canonical path.
REPORT_DIR = Path(__file__).resolve().parent
# The kinds of files the report uses: its stylesheet and the fonts it declares.
ALLOWED_SUFFIXES = {".css": "text/css", ".woff": "font/woff"}
# Bytes of HTML read at most. The heaviest report measured (3,000 MX, 117 pages) has 241 KB of HTML.
MAX_INPUT = 32 * 2**20
# Exit statuses, besides 0 (the PDF is on the standard output) and 1 (any other failure).
UNAVAILABLE = 3
TOO_LARGE = 4
NO_MEMORY = 5
PARENT_GONE = 6
# The option of prctl(2) that sets the signal sent to this process when its parent dies (linux/prctl.h).
PR_SET_PDEATHSIG = 1
# How the notice of a refused request begins, on the standard error: report/jobs.py writes it to the log.
NOT_KILLED = "Not killed with the application"


def report_file(url: str, root: Path = REPORT_DIR) -> Path:
    """The file of the report ``url`` names, or ValueError: a ``file:`` URL whose canonical path (links
    resolved, ``..`` removed) is a file under ``root`` with a suffix of :data:`ALLOWED_SUFFIXES`."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "file" or parts.netloc not in ("", "localhost"):
        raise ValueError(f"not a file of the report: {url[:200]}")
    path = Path(unquote(parts.path)).resolve()
    if not path.is_relative_to(root.resolve()) or path.suffix.lower() not in ALLOWED_SUFFIXES or not path.is_file():
        raise ValueError(f"not a file of the report: {url[:200]}")
    return path


def local_files(root: Path = REPORT_DIR) -> Any:
    """The URL fetcher of WeasyPrint, restricted to the files of the report (imported with WeasyPrint)."""
    from weasyprint.urls import URLFetcher, URLFetcherResponse

    class LocalFiles(URLFetcher):
        """Answers only with a file of the report; refuses anything else, never opens a connection."""

        def fetch(self, url: str, headers: Any = None) -> URLFetcherResponse:
            path = report_file(url, root)
            mime = ALLOWED_SUFFIXES.get(path.suffix.lower()) or mimetypes.guess_type(path.name)[0]
            return URLFetcherResponse(path.as_uri(), path.read_bytes(), {"Content-Type": mime})

    return LocalFiles(allowed_protocols={"file"}, allow_redirects=False)


def die_with_parent(prctl: Callable[..., int] | None = None) -> str:
    """Asks the system to kill this process (SIGKILL) when the application that started it stops: prctl
    PR_SET_PDEATHSIG, on Linux. Returns "" once the request is accepted, else why it is not: not Linux, no
    prctl in the C library, or its error (the result of prctl checked, errno read). ``prctl``: another
    function, for the tests. The caller then checks that its parent is still the application."""
    if prctl is None:
        if not sys.platform.startswith("linux"):
            return f"not Linux ({sys.platform})"
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            call = libc.prctl
            call.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
            call.restype = ctypes.c_int
        except (OSError, AttributeError) as error:
            return f"prctl unavailable: {error}"

        def prctl(option: int, value: int, *rest: int) -> int:
            result = int(call(option, value, *rest))
            return -ctypes.get_errno() if result != 0 else 0

    result = prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    if result != 0:
        return f"prctl(PR_SET_PDEATHSIG) failed: {os.strerror(-result) if result < 0 else result}"
    return ""


def bound(memory_mb: int, cpu_seconds: int) -> None:
    """The limits of this process: its address space and its processor time, soft and hard alike."""
    resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 2**20, memory_mb * 2**20))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))


def main(argv: list[str]) -> int:
    memory_mb, cpu_seconds, parent = int(argv[0]), int(argv[1]), int(argv[2])
    refused = die_with_parent()
    # After the request, never before: if the application stopped while this process was starting, it is no
    # longer its parent (the system gave it another), and the signal will never come.
    if os.getppid() != parent:
        return PARENT_GONE
    if refused:  # still bounded: its processor time, the deadline, and its pipes, closed with the application
        print(f"{NOT_KILLED} ({refused}): bounded by its processor time and deadline only.", file=sys.stderr,
              flush=True)
    bound(memory_mb, cpu_seconds)
    try:
        html = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(html) > MAX_INPUT:
            return TOO_LARGE
        try:
            from weasyprint import HTML
        except (ImportError, OSError) as error:  # Pango or another system library missing
            print(f"WeasyPrint unavailable: {error}", file=sys.stderr)
            return UNAVAILABLE
        pdf = HTML(string=html.decode("utf-8"), base_url=str(REPORT_DIR), url_fetcher=local_files()).write_pdf()
        sys.stdout.buffer.write(pdf)
        sys.stdout.buffer.flush()
    except MemoryError:
        return NO_MEMORY
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
