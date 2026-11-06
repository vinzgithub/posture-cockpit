# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A fake SMTP server on the loopback address, for the tests of the SMTP dialogue (version 0.7).

What it does
------------
:func:`smtp_server` starts a server on ``127.0.0.1``, on a port chosen by the
system, that plays a :class:`Script`: what to answer to the greeting, to
``EHLO``, to ``STARTTLS``, then whether to negotiate TLS and how, and what to
answer to ``QUIT``. Each answer is a list of items played in order:

- a ``str``: one reply line, sent with its CR LF;
- ``bytes``: sent exactly as given (a line without CR LF, a control character,
  bytes that are not TLS…);
- a ``float``: a pause, in seconds. During a pause of the greeting the server
  watches the connection: bytes the client sends before the greeting is over
  are recorded in :attr:`Session.early` (a client must not speak before the
  final ``220`` line, as postscreen checks);
- :data:`SILENT`: say nothing more, until the client leaves (a server that never
  finishes its reply);
- :data:`CLOSE`: close the connection at once.

After its answer to ``STARTTLS``, the server negotiates TLS when
:attr:`Script.tls` is a server context, or plays it when it is an answer (bytes
in the clear instead of TLS, a close, a silence), once the client's first TLS
bytes have arrived. The server side of TLS runs
on :class:`ssl.MemoryBIO`: its alerts (``protocol_version``,
``handshake_failure``) reach the client as a real mail server sends them,
which asyncio's own TLS server does not do when it closes after a failure.

What it records, per connection (:class:`Session`): every command line, and
whether it came over TLS; the bytes received too early; the SNI the client gave;
the TLS version negotiated.

Why it can never send mail
--------------------------
It listens on the loopback address only and talks to nobody else: no mail
store, no relay, no DNS. It understands ``EHLO``, ``STARTTLS`` and ``QUIT``;
any other command (``MAIL``, ``RCPT``, ``DATA``, ``AUTH``, ``HELO``…) is answered
``502`` and recorded, and leaving the :func:`smtp_server` block then fails the
test: the probe must never say anything else (S04). No test depends on a public
server.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from enum import Enum

from local_servers import LOOPBACK

MX = "mx.lab.example"
ALLOWED = frozenset({"EHLO", "STARTTLS", "QUIT"})
MAX_COMMAND = 64 * 1024  # bytes of a command line the server waits for, at most


class Act(Enum):
    SILENT = "say nothing more until the client leaves"
    CLOSE = "close the connection at once"


SILENT, CLOSE = Act.SILENT, Act.CLOSE
Item = str | bytes | float | Act
Answer = Sequence[Item]


def ehlo(*keywords: str, name: str = MX) -> list[str]:
    """The lines of an EHLO reply: the server's name, then one extension keyword per line."""
    lines = [name, *keywords]
    return [f"250-{line}" for line in lines[:-1]] + [f"250 {lines[-1]}"]


@dataclass
class Script:
    """What the server answers, step by step (see the module documentation)."""

    banner: Answer = (f"220 {MX} ESMTP ready",)
    ehlo: Answer = tuple(ehlo("PIPELINING", "SIZE 10240000", "8BITMIME", "STARTTLS"))
    starttls: Answer = ("220 2.0.0 Ready to start TLS",)
    tls: ssl.SSLContext | Answer | None = None  # after the answer to STARTTLS
    quit: Answer = ("221 2.0.0 Bye",)


@dataclass
class Session:
    """What the server received on one connection."""

    commands: list[tuple[bool, str]] = field(default_factory=list)  # (over TLS, command line)
    early: bytes = b""            # sent by the client before the greeting was over
    sni: list[str | None] = field(default_factory=list)
    tls_version: str = ""         # negotiated, when the negotiation succeeded
    tls_error: str = ""           # the server's side of a failed negotiation
    forbidden: list[str] = field(default_factory=list)


@dataclass
class Record:
    sessions: list[Session] = field(default_factory=list)

    @property
    def connections(self) -> int:
        return len(self.sessions)


@contextlib.asynccontextmanager
async def smtp_server(script: Script) -> AsyncIterator[tuple[Record, int]]:
    """Starts a fake SMTP server playing ``script``; yields what it records and its port.

    Leaving the block waits for the connections to end, then fails the test if the client sent
    any command other than EHLO, STARTTLS and QUIT."""
    record = Record()
    handlers: set[asyncio.Task] = set()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        handlers.add(task)
        session = Session()
        record.sessions.append(session)
        try:
            await _Play(script, session, reader, writer).run()
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass  # the client left: what it did is in the session
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1)

    server = await asyncio.start_server(handle, LOOPBACK, 0)
    async with server:
        yield record, server.sockets[0].getsockname()[1]
    # The client has closed its side: each handler ends at once. A handler still running after
    # a few seconds is a server bug; it is cancelled so the test ends.
    if handlers:
        _, pending = await asyncio.wait(handlers, timeout=5)
        for task in pending:
            task.cancel()
    forbidden = [line for session in record.sessions for line in session.forbidden]
    assert not forbidden, f"the client sent commands other than EHLO, STARTTLS and QUIT: {forbidden}"


class _Play:
    """One connection: plays the script, in the clear then over TLS."""

    def __init__(self, script: Script, session: Session, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.script, self.session = script, session
        self.reader, self.writer = reader, writer
        self.buffer = bytearray()        # received, not yet made into command lines (decrypted over TLS)
        self.tls: ssl.SSLObject | None = None
        self.incoming = ssl.MemoryBIO()  # TLS records from the client
        self.outgoing = ssl.MemoryBIO()  # TLS records for the client

    async def run(self) -> None:
        if not await self.say(self.script.banner, greeting=True):
            return
        while (line := await self.read_line()) is not None:
            self.session.commands.append((self.tls is not None, line))
            verb = line.split(" ", 1)[0].upper()
            if verb not in ALLOWED:
                self.session.forbidden.append(line)
                if not await self.say(["502 5.5.2 Not in this test"]):
                    return
            elif verb == "QUIT":
                await self.say(self.script.quit)
                return
            elif verb == "EHLO":
                if not await self.say(self.script.ehlo):
                    return
            elif not await self.starttls():
                return

    async def starttls(self) -> bool:
        if not await self.say(self.script.starttls):
            return False
        tls = self.script.tls
        if isinstance(tls, ssl.SSLContext):
            return await self.negotiate(tls)
        if tls is None:
            return True
        # A server that does not speak TLS answers what the client sends first, its ClientHello.
        # Waiting for it also keeps the answer apart from the 220, as a real server would.
        if not self.buffer and not await self.reader.read(65536):
            return False
        self.buffer.clear()
        return await self.say(tls)

    # ---------------------------------------------------------------- answers
    async def say(self, answer: Answer, *, greeting: bool = False) -> bool:
        """Plays ``answer``; False when it ended the connection (SILENT or CLOSE)."""
        for item in answer:
            if item is CLOSE:
                return False
            if item is SILENT:
                await self.until_the_client_leaves()
                return False
            if isinstance(item, float | int):
                await self.pause(float(item), greeting)
            elif isinstance(item, bytes):
                await self.send(item)
            else:
                await self.send(str(item).encode("latin-1") + b"\r\n")
        return True

    async def pause(self, seconds: float, greeting: bool) -> None:
        if not greeting:
            await asyncio.sleep(seconds)
            return
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(seconds):
                while data := await self.reader.read(4096):
                    self.session.early += data  # the client spoke before the end of the greeting
                    self.buffer += data

    async def until_the_client_leaves(self) -> None:
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(60):  # far beyond any limit of the dialogue
                while await self.reader.read(65536):
                    pass

    async def send(self, data: bytes) -> None:
        if self.tls is None:
            self.writer.write(data)
        else:
            self.tls.write(data)
            self.writer.write(self.outgoing.read())
        await self.writer.drain()

    # ---------------------------------------------------------------- commands
    async def read_line(self) -> str | None:
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_COMMAND:
                return None
            chunk = await self.receive()
            if not chunk:
                return None
            self.buffer += chunk
        line, _, rest = bytes(self.buffer).partition(b"\n")
        self.buffer = bytearray(rest)
        return line.rstrip(b"\r").decode("latin-1")

    async def receive(self) -> bytes:
        """The next bytes from the client, decrypted once TLS is up."""
        if self.tls is None:
            return await self.reader.read(4096)
        while True:
            try:
                return self.tls.read(4096)
            except ssl.SSLWantReadError:
                data = await self.reader.read(65536)
                if not data:
                    return b""
                self.incoming.write(data)
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    # ---------------------------------------------------------------- TLS
    async def negotiate(self, context: ssl.SSLContext) -> bool:
        """The server side of the negotiation; its alert, if any, is sent before the server waits
        for the client to leave."""
        context.sni_callback = lambda _object, name, _context: self.session.sni.append(name)
        tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        if self.buffer:  # sent by the client right after STARTTLS, read along with it
            self.incoming.write(bytes(self.buffer))
            self.buffer.clear()
        while True:
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self.flush()
                data = await self.reader.read(65536)
                if not data:
                    return False
                self.incoming.write(data)
            except ssl.SSLError as e:
                self.session.tls_error = e.reason or str(e)
                await self.flush()
                await self.until_the_client_leaves()
                return False
        await self.flush()
        self.tls = tls
        self.session.tls_version = tls.version() or ""
        return True

    async def flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.writer.write(data)
            await self.writer.drain()
