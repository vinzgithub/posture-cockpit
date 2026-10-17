# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0: one owner per transaction (storage/database.py).

The connection is shared by the process and its lock lets the same thread in again; every asyncio
task runs on that thread. Without the guard, a task writing while another task waits inside a
transaction joins that transaction and is rolled back with it, silently (the first test shows it
on a copy of the class without the guard). With it, that write is refused; another thread waits."""

import ast
import asyncio
import threading
import time
from pathlib import Path

import pytest

from posture_cockpit.storage import database
from posture_cockpit.storage.database import Database, TransactionOwnerError

SOURCE = Path(database.__file__)


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "posture_cockpit.db")
    d.execute("CREATE TABLE t(who TEXT)")
    yield d
    d.close()


def rows(db):
    return [r[0] for r in db.all("SELECT who FROM t ORDER BY rowid")]


async def a_transaction_that_waits_then_fails(db, log):
    try:
        with db.transaction():
            db.execute("INSERT INTO t VALUES('A')")
            await asyncio.sleep(0.02)  # the mistake the guard catches
            raise ValueError("A fails")
    except ValueError:
        log.append("A rolled back")


def test_without_the_guard_a_write_of_another_task_is_lost_silently(db, monkeypatch):
    monkeypatch.setattr(Database, "_check_owner", lambda self: None)
    log = []

    async def other_task():
        await asyncio.sleep(0.005)
        db.execute("INSERT INTO t VALUES('B')")
        log.append("B written")

    async def main():
        await asyncio.gather(a_transaction_that_waits_then_fails(db, log), other_task())

    asyncio.run(main())
    assert log == ["B written", "A rolled back"]
    assert rows(db) == []  # B was told its write succeeded; it went away with A's rollback


def test_with_the_guard_the_other_task_is_refused_and_nothing_is_lost_silently(db):
    log = []

    async def other_task():
        await asyncio.sleep(0.005)
        try:
            db.execute("INSERT INTO t VALUES('B')")
        except TransactionOwnerError:
            log.append("B refused")
        await asyncio.sleep(0.05)  # once A's transaction has ended, B can write
        db.execute("INSERT INTO t VALUES('B again')")

    async def main():
        await asyncio.gather(a_transaction_that_waits_then_fails(db, log), other_task())

    asyncio.run(main())
    assert log == ["B refused", "A rolled back"]
    assert rows(db) == ["B again"]


CALLS = {
    "execute": lambda db: db.execute("SELECT 1"),
    "executemany": lambda db: db.executemany("INSERT INTO t VALUES(?)", [("x",)]),
    "one": lambda db: db.one("SELECT 1"),
    "all": lambda db: db.all("SELECT 1"),
    "value": lambda db: db.value("SELECT 1"),
    "get_meta": lambda db: db.get_meta("schema_version"),
    "set_meta": lambda db: db.set_meta("k", "v"),
    "delete_meta": lambda db: db.delete_meta("k"),
    "schema_version": lambda db: db.schema_version,
    "nested transaction": lambda db: db.transaction().__enter__(),
    "backup": lambda db: db.backup("guard"),
}


@pytest.mark.parametrize("call", list(CALLS))
def test_every_use_of_the_connection_by_another_task_is_refused_reads_included(db, call):
    outcome = []

    async def owner(opened, release):
        with db.transaction():
            db.execute("INSERT INTO t VALUES('owner')")
            opened.set()
            await release.wait()

    async def intruder(opened, release):
        await opened.wait()
        try:
            CALLS[call](db)
            outcome.append("allowed")
        except TransactionOwnerError:
            outcome.append("refused")
        release.set()

    async def main():
        opened, release = asyncio.Event(), asyncio.Event()
        await asyncio.gather(owner(opened, release), intruder(opened, release))

    asyncio.run(main())
    assert outcome == ["refused"]
    assert rows(db) == ["owner"]  # the owner's transaction committed normally afterwards


def test_the_owner_may_nest_and_use_every_method(db):
    async def owner():
        with db.transaction(immediate=True):
            for name, call in CALLS.items():
                if name not in ("nested transaction", "backup"):
                    call(db)
            with db.transaction():
                db.execute("INSERT INTO t VALUES('inner')")

    asyncio.run(owner())
    assert rows(db) == ["x", "inner"]


def test_another_thread_waits_for_the_end_of_the_transaction(db):
    order = []

    def a():
        with db.transaction():
            db.execute("INSERT INTO t VALUES('A')")
            order.append("A in transaction")
            time.sleep(0.2)
            order.append("A commits")

    def b():
        time.sleep(0.05)
        order.append("B wants to write")
        db.execute("INSERT INTO t VALUES('B')")
        order.append("B written")

    threads = [threading.Thread(target=a), threading.Thread(target=b)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert not any(thread.is_alive() for thread in threads)  # no deadlock
    assert order == ["A in transaction", "B wants to write", "A commits", "B written"]
    assert rows(db) == ["A", "B"]


def test_a_refused_task_leaves_no_trace_once_the_transaction_ended(db):
    async def main():
        with db.transaction():
            db.execute("INSERT INTO t VALUES('A')")
        assert db._owner is None and db._depth == 0
        db.execute("INSERT INTO t VALUES('after')")

    asyncio.run(main())
    assert rows(db) == ["A", "after"]


GUARDED = {"execute", "executemany", "all", "one", "backup"}
# Methods that use the connection directly without the guard, and why that is safe:
UNGUARDED = {
    "__init__": "before the object exists for anyone else",
    "close": "closing is not a query; the server closes at shutdown",
    "transaction": "checks the owner itself before joining, and opens or ends the transaction",
    "_migrate": "runs inside __init__",
    "_apply": "runs inside __init__",
}


def test_every_method_that_touches_the_connection_is_guarded_or_listed():
    tree = ast.parse(SOURCE.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Database")
    seen = set()
    for method in (n for n in cls.body if isinstance(n, ast.FunctionDef)):
        names = {f"{a.value.id}.{a.attr}" for a in ast.walk(method)
                 if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name)}
        calls = {a.func.attr for a in ast.walk(method)
                 if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)}
        if "self._conn" not in names:
            continue
        seen.add(method.name)
        if method.name in GUARDED:
            assert "_check_owner" in calls, method.name
        else:
            assert method.name in UNGUARDED, f"{method.name} uses the connection without the guard"
    assert seen == GUARDED | set(UNGUARDED)
