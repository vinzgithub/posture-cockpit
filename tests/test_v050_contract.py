# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.5.0, written before any change: what 0.4.1 promises and 0.5.0 must keep.

- The API: every key, type and value that ``GET /api/v1/domains`` gave in 0.4.1, on databases
  made by v0.3.0, v0.4.0 and v0.4.1. Later versions may add keys, never change or remove one.
  tests/data/api-contract-0.4.1.json was written by the code of 0.4.1 (run this file as a script).
- The storage: no ``await`` inside a ``with ….transaction()`` block. The database has one
  connection per process; a task that waited in the middle of a transaction would let another
  task's statements join it (see storage/database.py)."""

import ast
import json
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from posture_cockpit.config import Config
from posture_cockpit.web.app import create_app

DATA = Path(__file__).parent / "data"
SOURCE = Path(__file__).parent.parent / "src" / "posture_cockpit"
CONTRACT = DATA / "api-contract-0.4.1.json"
TOKEN = "legacy-api-token-for-tests-0123456789"
VERSIONS = ("v0.3.0", "v0.4.0", "v0.4.1")


def api_of(folder: Path, version: str) -> dict[str, dict]:
    """The domains of ``GET /api/v1/domains`` for an instance made by ``version``."""
    folder.mkdir(parents=True)
    with sqlite3.connect(folder / "posture_cockpit.db") as conn:
        conn.executescript((DATA / f"database-{version}.sql").read_text())
    app = create_app(Config(data_dir=folder))
    try:
        with TestClient(app) as client:
            answer = client.get("/api/v1/domains", headers={"Authorization": f"Bearer {TOKEN}"})
            assert answer.status_code == 200
            return {d["domain"]: d for d in answer.json()["domains"]}
    finally:
        app.state.services.db.close()


@pytest.mark.parametrize("version", VERSIONS)
def test_the_api_keeps_every_key_type_and_value_of_0_4_1(tmp_path, version):
    promised = json.loads(CONTRACT.read_text())[version]
    given = api_of(tmp_path / version, version)
    assert set(given) == set(promised)  # the same domains, the internal one included for an administrator
    for domain, old in promised.items():
        new = given[domain]
        for key, value in old.items():
            assert key in new, (domain, key)
            assert type(new[key]) is type(value), (domain, key, new[key], value)
            assert new[key] == value, (domain, key, new[key], value)


def test_the_contract_covers_what_0_5_0_must_carry_over():
    promised = json.loads(CONTRACT.read_text())["v0.4.1"]
    evaluations = {d["evaluation"] for d in promised.values()}
    assert {"complete", "undetermined", "not_evaluated"} <= evaluations
    assert any(d.get("perimeter") for d in promised.values())  # a domain of an internal perimeter


def transaction_blocks(root: Path) -> tuple[int, list[str]]:
    """How many ``with ….transaction(…)`` blocks the code holds, and every await found inside one."""
    blocks, found = 0, []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.With, ast.AsyncWith)):
                continue
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) \
                        and call.func.attr == "transaction":
                    blocks += 1
                    for statement in node.body:
                        for inner in ast.walk(statement):
                            if isinstance(inner, (ast.Await, ast.AsyncFor, ast.AsyncWith)):
                                found.append(f"{path.relative_to(root)}:{inner.lineno}")
    return blocks, found


def test_no_await_inside_a_transaction():
    blocks, found = transaction_blocks(SOURCE)
    assert blocks >= 8  # the check finds the blocks it is meant to look into
    assert found == []


def test_the_static_check_finds_an_await_inside_a_transaction(tmp_path):
    (tmp_path / "bad.py").write_text(
        "async def save(db, net):\n"
        "    with db.transaction(immediate=True):\n"
        "        db.execute('INSERT INTO t VALUES(1)')\n"
        "        await net.fetch()\n")
    assert transaction_blocks(tmp_path) == (1, ["bad.py:4"])


def write_contract(target: Path) -> None:
    """Writes the contract with the code installed (run it with the code of 0.4.1 only)."""
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        contract = {version: api_of(Path(folder) / version, version) for version in VERSIONS}
    target.write_text(json.dumps(contract, indent=1, ensure_ascii=False, sort_keys=True) + "\n")


if __name__ == "__main__":
    write_contract(Path(sys.argv[1]) if len(sys.argv) > 1 else CONTRACT)
