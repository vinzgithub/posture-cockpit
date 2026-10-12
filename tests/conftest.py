# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fixtures: a frozen clock, an application whose network is recorded data."""

import copy
import time

import pytest
from fastapi.testclient import TestClient

from posture_cockpit.config import Config
from posture_cockpit.core.fixture import FixtureNetwork
from posture_cockpit.scanner import DEMO_DOMAIN, demo_data
from posture_cockpit.web.app import create_app


class Clock:
    """Replaces time.time() so tests can move forward in time."""

    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(time, "time", c)
    return c


@pytest.fixture
def world():
    """The Internet as the application sees it: recorded answers by domain.

    Tests change it to simulate a fix made between a scan and a recheck."""
    return {DEMO_DOMAIN: copy.deepcopy(demo_data(DEMO_DOMAIN))}


@pytest.fixture
def app(tmp_path, world):
    def network(domain):
        # Domains the test did not describe do not exist.
        return FixtureNetwork(world.get(domain, {"dns": {f"{domain} SOA": None}}))

    return create_app(Config(data_dir=tmp_path), network_factory=network)


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c
