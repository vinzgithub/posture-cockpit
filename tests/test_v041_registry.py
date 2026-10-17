# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1, counter-review P2: what release.yml learns from the registry before and after publishing.

A small registry on the loopback address answers like ghcr.io does: 401 with a Bearer challenge,
a token, then the manifest or 404; and the failures a publication must stop on."""

import base64
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "registry_tag.py"
spec = importlib.util.spec_from_file_location("registry_tag", SCRIPT)
registry_tag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry_tag)

COMMIT = "6888623a" * 5
INDEX = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [],
         "annotations": {"org.opencontainers.image.revision": COMMIT}}


class Registry:
    def __init__(self):
        self.tags = {}            # tag -> manifest
        self.status = None        # forced status of every manifest request
        self.auth = False         # ask for a token, as ghcr.io does
        self.credentials = None   # "user:password" the token endpoint wants
        self.tokens = 0

    def start(self):
        registry = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body=b"", headers=()):
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/token"):
                    expected = registry.credentials
                    given = self.headers.get("Authorization", "")
                    if expected and given != "Basic " + base64.b64encode(expected.encode()).decode():
                        return self.reply(401)
                    registry.tokens += 1
                    return self.reply(200, json.dumps({"token": "t0k3n"}).encode())
                if registry.auth and self.headers.get("Authorization") != "Bearer t0k3n":
                    realm = f"http://127.0.0.1:{self.server.server_port}/token"
                    challenge = f'Bearer realm="{realm}",service="test",scope="repository:x:pull"'
                    return self.reply(401, b"{}", [("WWW-Authenticate", challenge)])
                if registry.status:
                    return self.reply(registry.status, b'{"errors":[{"code":"UNAVAILABLE"}]}')
                tag = self.path.rsplit("/", 1)[1]
                if tag not in registry.tags:
                    return self.reply(404, b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}')
                body = json.dumps(registry.tags[tag]).encode()
                return self.reply(200, body, [("Docker-Content-Digest", f"sha256:{'ab' * 32}")])

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"127.0.0.1:{self.server.server_port}/vinzgithub/posture-cockpit"


@pytest.fixture
def registry():
    r = Registry()
    image = r.start()
    yield r, image
    r.server.shutdown()


def run(*argv, capsys):
    status = registry_tag.main(list(argv))
    return status, capsys.readouterr().out


def test_a_version_never_published_can_be_published(registry, capsys):
    _, image = registry
    assert run("state", f"{image}:0.4.1", "--revision", COMMIT, capsys=capsys) == (0, "state=absent\ndigest=\n")
    assert run("digest", f"{image}:0.4.1", capsys=capsys)[0] == 1


def test_a_version_published_from_this_commit_resumes(registry, capsys):
    r, image = registry
    r.tags["0.4.1"] = INDEX
    status, out = run("state", f"{image}:0.4.1", "--revision", COMMIT, capsys=capsys)
    assert status == 0 and "state=same" in out and f"digest=sha256:{'ab' * 32}" in out
    assert run("digest", f"{image}:0.4.1", capsys=capsys) == (0, f"sha256:{'ab' * 32}\n")


@pytest.mark.parametrize("annotations", [{"org.opencontainers.image.revision": "another"}, {}, None])
def test_a_version_published_otherwise_is_never_overwritten(registry, capsys, annotations):
    r, image = registry
    r.tags["0.4.1"] = {**INDEX, "annotations": annotations} if annotations is not None else {"schemaVersion": 2}
    assert "state=other" in run("state", f"{image}:0.4.1", "--revision", COMMIT, capsys=capsys)[1]


def test_the_token_of_the_registry_is_asked_with_the_credentials(registry, capsys, monkeypatch):
    r, image = registry
    r.auth, r.credentials = True, "vinzgithub:secret"
    r.tags["0.4.1"] = INDEX
    monkeypatch.setenv("REGISTRY_USER", "vinzgithub")
    monkeypatch.setenv("REGISTRY_PASSWORD", "secret")
    assert "state=same" in run("state", f"{image}:0.4.1", "--revision", COMMIT, capsys=capsys)[1]
    assert r.tokens == 1


@pytest.mark.parametrize("failure", ["wrong credentials", 500, 429, 403, "unreachable"])
def test_a_registry_that_cannot_be_read_stops_the_publication(registry, capsys, monkeypatch, failure):
    r, image = registry
    if failure == "wrong credentials":
        r.auth, r.credentials = True, "vinzgithub:secret"
        monkeypatch.setenv("REGISTRY_USER", "vinzgithub")
        monkeypatch.setenv("REGISTRY_PASSWORD", "wrong")
    elif failure == "unreachable":
        image = "127.0.0.1:9/vinzgithub/posture-cockpit"
    else:
        r.status = failure
    assert run("state", f"{image}:0.4.1", "--revision", COMMIT, capsys=capsys)[0] == 2
    assert run("digest", f"{image}:0.4.1", capsys=capsys)[0] == 2


@pytest.mark.parametrize("reference", ["posture-cockpit:0.4.1", "ghcr.io/vinzgithub/posture-cockpit", "x/y:"])
def test_malformed_references_are_refused(reference):
    with pytest.raises(registry_tag.RegistryError):
        registry_tag.split(reference)


def test_ghcr_is_spoken_to_over_https_and_the_dry_run_registry_over_http():
    assert registry_tag._scheme("ghcr.io") == "https" and registry_tag._scheme("localhost:5000") == "http"
    assert registry_tag.split("ghcr.io/vinzgithub/posture-cockpit:0.4.1-rc.1") == (
        "ghcr.io", "vinzgithub/posture-cockpit", "0.4.1-rc.1")


def test_a_token_realm_other_than_https_is_refused():
    with pytest.raises(registry_tag.RegistryError, match="https only"):
        registry_tag._token('Bearer realm="file:///etc/passwd",service="x"', "x")
    with pytest.raises(registry_tag.RegistryError, match="https only"):
        registry_tag._token('Bearer realm="http://ghcr.io/token",service="x"', "x")
