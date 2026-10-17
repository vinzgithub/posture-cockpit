#!/usr/bin/env python3
# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""What a registry holds under a tag (used by .github/workflows/release.yml).

    registry_tag.py state  ghcr.io/vinzgithub/posture-cockpit:0.4.1 --revision <commit>
    registry_tag.py digest ghcr.io/vinzgithub/posture-cockpit:0.4.1

``state`` prints, in the format of $GITHUB_OUTPUT, ``state=absent`` (the tag does not exist),
``state=same`` (it exists and was built from this commit: an interrupted publication can resume)
or ``state=other`` (it exists, built from another commit or from an unknown one: never overwrite
it), and ``digest=``. ``digest`` prints the digest of the tag. Any other answer of the registry,
an authentication refused, a timeout... is an error (exit 2): the publication stops rather than
guess. ``digest`` exits 1 for an absent tag.

Credentials, if any, come from REGISTRY_USER and REGISTRY_PASSWORD (for ghcr.io: the actor and
GITHUB_TOKEN). A registry on localhost (the dry run) is spoken to over HTTP. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
REVISION = "org.opencontainers.image.revision"
TIMEOUT = 20


class RegistryError(Exception):
    pass


def split(reference: str) -> tuple[str, str, str]:
    """host, repository, tag of ``host/repository:tag``."""
    match = re.fullmatch(r"([^/]+)/([a-z0-9._/-]+):([A-Za-z0-9_][A-Za-z0-9._-]{0,127})", reference)
    if not match or ("." not in match[1] and ":" not in match[1] and match[1] != "localhost"):
        raise RegistryError(f"{reference!r} is not host/repository:tag")
    return match[1], match[2], match[3]


def _scheme(host: str) -> str:
    return "http" if host.split(":")[0] in {"localhost", "127.0.0.1", "::1"} else "https"


def _open(request: urllib.request.Request) -> tuple[int, dict[str, str], bytes]:
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310 - registry URL built above
            return answer.status, dict(answer.headers), answer.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers or {}), error.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise RegistryError(f"{request.full_url}: {error}") from None


def _token(challenge: str, repository: str) -> str:
    """A bearer token from the realm the registry named, with the credentials if there are any."""
    fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    if not challenge.lower().startswith("bearer") or "realm" not in fields:
        raise RegistryError(f"unexpected authentication challenge: {challenge}")
    realm = urllib.parse.urlsplit(fields["realm"])
    if realm.scheme != "https" and not (realm.scheme == "http" and _scheme(realm.netloc) == "http"):
        raise RegistryError(f"refusing the token realm {fields['realm']!r}: https only")
    query = {"service": fields.get("service", ""), "scope": fields.get("scope", f"repository:{repository}:pull")}
    request = urllib.request.Request(fields["realm"] + "?" + urllib.parse.urlencode(query))  # noqa: S310 - checked
    user, password = os.environ.get("REGISTRY_USER", ""), os.environ.get("REGISTRY_PASSWORD", "")
    if user and password:
        request.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    status, _, body = _open(request)
    if status != 200:
        raise RegistryError(f"the registry refused a token ({status})")
    data = json.loads(body or b"{}")
    token = data.get("token") or data.get("access_token")
    if not token:
        raise RegistryError("the registry gave no token")
    return token


def manifest(reference: str) -> tuple[str, dict] | None:
    """(digest, manifest) of a tag, None when the registry says it does not exist."""
    host, repository, tag = split(reference)
    url = f"{_scheme(host)}://{host}/v2/{repository}/manifests/{tag}"
    request = urllib.request.Request(url, headers={"Accept": ACCEPT})  # noqa: S310 - http(s) built above
    status, headers, body = _open(request)
    if status == 401:
        challenge = next((v for k, v in headers.items() if k.lower() == "www-authenticate"), "")
        request.add_header("Authorization", "Bearer " + _token(challenge, repository))
        status, headers, body = _open(request)
    if status == 404:
        return None
    if status != 200:
        raise RegistryError(f"{reference}: the registry answered {status} {body[:200]!r}")
    digest = next((v for k, v in headers.items() if k.lower() == "docker-content-digest"), "")
    digest = digest or "sha256:" + hashlib.sha256(body).hexdigest()
    try:
        return digest, json.loads(body)
    except ValueError:
        raise RegistryError(f"{reference}: unreadable manifest") from None


def state(reference: str, revision: str) -> tuple[str, str]:
    found = manifest(reference)
    if found is None:
        return "absent", ""
    digest, content = found
    built_from = (content.get("annotations") or {}).get(REVISION)
    return ("same" if built_from and built_from == revision else "other"), digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    of_state = sub.add_parser("state")
    of_state.add_argument("reference")
    of_state.add_argument("--revision", required=True)
    of_digest = sub.add_parser("digest")
    of_digest.add_argument("reference")
    args = parser.parse_args(argv)
    try:
        if args.command == "state":
            found, digest = state(args.reference, args.revision)
            print(f"state={found}")
            print(f"digest={digest}")
            print(f"{args.reference}: {found} {digest}", file=sys.stderr)
            return 0
        found_manifest = manifest(args.reference)
        if found_manifest is None:
            print(f"{args.reference}: absent", file=sys.stderr)
            return 1
        print(found_manifest[0])
        return 0
    except RegistryError as error:
        print(f"::error::registry: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
