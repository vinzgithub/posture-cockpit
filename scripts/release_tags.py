#!/usr/bin/env python3
# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Version checks and image tags of a release (used by .github/workflows/release.yml).

    release_tags.py --image ghcr.io/vinzgithub/posture-cockpit --tag v0.4.1 --prerelease false
    release_tags.py --image ghcr.io/vinzgithub/posture-cockpit            (dry run: the version of pyproject.toml)

Checks that the tag, pyproject.toml, posture_cockpit.__version__ and the image of compose.yaml
name the same version, and that GitHub's "pre-release" box matches the tag. Then prints, in the
format of $GITHUB_OUTPUT, the version and the tags to publish:

- always the exact version (0.4.1, or 0.4.1-rc.1 for a pre-release);
- for a final version only: X.Y, unless a later X.Y.Z is already released, and latest, unless
  a later version is already released. A pre-release never moves X.Y nor latest.

Only the standard library: the workflow runs it before installing anything.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = re.compile(r"v(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
                 r"(?:-(?P<kind>alpha|beta|rc)\.(?P<number>[1-9]\d*))?")
PEP440 = {"alpha": "a", "beta": "b", "rc": "rc"}


class ReleaseError(Exception):
    pass


def parse(tag: str) -> tuple[tuple[int, int, int], str | None, str]:
    """(major, minor, patch), pre-release part (rc.1) or None, and the PEP 440 version (0.4.1rc1)."""
    match = TAG.fullmatch(tag)
    if not match:
        raise ReleaseError(f"{tag!r} is not a release tag: vX.Y.Z, or vX.Y.Z-rc.N (alpha, beta, rc)")
    numbers = (int(match["major"]), int(match["minor"]), int(match["patch"]))
    base = ".".join(map(str, numbers))
    if match["kind"]:
        return numbers, f"{match['kind']}.{match['number']}", f"{base}{PEP440[match['kind']]}{match['number']}"
    return numbers, None, base


def tag_of(pep440: str) -> str:
    """The release tag of a PEP 440 version: 0.4.1 -> v0.4.1, 0.4.1rc1 -> v0.4.1-rc.1."""
    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", pep440)
    if not match:
        raise ReleaseError(f"pyproject.toml: {pep440!r} is not X.Y.Z or X.Y.ZrcN")
    kind = {"a": "alpha", "b": "beta", "rc": "rc"}.get(match[2] or "")
    return f"v{match[1]}" + (f"-{kind}.{match[3]}" if kind else "")


def project_versions(root: Path = ROOT) -> dict[str, str]:
    """The version as each file of the repository states it."""
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    init = re.search(r'^__version__ = "([^"]+)"', (root / "src/posture_cockpit/__init__.py").read_text(), re.M)
    compose = re.search(r"\$\{POSTURE_COCKPIT_IMAGE:-[^:}]+:([^}]+)\}", (root / "compose.yaml").read_text())
    return {"pyproject.toml": pyproject, "__init__.py": init[1] if init else "",
            "compose.yaml": compose[1] if compose else ""}


def released(root: Path = ROOT) -> list[tuple[int, int, int]]:
    """Final versions already tagged in the repository."""
    out = subprocess.run(["git", "tag", "--list", "v*"],  # noqa: S607 - git of the CI runner
                         cwd=root, capture_output=True, text=True, check=False).stdout
    versions = []
    for tag in out.split():
        try:
            numbers, pre, _ = parse(tag)
        except ReleaseError:
            continue
        if pre is None:
            versions.append(numbers)
    return versions


def tags_for(image: str, tag: str, existing: list[tuple[int, int, int]]) -> list[str]:
    numbers, pre, _ = parse(tag)
    version = ".".join(map(str, numbers)) + (f"-{pre}" if pre else "")
    tags = [f"{image}:{version}"]
    if pre is None:
        same_minor = [v for v in existing if v[:2] == numbers[:2]]
        if all(v <= numbers for v in same_minor):
            tags.append(f"{image}:{numbers[0]}.{numbers[1]}")
        if all(v <= numbers for v in existing):
            tags.append(f"{image}:latest")
    return tags


def check(tag: str, prerelease: bool | None, versions: dict[str, str]) -> None:
    numbers, pre, pep440 = parse(tag)
    final = ".".join(map(str, numbers))
    expected = {"pyproject.toml": pep440, "__init__.py": pep440, "compose.yaml": final}
    wrong = [f"{name} says {versions[name]!r}, expected {value!r}" for name, value in expected.items()
             if versions[name] != value]
    if wrong:
        raise ReleaseError(f"{tag} does not match the repository: " + "; ".join(wrong))
    if prerelease is not None and prerelease != (pre is not None):
        raise ReleaseError(f"{tag}: the GitHub release is {'a' if prerelease else 'not a'} pre-release, "
                           f"the tag says the opposite")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--image", required=True)
    parser.add_argument("--tag", help="tag of the release (default: v + the version of pyproject.toml, a dry run)")
    parser.add_argument("--prerelease", choices=["true", "false"], help="GitHub's pre-release flag")
    args = parser.parse_args(argv)
    versions = project_versions()
    try:
        tag = args.tag or tag_of(versions["pyproject.toml"])
        check(tag, None if args.prerelease is None else args.prerelease == "true", versions)
        numbers, pre, _ = parse(tag)
        existing = [v for v in released() if v != numbers]
        tags = tags_for(args.image, tag, existing)
    except ReleaseError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    version = tags[0].rsplit(":", 1)[1]
    print(f"version={version}")
    print(f"prerelease={'true' if pre else 'false'}")
    print(f"tags={','.join(tags)}")
    print(f"{tag}: {', '.join(tags)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
