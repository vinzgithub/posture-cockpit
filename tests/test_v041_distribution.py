# Copyright © 2026 Vincent Fournet
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""0.4.1: the files that install, build and publish Posture Cockpit say what they should."""

import importlib.util
import re
import tomllib
from pathlib import Path

import pytest

from posture_cockpit import __version__

ROOT = Path(__file__).parent.parent
yaml = pytest.importorskip("yaml")


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_script("release_tags")


def compose():
    return yaml.safe_load((ROOT / "compose.yaml").read_text())


# ---------------------------------------------------------------- compose.yaml
def test_compose_runs_the_published_image_of_this_version_without_building():
    service = compose()["services"]["posture-cockpit"]
    assert service["image"] == f"${{POSTURE_COCKPIT_IMAGE:-ghcr.io/vinzgithub/posture-cockpit:{__version__}}}"
    assert "build" not in service


def test_compose_keeps_the_docker_protections():
    service = compose()["services"]["posture-cockpit"]
    assert service["read_only"] is True and service["tmpfs"] == ["/tmp"]  # noqa: S108
    assert service["security_opt"] == ["no-new-privileges:true"] and service["cap_drop"] == ["ALL"]
    assert "privileged" not in service and "cap_add" not in service and "user" not in service
    assert service["restart"] == "unless-stopped"


def test_compose_names_the_volume_whatever_the_folder():
    # posture-cockpit_posture-cockpit-data: the volume of the installations made with 0.3.x and 0.4.0
    data = compose()
    assert data["name"] == "posture-cockpit" and data["volumes"] == {"posture-cockpit-data": None}
    assert data["services"]["posture-cockpit"]["volumes"] == ["posture-cockpit-data:/data"]


def test_compose_settings_come_from_an_optional_env_file():
    service = compose()["services"]["posture-cockpit"]
    assert service["env_file"] == [{"path": ".env", "required": False}]
    assert service["ports"] == ["${POSTURE_COCKPIT_BIND:+${POSTURE_COCKPIT_BIND}:}${POSTURE_COCKPIT_PORT:-8080}:8080"]
    assert service["environment"] == {"TZ": "${TZ:-Europe/Paris}"}
    assert service["container_name"] == "${POSTURE_COCKPIT_CONTAINER:-posture-cockpit}"


def documented_variables():
    text = (ROOT / ".env.example").read_text()
    for line in text.splitlines():
        assert not line.strip() or line.startswith("#"), f".env.example sets something by default: {line}"
    return set(re.findall(r"^#([A-Z][A-Z0-9_]+)=", text, re.M))


def test_every_variable_of_env_example_is_used():
    config = (ROOT / "src/posture_cockpit/config.py").read_text()
    read = {f"POSTURE_COCKPIT_{n}" for n in re.findall(r'_env(?:_bool)?\("([A-Z_]+)"', config)}
    read |= {"POSTURE_COCKPIT_TIMEZONE", "POSTURE_COCKPIT_DKIM_SELECTORS"}
    compose_text = (ROOT / "compose.yaml").read_text()
    used = read | set(re.findall(r"\$\{([A-Z_]+)", compose_text)) | {"COMPOSE_PROJECT_NAME", "FORWARDED_ALLOW_IPS"}
    assert documented_variables() <= used
    assert {"POSTURE_COCKPIT_PORT", "POSTURE_COCKPIT_BIND", "TZ", "POSTURE_COCKPIT_COOKIE_SECURE",
            "FORWARDED_ALLOW_IPS"} <= documented_variables()


# ------------------------------------------------------------------ Dockerfile
def test_the_image_is_pinned_and_unprivileged():
    text = (ROOT / "Dockerfile").read_text()
    bases = re.findall(r"^FROM (\S+)", text, re.M)
    assert len(bases) == 2 and bases[0] == bases[1]
    assert re.fullmatch(r"python:\d+\.\d+\.\d+-slim-[a-z]+", bases[0]), "an exact Python and Debian release"
    assert "--require-hashes --no-deps -r /tmp/requirements.lock" in text
    assert "pip install --no-cache-dir --no-deps /tmp/*.whl" in text and "pip check" in text
    assert re.search(r"^USER 10001:10001$", text, re.M) and "HEALTHCHECK" in text
    assert re.search(r"build==[\d.]+ setuptools==[\d.]+", text), "pinned build tools"


def test_the_lock_file_satisfies_pyproject():
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    lock = (ROOT / "docker/requirements.lock").read_text()
    pinned = {canonicalize_name(n): v for n, v in re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", lock, re.M)}
    blocks = re.split(r"\n(?=[A-Za-z])", "\n".join(line for line in lock.splitlines() if not line.startswith("#")))
    assert all("--hash=sha256:" in block for block in blocks if block.strip()), "every pin has its hashes"
    for spec in tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]:
        requirement = Requirement(spec)
        name = canonicalize_name(requirement.name)
        assert name in pinned, f"{name} is missing from docker/requirements.lock"
        assert requirement.specifier.contains(pinned[name], prereleases=True), f"{name}=={pinned[name]} vs {spec}"


def test_the_versions_agree():
    versions = release.project_versions(ROOT)
    assert versions == {"pyproject.toml": __version__, "__init__.py": __version__, "compose.yaml": __version__}
    first = re.search(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(), re.M)[1]
    assert first == __version__


# --------------------------------------------------------------- publication
EXISTING = [(0, 3, 0), (0, 3, 1), (0, 4, 0)]
IMAGE = "ghcr.io/vinzgithub/posture-cockpit"


@pytest.mark.parametrize(("tag", "existing", "expected"), [
    ("v0.4.1", EXISTING, ["0.4.1", "0.4", "latest"]),
    ("v0.4.1-rc.1", EXISTING, ["0.4.1-rc.1"]),
    ("v0.4.2-beta.3", EXISTING, ["0.4.2-beta.3"]),
    ("v0.3.2", EXISTING, ["0.3.2", "0.3"]),            # an older line never takes latest back
    ("v0.4.1", [*EXISTING, (0, 4, 2)], ["0.4.1"]),     # nor X.Y
    ("v1.0.0", EXISTING, ["1.0.0", "1.0", "latest"]),
])
def test_image_tags_never_move_backwards_nor_for_a_pre_release(tag, existing, expected):
    assert release.tags_for(IMAGE, tag, existing) == [f"{IMAGE}:{t}" for t in expected]


@pytest.mark.parametrize("tag", ["0.4.1", "v0.4", "v0.4.1-rc1", "v0.4.1-dev.1", "v0.4.01", "v0.4.1 "])
def test_malformed_tags_are_refused(tag):
    with pytest.raises(release.ReleaseError):
        release.parse(tag)


def test_a_release_must_match_the_repository_and_its_pre_release_flag():
    good = {"pyproject.toml": "0.4.1", "__init__.py": "0.4.1", "compose.yaml": "0.4.1"}
    release.check("v0.4.1", False, good)
    with pytest.raises(release.ReleaseError, match="pre-release"):
        release.check("v0.4.1", True, good)
    with pytest.raises(release.ReleaseError, match=r"pyproject\.toml says '0\.4\.1', expected '0\.4\.2'"):
        release.check("v0.4.2", False, good)
    candidate = {"pyproject.toml": "0.4.2rc1", "__init__.py": "0.4.2rc1", "compose.yaml": "0.4.2"}
    release.check("v0.4.2-rc.1", True, candidate)
    assert release.tag_of("0.4.2rc1") == "v0.4.2-rc.1" and release.tag_of("0.4.1") == "v0.4.1"


def test_the_release_workflow_requires_separate_ghcr_approval_after_a_published_release():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    triggers = workflow[True]  # PyYAML reads the key "on" as True
    assert set(triggers) == {"workflow_dispatch", "pull_request"}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["release_tag"]["required"] is True
    assert inputs["confirmation"]["required"] is True
    image = workflow["jobs"]["image"]
    assert image["needs"] == "tests" and workflow["jobs"]["tests"]["uses"] == "./.github/workflows/tests.yml"
    assert workflow["jobs"]["tests"]["if"] == "github.event_name == 'workflow_dispatch'"
    assert image["env"]["PUBLISH"] == "${{ github.event_name == 'workflow_dispatch' }}"
    assert image["env"]["TAG"] == "${{ inputs.release_tag }}"
    assert image["env"]["CONFIRMATION"] == "${{ inputs.confirmation }}"
    # Pull requests publish only to the registry of the job, never to GHCR.
    assert "localhost:5000/posture-cockpit" in image["env"]["IMAGE"] and "registry" in image["services"]
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert "value=latest" not in text and "type=raw" not in text  # tags come from release_tags.py only
    steps = {s.get("id") or s.get("name"): s for s in image["steps"]}
    order = [s.get("id") or s.get("name") for s in image["steps"]]
    approval = steps["release_gate"]
    assert approval["if"] == "env.PUBLISH == 'true'"
    assert order.index("release_gate") < order.index("release") < order.index("registry")
    assert "PUBLISH_GHCR" in approval["run"]
    assert "releases/tags/" in approval["run"] and ".published_at" in approval["run"]
    assert "refs/heads/main" in approval["run"]  # manual dispatch from main only
    assert 'git rev-parse refs/remotes/origin/main' in approval["run"]  # tested main HEAD equals tag commit
    assert steps["source"]["run"].find("git rev-parse HEAD") >= 0
    assert steps["registry"]["run"].find("steps.source.outputs.revision") >= 0
    assert steps["build"]["with"]["annotations"].find("steps.source.outputs.revision") >= 0
    assert steps["Sign in to ghcr.io"]["if"] == "env.PUBLISH == 'true'"
    assert order.index("registry") < order.index("build") < order.index("tags")
    build = steps["build"]
    assert build["if"] == "steps.registry.outputs.state == 'absent'"   # resumed or refused otherwise
    assert build["with"]["tags"] == "${{ env.IMAGE }}:${{ steps.release.outputs.version }}"  # the exact version only
    assert build["with"]["sbom"] is True and build["with"]["provenance"] == "mode=max"
    assert build["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert "state=other" in steps["registry"]["run"] and "exit 1" in steps["registry"]["run"]
    assert "imagetools create" in steps["tags"]["run"] and "registry_tag.py digest" in steps["tags"]["run"]
    tests = yaml.safe_load((ROOT / ".github/workflows/tests.yml").read_text())
    assert "workflow_call" in tests[True]
    # the names the branch protection of main requires
    assert {"test", "browser", "docker"} <= set(tests["jobs"])
