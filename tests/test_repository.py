"""Repository invariants: run-mode scripts, import bans, image and env template."""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from ai_gateway.core.config import Settings

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "ai_gateway"
SCRIPTS = PACKAGE / "scripts"
RUN_MODE_SCRIPTS = ("docker_start.sh", "scheduler_start.sh", "pre_start.sh")


def _commands(path: Path) -> list[str]:
    """Return the script's non-comment, non-blank lines."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


@pytest.mark.parametrize("name", RUN_MODE_SCRIPTS)
def test_run_mode_scripts_never_run_alembic(name: str) -> None:
    for line in _commands(SCRIPTS / name):
        assert not re.search(r"\balembic\b", line), line
        assert not re.search(r"\b(upgrade|revision|autogenerate)\b", line), line


@pytest.mark.parametrize("name", ("docker_start.sh", "scheduler_start.sh"))
def test_run_modes_run_the_pre_start_checks(name: str) -> None:
    assert "./ai_gateway/scripts/pre_start.sh" in "\n".join(_commands(SCRIPTS / name))


def test_pre_start_runs_the_revision_check() -> None:
    assert "python -m ai_gateway.prestart" in "\n".join(
        _commands(SCRIPTS / "pre_start.sh")
    )


def test_only_ai_migrate_upgrades_and_it_never_autogenerates() -> None:
    commands = "\n".join(_commands(SCRIPTS / "ai_migrate.sh"))
    assert "alembic -c /opt/ai_gateway/alembic.ini upgrade head" in commands
    assert "revision" not in commands
    assert "autogenerate" not in commands


def test_the_dockerfile_never_migrates_and_drops_root() -> None:
    dockerfile = (PACKAGE / "Dockerfile").read_text(encoding="utf-8")
    assert "upgrade head" not in dockerfile
    assert "useradd --uid 1000 --gid appuser" in dockerfile
    assert "\nUSER 1000:1000\n" in dockerfile
    assert "python -m pip uninstall -y pip" in dockerfile
    digests = re.findall(
        r"^FROM python:3\.14-slim@sha256:([0-9a-f]{64})", dockerfile, re.M
    )
    assert len(digests) == 2 and digests[0] == digests[1]


def test_the_dockerfile_carries_the_debian_patch_layer() -> None:
    dockerfile = (PACKAGE / "Dockerfile").read_text(encoding="utf-8")
    assert (
        "RUN apt-get update \\\n"
        "    && apt-get upgrade -y \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    ) in dockerfile


def _ruff(path: str, source: str) -> subprocess.CompletedProcess[str]:
    ruff = shutil.which("ruff") or str(Path(sys.executable).parent / "ruff")
    return subprocess.run(  # nosec B603
        [ruff, "check", "--select", "TID251", "--stdin-filename", path, "-"],
        input=source,
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )


@pytest.mark.parametrize(
    ("path", "module", "banned"),
    [
        ("ai_gateway/providers/x.py", "auth_sdk_m8", True),
        ("ai_gateway/credentials/x.py", "auth_sdk_m8", True),
        ("ai_gateway/providers/x.py", "ai_gateway.db_models.credential_version", True),
        (
            "ai_gateway/credentials/x.py",
            "ai_gateway.db_models.credential_version",
            False,
        ),
    ],
)
def test_the_import_bans(path: str, module: str, banned: bool) -> None:
    result = _ruff(path, f"import {module}\n")
    assert ("TID251" in result.stdout) is banned, result.stdout


def test_no_service_module_imports_auth_sdk_m8() -> None:
    for source in PACKAGE.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert not re.search(r"^\s*(from|import)\s+auth_sdk_m8\b", text, re.M), source


def _example_keys() -> dict[str, str | None]:
    """Map each AI_* key of .env.example to its value (None when commented)."""
    keys: dict[str, str | None] = {}
    for line in (PACKAGE / ".env.example").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^(#?)(AI_[A-Z0-9_]+)=(.*)$", line)
        if match:
            keys[match.group(2)] = None if match.group(1) else match.group(3)
    return keys


def test_the_env_template_lists_every_gateway_key() -> None:
    declared = {name for name in Settings.model_fields if name.startswith("AI_")}
    assert set(_example_keys()) == declared


def test_every_gateway_placeholder_is_changethis() -> None:
    keys = _example_keys()
    assert keys.pop("AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED") is None
    assert keys.pop("AI_RUN_MODE") is None  # set by the scheduler's command only
    assert set(keys.values()) == {"changethis"}


def test_the_env_template_keeps_api_key_introspection_off() -> None:
    template = (PACKAGE / ".env.example").read_text(encoding="utf-8")
    assert not re.search(r"^API_KEY_INTROSPECTION_ENABLED=true", template, re.M)
