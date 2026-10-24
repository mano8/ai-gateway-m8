"""
The compose policy test (T87): every gateway deployment example keeps the
gateway's container, secret, spool and configuration rules.

It reads the stack files as data (no Docker needed) and asserts, for the web
service, the scheduler and ``ai-migrate`` of every stack: non-root user,
read-only root, every capability dropped and none added, no-new-privileges,
memory and pid limits, no Docker socket or host-path mount, the per-service
secret list D-42 states, the ``ai_spool`` volume without NFS/CIFS options and
sized by the D-45 rule, Alembic only in ``ai-migrate``; and, for each stack's
gateway env template, the ratified first-deployment values.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

import pytest
import yaml

ROOT: Final = Path(__file__).resolve().parent.parent
COMPOSE: Final = ROOT / "docker_compose"

#: The runnable stacks, and the production reference template.
RUNNABLE: Final = ("postgres_m8", "encrypted_db_m8", "vault_transit_m8", "vault_kv_m8")
TEMPLATE: Final = "vault_prod_template"
STACKS: Final = (*RUNNABLE, TEMPLATE)

WEB: Final = "ai_gateway"
SCHEDULER: Final = "ai_gateway_scheduler"
MIGRATE: Final = "ai-migrate"
GATEWAY: Final = (WEB, SCHEDULER, MIGRATE)

#: Secrets every gateway service needs to construct its settings.
COMMON_SECRETS: Final = frozenset(
    {
        "ai_deployment_id",
        "ai_service_clients.json",
        "gateway_secret_key",
        "gateway_access_secret_key",
        "gateway_refresh_secret_key",
        "gateway_private_api_secret",
        "event_signing_key",
        "health_detail_credential",
        "metrics_scrape_credential",
    }
)

#: The KEK material (or Vault trust anchor) each stack's backend needs.
BACKEND_SECRETS: Final = {
    "postgres_m8": frozenset({"ai_kek"}),
    "encrypted_db_m8": frozenset({"ai_kek"}),
    "vault_transit_m8": frozenset({"stack_ca.pem"}),
    "vault_kv_m8": frozenset({"stack_ca.pem"}),
    TEMPLATE: frozenset({"vault_ca.pem", "vault_role_id", "vault_secret_id"}),
}

#: D-42: the receipt seed and fingerprint key on the web service only; the
#: schema-owner password on ai-migrate only; the runtime password never there.
ROLE_SECRETS: Final = {
    WEB: frozenset({"ai_runtime_db_password", "ai_fingerprint_key", "ai_receipt_seed"}),
    SCHEDULER: frozenset({"ai_runtime_db_password"}),
    MIGRATE: frozenset({"ai_owner_db_password"}),
}

#: The bounded spool volume (D-45) and the learning Vault's AppRole volume.
SPOOL: Final = "ai_spool:/spool"
APPROLE: Final = "vault_approle:/run/vault:ro"
LEARNING_VAULT: Final = ("vault_transit_m8", "vault_kv_m8")
LOCAL_IMAGE: Final = "ai-gateway-m8:stack"

#: Settings whose value is a secret: only their <FIELD>_FILE form may be set.
SECRET_SETTINGS: Final = (
    "SECRET_KEY",
    "ACCESS_SECRET_KEY",
    "REFRESH_SECRET_KEY",
    "PRIVATE_API_SECRET",
    "EVENT_SIGNING_KEY",
    "DB_PASSWORD",
    "HEALTH_DETAIL_CREDENTIAL",
    "METRICS_SCRAPE_CREDENTIAL",
    "AI_SERVICE_CLIENTS",
    "AI_DEPLOYMENT_ID",
)

_ENV_LINE: Final = re.compile(r"^(#?)\s*([A-Z][A-Z0-9_]*)=(.*)$")


def _compose_file(stack: str) -> Path:
    name = "docker-compose.template.yml" if stack == TEMPLATE else "docker-compose.yml"
    return COMPOSE / stack / name


def _compose(stack: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(_compose_file(stack).read_text("utf-8"))
    return data


def _services(stack: str) -> Mapping[str, dict[str, Any]]:
    services: Mapping[str, dict[str, Any]] = _compose(stack)["services"]
    return services


def _env(stack: str) -> tuple[dict[str, str], set[str]]:
    """The gateway env template: active ``KEY=value`` pairs and every listed key."""
    active: dict[str, str] = {}
    listed: set[str] = set()
    text = (COMPOSE / stack / "gateway.env.example").read_text("utf-8")
    for line in text.splitlines():
        match = _ENV_LINE.match(line.strip())
        if not match:
            continue
        listed.add(match.group(2))
        if not match.group(1):
            active[match.group(2)] = match.group(3)
    return active, listed


def _secret_names(service: Mapping[str, Any]) -> set[str]:
    return {
        s if isinstance(s, str) else s["source"] for s in service.get("secrets", [])
    }


def _volume_entries(service: Mapping[str, Any]) -> list[str]:
    entries = []
    for volume in service.get("volumes", []):
        if isinstance(volume, str):
            entries.append(volume)
        else:
            entries.append(f"{volume.get('source', '')}:{volume['target']}")
    return entries


def _command_text(service: Mapping[str, Any]) -> str:
    parts = [service.get("command", ""), service.get("entrypoint", "")]
    return " ".join(" ".join(p) if isinstance(p, list) else str(p) for p in parts)


def _limits(service: Mapping[str, Any]) -> Mapping[str, Any]:
    limits: Mapping[str, Any] = (
        service.get("deploy", {}).get("resources", {}).get("limits", {})
    )
    return limits


# ── container hardening ──────────────────────────────────────────────────────


@pytest.mark.parametrize("stack", STACKS)
@pytest.mark.parametrize("name", GATEWAY)
def test_gateway_services_are_hardened(stack: str, name: str) -> None:
    service = _services(stack)[name]
    assert service["user"] == "1000:1000"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert "privileged" not in service
    assert "no-new-privileges:true" in service["security_opt"]
    assert _limits(service).get("memory")
    assert _limits(service).get("pids")


@pytest.mark.parametrize("stack", STACKS)
@pytest.mark.parametrize("name", GATEWAY)
def test_gateway_services_mount_no_host_path(stack: str, name: str) -> None:
    allowed = {SPOOL} if name != MIGRATE else set()
    if stack in LEARNING_VAULT:
        allowed |= {APPROLE}
    entries = _volume_entries(_services(stack)[name])
    assert set(entries) <= allowed, entries
    for entry in entries:
        assert not entry.startswith((".", "/", "~")), entry


@pytest.mark.parametrize("stack", STACKS)
def test_no_service_mounts_the_docker_socket(stack: str) -> None:
    for name, service in _services(stack).items():
        for entry in _volume_entries(service):
            assert "docker.sock" not in entry, name


@pytest.mark.parametrize("stack", STACKS)
@pytest.mark.parametrize("name", GATEWAY)
def test_the_per_service_secret_list(stack: str, name: str) -> None:
    expected = COMMON_SECRETS | BACKEND_SECRETS[stack] | ROLE_SECRETS[name]
    assert _secret_names(_services(stack)[name]) == expected


@pytest.mark.parametrize("stack", STACKS)
def test_d42_secret_placement(stack: str) -> None:
    services = _services(stack)
    holders = {
        secret: {n for n in GATEWAY if secret in _secret_names(services[n])}
        for secret in ("ai_receipt_seed", "ai_fingerprint_key", "ai_owner_db_password")
    }
    assert holders == {
        "ai_receipt_seed": {WEB},
        "ai_fingerprint_key": {WEB},
        "ai_owner_db_password": {MIGRATE},
    }


@pytest.mark.parametrize("stack", RUNNABLE)
def test_the_gateway_is_built_from_this_repository(stack: str) -> None:
    for name in GATEWAY:
        service = _services(stack)[name]
        assert service["image"] == LOCAL_IMAGE
        assert service["build"]["context"] == "../.."
        assert service["build"]["dockerfile"] == "ai_gateway/Dockerfile"


@pytest.mark.parametrize("stack", STACKS)
def test_every_other_image_is_pinned(stack: str) -> None:
    for name, service in _services(stack).items():
        image = service.get("image", "")
        if image == LOCAL_IMAGE:
            continue
        repository, _, tag = image.rpartition(":")
        assert repository and tag and tag != "latest", (name, image)


# ── run-modes, scheduler and migrations ──────────────────────────────────────


@pytest.mark.parametrize("stack", STACKS)
def test_only_ai_migrate_runs_alembic(stack: str) -> None:
    services = _services(stack)
    assert "ai_migrate.sh" in _command_text(services[MIGRATE])
    for name in (WEB, SCHEDULER):
        text = _command_text(services[name])
        assert "alembic" not in text and "ai_migrate" not in text, name
    assert "scheduler_start.sh" in _command_text(services[SCHEDULER])
    assert "command" not in services[WEB]  # the image's web run-mode


@pytest.mark.parametrize("stack", STACKS)
def test_web_and_scheduler_start_after_ai_migrate(stack: str) -> None:
    services = _services(stack)
    for name in (WEB, SCHEDULER):
        condition = services[name]["depends_on"][MIGRATE]["condition"]
        assert condition == "service_completed_successfully", name
    assert services[MIGRATE]["restart"] == "no"


@pytest.mark.parametrize("stack", STACKS)
def test_the_scheduler_run_mode(stack: str) -> None:
    services = _services(stack)
    scheduler = services[SCHEDULER]
    assert set(scheduler["networks"]) == {"data_net", "ai_net", "ai_egress"}
    assert "ports" not in scheduler and "expose" not in scheduler
    assert not any(
        str(label).startswith("traefik") for label in scheduler.get("labels", [])
    )
    assert scheduler["deploy"]["replicas"] == 1
    assert "--healthcheck" in scheduler["healthcheck"]["test"]
    assert scheduler["env_file"] == services[WEB]["env_file"]
    assert {"ai_net", "ai_egress", "app_net"} <= set(services[WEB]["networks"])
    assert services[MIGRATE]["networks"] == ["data_net"]
    assert services[MIGRATE]["environment"]["AI_RUN_MODE"] == "scheduler"


@pytest.mark.parametrize("stack", STACKS)
def test_network_posture(stack: str) -> None:
    networks = _compose(stack)["networks"]
    for name in ("app_net", "data_net", "ai_net"):
        assert networks[name]["internal"] is True, name
    members = {
        name
        for name, service in _services(stack).items()
        if "ai_net" in service.get("networks", [])
        or "ai_egress" in service.get("networks", [])
    }
    assert members <= {WEB, SCHEDULER, "ollama"}, members
    for name, service in _services(stack).items():
        if "ai_egress" in service.get("networks", []):
            assert name in (WEB, SCHEDULER), name


# ── the D-45 spool ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("stack", STACKS)
def test_the_spool_volume(stack: str) -> None:
    services = _services(stack)
    for name in (WEB, SCHEDULER):
        assert SPOOL in _volume_entries(services[name]), name
    volume = _compose(stack)["volumes"]["ai_spool"] or {}
    assert volume.get("driver", "local") == "local"
    options = " ".join(str(v) for v in (volume.get("driver_opts") or {}).values())
    assert not re.search(r"nfs|cifs|smb", options, re.I)
    active, _ = _env(stack)
    declared = int(volume["labels"]["org.m8.ai-spool.size-bytes"])
    spool_max = int(active["AI_OCR_SPOOL_MAX_BYTES"])
    assert active["AI_OCR_SPOOL_DIR"] == "/spool"
    assert spool_max <= declared
    assert (
        int(active["AI_MAX_CONCURRENT_SPOOLS"]) * int(active["AI_MAX_REQUEST_BYTES"])
        <= spool_max
    )


# ── the env template and the ratified first-deployment values ────────────────


@pytest.mark.parametrize("stack", STACKS)
def test_the_ratified_first_deployment_values(stack: str) -> None:
    active, _ = _env(stack)
    assert active["AI_USER_BYOK_ENABLED"] == "true"  # Q6
    assert active.get("AI_RESTRICTED_OCR_RESTORE_RESIDUAL_ACCEPTED", "false") == "false"
    assert "AI_DATA_CLASS_POLICY" not in active  # Q4: the default table
    assert active["AI_JOB_CONTEXT_MAX_TTL_SECONDS"] == "900"  # Q5
    assert active.get("API_KEY_INTROSPECTION_ENABLED", "false") == "false"  # D-05
    capabilities = active["AI_CAPABILITIES_ENABLED"].split(",")
    assert "ocr" not in [c.strip() for c in capabilities]  # Q12
    assert "AI_RUN_MODE" not in active  # set by the scheduler's command only


@pytest.mark.parametrize("stack", STACKS)
def test_the_env_template_lists_every_gateway_key(stack: str) -> None:
    template = (ROOT / "ai_gateway" / ".env.example").read_text("utf-8")
    gateway_keys = {
        m.group(2)
        for m in map(_ENV_LINE.match, template.splitlines())
        if m and m.group(2).startswith("AI_")
    }
    _, listed = _env(stack)
    missing = {k for k in gateway_keys if k not in listed and f"{k}_FILE" not in listed}
    assert not missing


@pytest.mark.parametrize("stack", STACKS)
def test_secrets_are_files_never_values(stack: str) -> None:
    active, _ = _env(stack)
    web_secrets = _secret_names(_services(stack)[WEB])
    for name in SECRET_SETTINGS:
        assert name not in active, name
        assert f"{name}_FILE" in active, name
    for key, value in active.items():
        if key.endswith("_FILE") and value.startswith("/run/secrets/"):
            assert value.removeprefix("/run/secrets/") in web_secrets, key


@pytest.mark.parametrize("stack", STACKS)
def test_production_and_vault_addresses(stack: str) -> None:
    active, _ = _env(stack)
    if stack != "postgres_m8":
        assert active["ENVIRONMENT"] == "production"
        assert active["STRICT_PRODUCTION_MODE"] == "true"
    if stack in (*LEARNING_VAULT, TEMPLATE):
        assert active["AI_VAULT_ADDR"].startswith("https://")
        assert active["AI_VAULT_AUTH_METHOD"] == "approle"
        assert "AI_VAULT_TOKEN_FILE" not in active


def test_the_production_template_holds_no_vault_token() -> None:
    for path in _shipped_files(COMPOSE / TEMPLATE):
        text = path.read_text("utf-8")
        assert not re.search(r"^\s*VAULT_(DEV_ROOT_)?TOKEN\s*[:=]", text, re.M), path
    services = _services(TEMPLATE)
    assert "vault" not in services and "vault-init" not in services


# ── self-containment ─────────────────────────────────────────────────────────


def _shipped_files(directory: Path) -> list[Path]:
    """The files a stack ships: not its generated secrets or runtime env files."""
    return [
        path
        for path in directory.rglob("*")
        if path.is_file()
        and "secrets" not in path.relative_to(directory).parts
        and not (path.name.endswith(".env") or path.name == ".env")
    ]


def _relative_sources(stack: str) -> list[str]:
    data = _compose(stack)
    sources = []
    for service in data["services"].values():
        sources += [e.split(":")[0] for e in _volume_entries(service)]
        sources += service.get("env_file", [])
        build = service.get("build")
        if build:
            sources.append(build["context"])
    for section in ("secrets", "configs"):
        sources += [
            v["file"] for v in (data.get(section) or {}).values() if "file" in v
        ]
    return [s for s in sources if s.startswith(".")]


@pytest.mark.parametrize("stack", STACKS)
def test_no_stack_file_refers_outside_this_repository(stack: str) -> None:
    for source in _relative_sources(stack):
        resolved = (COMPOSE / stack / source).resolve()
        assert resolved == ROOT or ROOT in resolved.parents, source
    for path in _shipped_files(COMPOSE / stack):
        assert ".workspace" not in path.read_text("utf-8"), path


@pytest.mark.parametrize("stack", STACKS)
def test_runtime_files_are_ignored(stack: str) -> None:
    ignore = (COMPOSE / stack / ".gitignore").read_text("utf-8").splitlines()
    assert {"*.env", "!*.env.example", "secrets/"} <= set(ignore)
    for env_file in _services(stack)[WEB]["env_file"]:
        assert (COMPOSE / stack / f"{env_file}.example").is_file(), env_file
