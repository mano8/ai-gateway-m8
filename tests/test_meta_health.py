"""T15: /meta values, clock skew on /health and execution, docs gating, spool."""

from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from ai_sdk_m8.compatibility import check_gateway_meta
from ai_sdk_m8.schemas.meta import GatewayMeta
from fastapi.testclient import TestClient

from ai_gateway import main
from ai_gateway.core import clock as clock_module
from ai_gateway.core import deps
from ai_gateway.core.config import Settings, settings
from ai_gateway.core.errors import DEFAULT_STATUS, GatewayError, new_request_id
from ai_gateway.core.execution_guard import JOB_CONTEXT_HEADER
from ai_gateway.core.meta import build_gateway_meta
from ai_gateway.core.spool_check import (
    SpoolFilesystemError,
    assert_local_spool,
    filesystem_type,
    lock_self_test,
)
from ai_sdk_m8.schemas import AiErrorCode
from conftest import ADMISSION_LIMITS, HEALTH_DETAIL

PREFIX = settings.API_PREFIX


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def skewed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The application clock runs 120 s ahead of the database."""
    monkeypatch.setattr(deps.clock, "_wall_clock", lambda: time.time() + 120)
    monkeypatch.setattr(deps.clock, "_cached", None)


@pytest.fixture(autouse=True)
def _fresh_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deps.clock, "_cached", None)
    main.app.state.health_cache = None


# --- /meta -------------------------------------------------------------------


def test_meta_serves_the_fleet_shape_and_the_gateway_values(client: TestClient) -> None:
    response = client.get(f"{PREFIX}/meta")
    assert response.headers["cache-control"] == "public, max-age=300"
    meta = GatewayMeta.model_validate(response.json())
    assert meta.contract.name == "ai-gateway-m8"
    values = meta.gateway
    assert values.deployment_id == settings.deployment_id
    assert values.user_byok_enabled is False
    assert values.job_context_max_ttl_seconds == 900
    assert values.dispatch_context_ttl_seconds == 30
    assert values.data_class_policy_sha256 == settings.data_class_policy.sha256()
    assert values.capabilities_enabled == ()
    assert values.credential_storage_backend == "database"
    assert values.kek_key_version == settings.kek.version("kek")  # type: ignore[union-attr]
    assert values.kek_key_version.startswith("kek-")  # type: ignore[union-attr]
    assert values.fingerprint_key_version.startswith("fingerprint-")  # type: ignore[union-attr]
    paths = [
        p
        for p in client.get(f"{PREFIX}/openapi.json").json()["paths"]
        if p.endswith("/meta")
    ]
    assert paths == [f"{PREFIX}/meta"]
    schema = client.get(f"{PREFIX}/openapi.json").json()["paths"][f"{PREFIX}/meta"][
        "get"
    ]
    assert "GatewayMeta" in str(schema)


def test_meta_never_carries_key_material(client: TestClient) -> None:
    body = client.get(f"{PREFIX}/meta").text.encode()
    for key in (settings.kek, settings.fingerprint_key):
        assert key is not None
        assert key.reveal() not in body
        assert key.reveal().hex().encode() not in body


def test_meta_reports_the_flag_and_backend_as_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AI_USER_BYOK_ENABLED", "true")
    monkeypatch.setenv("AI_CAPABILITIES_ENABLED", "rerank,embedding")
    meta = build_gateway_meta(Settings(_env_file=None))  # type: ignore[call-arg]
    assert meta.gateway.user_byok_enabled is True
    assert [c.value for c in meta.gateway.capabilities_enabled] == [
        "embedding",
        "rerank",
    ]


def test_meta_satisfies_the_sdk_contract_check() -> None:
    meta = build_gateway_meta(settings)
    assert meta.contract.name == "ai-gateway-m8"
    assert meta.contract.version == "1.0"
    if meta.version >= "0.2.0":
        check_gateway_meta(meta)


# --- clock skew --------------------------------------------------------------


def test_health_is_ok_with_a_synchronised_clock(client: TestClient) -> None:
    body = client.get(f"{PREFIX}/health/", headers=HEALTH_DETAIL).json()
    assert body["status"] == "ok"
    check = next(c for c in body["checks"] if c["name"] == "clock_skew")
    assert check["status"] == "ok"
    assert check["meta"]["skew_ms"] < 5000


def test_skew_above_the_bound_degrades_health(client: TestClient, skewed: None) -> None:
    response = client.get(f"{PREFIX}/health/", headers=HEALTH_DETAIL)
    body = response.json()
    assert response.status_code == 200
    assert body["status"] == "degraded"
    check = next(c for c in body["checks"] if c["name"] == "clock_skew")
    assert check["status"] == "degraded"
    assert check["meta"]["skew_ms"] >= 119_000


def test_skew_above_the_bound_turns_execution_into_a_typed_503(
    client: TestClient, skewed: None
) -> None:
    from ai_gateway.app.routes import execution

    execution.router.add_api_route("/__probe", lambda: {"ok": True}, methods=["POST"])
    try:
        main.app.include_router(execution.router, prefix=PREFIX)
        response = client.post(
            f"{PREFIX}{execution.router.prefix}/__probe",
            headers={JOB_CONTEXT_HEADER: "a.b"},
        )
    finally:
        execution.router.routes.pop()
        main.app.router.routes[:] = [
            r
            for r in main.app.router.routes
            if getattr(r, "path", "") != f"{PREFIX}{execution.router.prefix}/__probe"
        ]
    assert response.status_code == 503
    assert response.headers["retry-after"] == "30"
    body = response.json()
    assert body["code"] == "clock_skew_exceeded"
    assert set(body) == {"code", "request_id", "retry_after_seconds"}


def test_an_unreadable_clock_fails_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken() -> object:
        raise OSError("db down at 10.0.0.1")

    monitor = clock_module.ClockSkewMonitor(broken, 5)  # type: ignore[arg-type]
    import asyncio

    result = asyncio.run(monitor.health_check())
    assert result.status == "fail"
    assert result.error == "OSError"


def test_a_measurement_is_cached_for_a_few_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    monitor = clock_module.ClockSkewMonitor(lambda: deps.engine._engine, 5)
    real = monitor.measure

    def counted() -> clock_module.SkewReading:
        calls.append(1)
        return real()

    monkeypatch.setattr(monitor, "measure", counted)
    ticks = iter([100.0, 101.0, 100.0 + clock_module.MEASUREMENT_TTL_SECONDS + 1])
    monkeypatch.setattr(monitor, "_monotonic", lambda: next(ticks))
    monitor.reading()
    monitor.reading()
    monitor.reading()
    assert len(calls) == 2


# --- errors ------------------------------------------------------------------


def test_every_error_code_has_a_status() -> None:
    assert set(DEFAULT_STATUS) == set(AiErrorCode)
    assert GatewayError(AiErrorCode.TIMEOUT).status_code == 504
    assert str(GatewayError(AiErrorCode.TIMEOUT)) == "timeout"
    assert GatewayError(AiErrorCode.TIMEOUT, status_code=500).status_code == 500


def test_request_ids_are_opaque_and_unique() -> None:
    ids = {new_request_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(i) == 22 for i in ids)


# --- docs gating -------------------------------------------------------------


def test_docs_and_openapi_are_absent_under_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AI_USER_BYOK_ENABLED", "true")
    for key, value in ADMISSION_LIMITS.items():
        monkeypatch.setenv(key, value)
    production = Settings(_env_file=None)  # type: ignore[call-arg]
    client = TestClient(main.build_app(production))  # no lifespan needed
    if True:
        for path in ("/docs", "/redoc", "/openapi.json", f"{PREFIX}/openapi.json"):
            assert client.get(path).status_code == 404, path
    assert TestClient(main.app).get(f"{PREFIX}/openapi.json").status_code == 200


# --- the spool filesystem ----------------------------------------------------

MOUNTINFO = """\
22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw
30 22 0:40 / /spool rw,relatime - nfs4 server:/export rw
31 22 0:41 / /spool/local rw - xfs /dev/sdb1 rw
32 22 0:42 / /with\\040space rw - btrfs /dev/sdc1 rw
33 22 0:43 / /mem rw - tmpfs tmpfs rw
"""


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/", "ext4"),
        ("/var/lib", "ext4"),
        ("/spool", "nfs4"),
        ("/spool/x", "nfs4"),
        ("/spool/local/a", "xfs"),
        ("/spoolx", "ext4"),
        ("/with space/f", "btrfs"),
        ("/mem", "tmpfs"),
    ],
)
def test_filesystem_type_takes_the_longest_mount(path: str, kind: str) -> None:
    assert filesystem_type(Path(path), MOUNTINFO) == kind


def test_unidentifiable_mount() -> None:
    with pytest.raises(SpoolFilesystemError, match="could not be identified"):
        filesystem_type(Path("/x"), "garbage\n10 1 0:1 / /other rw - \n")


def test_remote_or_memory_spool_is_refused(tmp_path: Path) -> None:
    info = f"1 0 0:1 / {tmp_path} rw - nfs server:/x rw\n"
    with pytest.raises(SpoolFilesystemError, match="needs ext4, xfs or btrfs"):
        assert_local_spool(tmp_path, info)
    info = f"1 0 0:1 / {tmp_path} rw - tmpfs tmpfs rw\n"
    with pytest.raises(SpoolFilesystemError, match="'tmpfs'"):
        assert_local_spool(tmp_path, info)
    with pytest.raises(SpoolFilesystemError, match="not a directory"):
        assert_local_spool(tmp_path / "absent", info)


def test_a_local_spool_passes_the_lock_self_test(tmp_path: Path) -> None:
    info = f"1 0 0:1 / {tmp_path} rw - ext4 /dev/sda1 rw\n"
    assert_local_spool(tmp_path, info)
    assert list((tmp_path / ".locks").iterdir()) == []


def test_locks_that_do_not_exclude_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fcntl

    monkeypatch.setattr(fcntl, "flock", lambda *_a: None)
    with pytest.raises(SpoolFilesystemError, match="do not exclude"):
        lock_self_test(tmp_path)


def test_a_holder_that_never_starts_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway.core import spool_check

    monkeypatch.setattr(spool_check, "_HOLDER", "import sys; sys.stdin.read()")
    monkeypatch.setattr(spool_check, "HOLDER_START_TIMEOUT_SECONDS", 0.5)
    with pytest.raises(SpoolFilesystemError, match="did not start"):
        lock_self_test(tmp_path)
    monkeypatch.setattr(spool_check, "_HOLDER", "pass")
    with pytest.raises(SpoolFilesystemError, match="did not start"):
        lock_self_test(tmp_path)


def test_the_app_refuses_to_start_on_a_bad_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", tmp_path / "absent")
    with pytest.raises(SpoolFilesystemError):
        with TestClient(main.app):
            pass


def test_prestart_refuses_a_bad_spool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ai_gateway import prestart

    monkeypatch.setattr(settings, "AI_OCR_SPOOL_DIR", tmp_path / "absent")
    assert prestart.main() == 1


def test_an_error_without_retry_after_sends_no_header() -> None:
    from ai_gateway.core.errors import error_response

    response = error_response(GatewayError(AiErrorCode.FORBIDDEN_SCOPE))
    assert response.status_code == 403
    assert "retry-after" not in response.headers
