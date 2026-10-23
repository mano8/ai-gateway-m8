"""T16: the packaged migration, the role split and every database invariant."""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import factories as f
import pg_harness as pg
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Connection, Engine, delete, insert, null, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

import ai_gateway.credentials  # noqa: F401 - registers the version table
from ai_gateway.core import deps
from ai_gateway.core.config import settings
from ai_gateway.db_models import metadata
from ai_gateway.db_models.accounting import ai_execution, ai_spool_capacity
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.audit import ai_admin_audit, ai_credential_audit
from ai_gateway.db_models.credential_version import ai_credential_version
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.installation import ai_installation
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_revision,
    ai_provider,
)
from ai_gateway.installation import InstallationError, init_installation, main

pytestmark = pytest.mark.usefixtures("clean_db")

Refused = (IntegrityError, ProgrammingError, DBAPIError)


@pytest.fixture
def runtime() -> Engine:
    return deps.engine._engine


@pytest.fixture
def owner() -> Iterator[Engine]:
    engine = pg.owner_engine()
    yield engine
    engine.dispose()


def refused(
    engine: Engine, action: Callable[[Connection], Any], match: str = ""
) -> None:
    """``action`` must fail inside one transaction (at the statement or commit)."""
    with pytest.raises(Refused) as info:
        with engine.begin() as connection:
            action(connection)
    assert re.search(match, str(info.value)), str(info.value)


@pytest.fixture
def world(runtime: Engine) -> dict[str, uuid.UUID]:
    with runtime.begin() as c:
        return f.resolved_world(c)


# --- migration and metadata --------------------------------------------------


def test_the_migration_matches_the_metadata(owner: Engine) -> None:
    with owner.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "include_object": lambda _o, name, kind, *_a: (
                    not (kind == "table" and name == "alembic_version_ai")
                ),
            },
        )
        diff = compare_metadata(context, metadata)
    assert diff == []


def test_the_image_ships_the_versions_directory() -> None:
    from ai_gateway.prestart import ALEMBIC_INI

    versions = ALEMBIC_INI.parent / "alembic" / "versions"
    assert (versions / "0001_initial_schema.py").is_file()
    ignored = (ALEMBIC_INI.parents[1] / ".dockerignore").read_text(encoding="utf-8")
    assert "alembic" not in ignored
    dockerfile = (ALEMBIC_INI.parent / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY --chown=appuser:appuser ./ai_gateway ./ai_gateway" in dockerfile


def test_upgrade_downgrade_upgrade_on_a_fresh_database() -> None:
    admin = pg.admin_engine()
    name = "ai_gateway_test_migration"
    try:
        with admin.connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {name}"))
            c.execute(text(f"CREATE DATABASE {name} OWNER {pg.OWNER}"))
        on_db = pg.admin_engine(name)
        with on_db.connect() as c:
            c.execute(text(f"ALTER SCHEMA public OWNER TO {pg.OWNER}"))
        on_db.dispose()
        config = pg.alembic_config(pg.owner_url().set(database=name))
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        command.upgrade(config, "head")
    finally:
        with admin.connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        admin.dispose()


# --- the role split (D-04) ---------------------------------------------------


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE TABLE ai_intruder (id int)",
        "ALTER TABLE ai_provider ADD COLUMN x int",
        "DROP TRIGGER ai_provider_freeze ON ai_provider",
        "TRUNCATE ai_execution",
    ],
)
def test_the_runtime_role_cannot_run_ddl(runtime: Engine, ddl: str) -> None:
    refused(runtime, lambda c: c.execute(text(ddl)), "permission denied|must be owner")


@pytest.mark.parametrize("table", [ai_admin_audit, ai_credential_audit])
def test_the_runtime_role_cannot_rewrite_the_audit_trail(
    runtime: Engine, table: Any
) -> None:
    extra = {"target_type": "provider"} if table is ai_admin_audit else {}
    with runtime.begin() as c:
        c.execute(insert(table).values(action="x", actor_kind="system", **extra))
        assert c.execute(select(table.c.action)).scalars().all() == ["x"]
    refused(
        runtime,
        lambda c: c.execute(update(table).values(action="y")),
        "permission denied",
    )
    refused(runtime, lambda c: c.execute(delete(table)), "permission denied")


def test_audit_rows_are_immutable_even_for_the_owner(owner: Engine) -> None:
    with owner.begin() as c:
        c.execute(
            insert(ai_admin_audit).values(
                action="x", actor_kind="system", target_type="t"
            )
        )
    refused(
        owner,
        lambda c: c.execute(update(ai_admin_audit).values(action="y")),
        "immutable",
    )
    with owner.begin() as c:  # audit-prune (owner) may delete
        c.execute(delete(ai_admin_audit))


@pytest.mark.parametrize("table", [ai_admin_audit, ai_credential_audit])
def test_audit_metadata_is_capped_at_4_kib(runtime: Engine, table: Any) -> None:
    extra = {"target_type": "provider"} if table is ai_admin_audit else {}
    with runtime.begin() as c:
        c.execute(
            insert(table).values(
                action="ok", actor_kind="user", metadata={"k": "v" * 4000}, **extra
            )
        )
    refused(
        runtime,
        lambda c: c.execute(
            insert(table).values(
                action="x", actor_kind="user", metadata={"k": "v" * 4100}, **extra
            )
        ),
        "metadata_size",
    )


def test_the_runtime_role_cannot_run_alembic() -> None:
    """No DDL and no write to the version table: downgrade and stamp both fail."""
    config = pg.alembic_config(pg.runtime_url())
    with pytest.raises(Refused, match="permission denied|must be owner"):
        command.downgrade(config, "base")
    with pytest.raises(Refused, match="permission denied"):
        command.stamp(config, "base")
    with pg.owner_engine().connect() as c:
        assert (
            c.execute(text("SELECT version_num FROM alembic_version_ai")).scalar_one()
            == "0001_initial"
        )


def test_the_runtime_role_only_reads_the_installation(runtime: Engine) -> None:
    with runtime.connect() as c:
        assert (
            c.execute(select(ai_installation.c.deployment_id)).scalar_one()
            == settings.AI_DEPLOYMENT_ID
        )
    refused(
        runtime,
        lambda c: c.execute(update(ai_installation).values(cloned_from=uuid.uuid4())),
        "permission denied",
    )


def test_a_second_installation_row_is_refused(owner: Engine) -> None:
    refused(
        owner,
        lambda c: c.execute(
            insert(ai_installation).values(id=2, deployment_id=uuid.uuid4())
        ),
        "single_row",
    )
    refused(
        owner,
        lambda c: c.execute(
            insert(ai_installation).values(id=1, deployment_id=uuid.uuid4())
        ),
        "pkey",
    )


# --- the installation identity -----------------------------------------------


def test_installation_init_records_once_and_verifies(owner: Engine) -> None:
    with owner.begin() as c:
        assert init_installation(c, settings.AI_DEPLOYMENT_ID, 123) is False
        assert c.execute(select(ai_spool_capacity.c.max_bytes)).scalar_one() == 123
        with pytest.raises(InstallationError, match="never rotated"):
            init_installation(c, uuid.uuid4(), 123)
    with owner.begin() as c:
        init_installation(c, settings.AI_DEPLOYMENT_ID, settings.AI_OCR_SPOOL_MAX_BYTES)


def test_installation_init_creates_the_row(owner: Engine) -> None:
    with owner.begin() as c:
        c.execute(delete(ai_installation))
        assert init_installation(c, settings.AI_DEPLOYMENT_ID, 1) is True
        c.rollback()


def test_installation_command(monkeypatch: pytest.MonkeyPatch) -> None:
    assert main(["bogus"]) == 2
    owner = pg.owner_engine()
    monkeypatch.setattr(deps.engine, "_engine", owner)
    try:
        assert main(["init"]) == 0
        monkeypatch.setattr(settings, "AI_DEPLOYMENT_ID", uuid.uuid4())
        assert main(["init"]) == 1
    finally:
        owner.dispose()


# --- providers and models freeze at first use --------------------------------


def _first_use(c: Connection, table: Any, row_id: uuid.UUID) -> None:
    c.execute(
        update(table)
        .where(table.c.id == row_id)
        .values(first_used_at=datetime.now(UTC))
    )


@pytest.mark.parametrize(
    "change",
    [
        {"base_url": "https://evil.example.com"},
        {"provider_type": "mistral"},
        {"auth_type": "none"},
        {"auth_type": "api_key_header", "auth_header_name": "x-api-key"},
        {"first_used_at": None},
    ],
)
def test_a_used_providers_endpoint_is_frozen(
    runtime: Engine, change: dict[str, Any]
) -> None:
    with runtime.begin() as c:
        provider_id = f.provider(c)
        c.execute(
            update(ai_provider)
            .where(ai_provider.c.id == provider_id)
            .values(base_url="https://new.example.com")
        )
        _first_use(c, ai_provider, provider_id)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider).where(ai_provider.c.id == provider_id).values(**change)
        ),
        "frozen",
    )
    with runtime.begin() as c:  # the emergency stop still works
        c.execute(
            update(ai_provider)
            .where(ai_provider.c.id == provider_id)
            .values(enabled=False)
        )


def test_a_header_change_on_a_used_provider_is_refused(runtime: Engine) -> None:
    with runtime.begin() as c:
        provider_id = f.provider(
            c, auth_type="api_key_header", auth_header_name="x-api-key"
        )
        _first_use(c, ai_provider, provider_id)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider)
            .where(ai_provider.c.id == provider_id)
            .values(auth_header_name="x-other")
        ),
        "frozen",
    )


@pytest.mark.parametrize("used", [False, True])
def test_a_boundary_change_is_always_refused(runtime: Engine, used: bool) -> None:
    with runtime.begin() as c:
        provider_id = f.provider(c)
        if used:
            _first_use(c, ai_provider, provider_id)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider)
            .where(ai_provider.c.id == provider_id)
            .values(boundary="local")
        ),
        "boundary is immutable",
    )


def test_providers_and_models_are_never_deleted(runtime: Engine) -> None:
    with runtime.begin() as c:
        provider_id = f.provider(c)
        model_id = f.model(c, provider_id)
    refused(
        runtime, lambda c: c.execute(delete(ai_model).where(ai_model.c.id == model_id))
    )
    refused(
        runtime,
        lambda c: c.execute(delete(ai_provider).where(ai_provider.c.id == provider_id)),
    )


@pytest.mark.parametrize(
    "change",
    [
        {"external_model_id": "other"},
        {"dimensions": 1024},
        {"model_revision": "sha256:abc"},
        {"model_version_label": "v2"},
        {"execution_identity": "f" * 32},
        {"capabilities": ["embedding", "rerank"]},
        {"first_used_at": None},
    ],
)
def test_a_used_models_identity_is_frozen(
    runtime: Engine, change: dict[str, Any]
) -> None:
    with runtime.begin() as c:
        provider_id = f.provider(c)
        model_id = f.model(
            c, provider_id, capabilities=["embedding", "structured_output"]
        )
        c.execute(
            update(ai_model)
            .where(ai_model.c.id == model_id)
            .values(model_version_label="v1.1")
        )
        _first_use(c, ai_model, model_id)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_model).where(ai_model.c.id == model_id).values(**change)
        ),
    )
    with runtime.begin() as c:  # shrinking and disabling stay possible
        c.execute(
            update(ai_model)
            .where(ai_model.c.id == model_id)
            .values(capabilities=["embedding"], enabled=False)
        )


def test_a_models_provider_never_changes(runtime: Engine) -> None:
    with runtime.begin() as c:
        model_id = f.model(c, f.provider(c))
        other = f.provider(c)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_model).where(ai_model.c.id == model_id).values(provider_id=other)
        ),
        "immutable",
    )


@pytest.mark.parametrize(
    "values",
    [
        {"capabilities": []},
        {"capabilities": ["chat"]},
        {"capabilities": ["embedding"], "dimensions": None},
        {"execution_identity": "short"},
        {"metadata": {"k": "v" * 5000}},
    ],
)
def test_model_row_checks(runtime: Engine, values: dict[str, Any]) -> None:
    refused(runtime, lambda c: f.model(c, f.provider(c), **values))


def test_provider_row_checks(runtime: Engine) -> None:
    refused(
        runtime,
        lambda c: f.provider(c, auth_type="api_key_header"),
        "header_matches_auth",
    )
    refused(runtime, lambda c: f.provider(c, boundary="mars"), "boundary")
    refused(
        runtime,
        lambda c: f.provider(c, base_url="https://" + "a" * 2050),
        "base_url_length",
    )


# --- profiles and revisions ----------------------------------------------------


def test_profile_revisions_are_immutable(runtime: Engine, owner: Engine) -> None:
    with runtime.begin() as c:
        profile_id = f.profile(c)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_profile_revision).values(execution_config={"x": 1})
        ),
        "permission denied",
    )
    refused(
        runtime, lambda c: c.execute(delete(ai_profile_revision)), "permission denied"
    )
    refused(
        owner,
        lambda c: c.execute(
            update(ai_profile_revision).values(execution_config={"x": 1})
        ),
        "immutable",
    )
    refused(owner, lambda c: c.execute(delete(ai_profile_revision)), "immutable")
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_profile)
            .where(ai_profile.c.id == profile_id)
            .values(capability="ocr")
        ),
        "immutable",
    )


def test_a_profile_must_point_at_an_existing_revision(runtime: Engine) -> None:
    refused(
        runtime,
        lambda c: c.execute(
            insert(ai_profile).values(
                id=uuid.uuid4(),
                profile_key="dangling",
                capability="rerank",
                current_revision=1,
            )
        ),
        "fk_ai_profile_current_revision",
    )
    with runtime.begin() as c:
        profile_id = f.profile(c)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_profile)
            .where(ai_profile.c.id == profile_id)
            .values(current_revision=2)
        ),
        "fk_ai_profile_current_revision",
    )


def test_an_executions_profile_revision_must_exist(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    refused(
        runtime,
        lambda c: f.execution(c, world, resolved_profile_revision=9),
        "fk_ai_execution_profile_revision",
    )


# --- bindings ------------------------------------------------------------------


def test_one_binding_per_scope_with_nulls_not_distinct(runtime: Engine) -> None:
    with runtime.begin() as c:
        model_id = f.model(c, f.provider(c))
        profile_id = f.profile(c)
        f.binding(c, profile_id, model_id)
    refused(
        runtime,
        lambda c: f.binding(c, profile_id, model_id),
        "uq_ai_profile_binding_scope",
    )
    tenant = uuid.uuid4()
    with runtime.begin() as c:
        f.binding(c, profile_id, model_id, scope_type="tenant", tenant_id=tenant)
    refused(
        runtime,
        lambda c: f.binding(
            c, profile_id, model_id, scope_type="tenant", tenant_id=tenant
        ),
        "uq_",
    )


def test_a_bindings_scope_is_immutable(runtime: Engine) -> None:
    from ai_gateway.db_models.registry import ai_profile_binding

    with runtime.begin() as c:
        binding_id = f.binding(
            c,
            f.profile(c),
            f.model(c, f.provider(c)),
            scope_type="tenant",
            tenant_id=uuid.uuid4(),
        )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_profile_binding)
            .where(ai_profile_binding.c.id == binding_id)
            .values(tenant_id=uuid.uuid4())
        ),
        "immutable",
    )
    refused(
        runtime,
        lambda c: f.binding(
            c, f.profile(c), f.model(c, f.provider(c)), scope_type="tenant"
        ),
        "scope_shape",
    )


# --- credentials and versions ----------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"scope_type": "global", "tenant_id": None},
        {"tenant_id": uuid.uuid4()},
        {"owner_user_id": uuid.uuid4(), "scope_type": "user"},
        {"secret_backend": "vault"},
    ],
)
def test_credential_ownership_is_immutable(
    runtime: Engine, change: dict[str, Any]
) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(**change)
        ),
        "immutable",
    )


def test_a_credentials_provider_is_immutable(runtime: Engine) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
        other = f.provider(c)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(provider_id=other)
        ),
        "immutable",
    )


def test_the_pointer_must_name_an_existing_version(runtime: Engine) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(current_version=7, next_version=8)
        ),
        "fk_ai_credential_current_version",
    )


def test_an_active_pointer_needs_committed_live_material(runtime: Engine) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=3)
        )
        f.version(c, credential_id, 2, committed=False)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(current_version=2)
        ),
        "committed, live material",
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 1,
            )
            .values(material_lost_at=datetime.now(UTC))
        ),
        "committed, live material",
    )
    with (
        runtime.begin() as c
    ):  # a lost current version with the credential moved off active is fine
        c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 1,
            )
            .values(material_lost_at=datetime.now(UTC))
        )
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(status="reprovision_required")
        )


def test_version_numbers_come_from_next_version_and_never_move_back(
    runtime: Engine, owner: Engine
) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
    refused(
        runtime, lambda c: f.version(c, credential_id, 2), "allocated from next_version"
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=1, current_version=None, status="disabled")
        ),
    )
    refused(
        runtime,
        lambda c: c.execute(
            delete(ai_credential_version).where(
                ai_credential_version.c.credential_id == credential_id
            )
        ),
        "permission denied",
    )
    refused(
        runtime,
        lambda c: c.execute(
            delete(ai_credential).where(ai_credential.c.id == credential_id)
        ),
        "permission denied",
    )
    refused(
        owner,
        lambda c: c.execute(
            delete(ai_credential_version).where(
                ai_credential_version.c.credential_id == credential_id
            )
        ),
        "never deleted",
    )
    refused(
        owner,
        lambda c: c.execute(
            delete(ai_credential).where(ai_credential.c.id == credential_id)
        ),
        "never deleted",
    )


def test_aborted_and_lifecycle_stamps_are_set_once(runtime: Engine) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=3)
        )
        f.version(c, credential_id, 2, committed=False)
        c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 2,
            )
            .values(aborted_at=datetime.now(UTC))
        )
    where = (
        ai_credential_version.c.credential_id == credential_id,
        ai_credential_version.c.version == 2,
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version).where(*where).values(aborted_at=None)
        ),
        "set once",
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version)
            .where(*where)
            .values(material_committed_at=datetime.now(UTC))
        ),
        "aborted_uncommitted",
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version).where(*where).values(prepare_id="0" * 32)
        ),
        "immutable",
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version).where(*where).values(ciphertext=b"other")
        ),
        "never rewritten",
    )


def _rotate(
    runtime: Engine,
    credential_id: uuid.UUID,
    barrier: threading.Barrier,
    out: list[int],
) -> None:
    with runtime.begin() as c:
        barrier.wait()
        row = c.execute(
            select(ai_credential.c.next_version)
            .where(ai_credential.c.id == credential_id)
            .with_for_update()
        ).one()
        number = row.next_version
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=number + 1)
        )
        f.version(c, credential_id, number)
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(current_version=number)
        )
        out.append(number)


def test_two_concurrent_rotations_serialize_into_consecutive_versions(
    runtime: Engine,
) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
    barrier = threading.Barrier(2)
    numbers: list[int] = []
    threads = [
        threading.Thread(
            target=_rotate, args=(runtime, credential_id, barrier, numbers)
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(numbers) == [2, 3]
    with runtime.connect() as c:
        current, following = c.execute(
            select(ai_credential.c.current_version, ai_credential.c.next_version).where(
                ai_credential.c.id == credential_id
            )
        ).one()
    assert current == numbers[-1]
    assert following == 4


def _destroy(c: Connection, credential_id: uuid.UUID, number: int) -> None:
    c.execute(
        update(ai_credential_version)
        .where(
            ai_credential_version.c.credential_id == credential_id,
            ai_credential_version.c.version == number,
        )
        .values(
            ciphertext=None,
            nonce=None,
            wrapped_dek=None,
            wrap_nonce=None,
            algorithm=None,
            kek_provider=None,
            kek_key_version=None,
            fingerprint=None,
            fingerprint_key_version=None,
            material_destroyed_at=datetime.now(UTC),
        )
    )


def test_destroying_a_version_keeps_the_row_and_clears_the_material(
    runtime: Engine,
) -> None:
    with runtime.begin() as c:
        credential_id = f.credential(c, f.provider(c))
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=3)
        )
        f.version(c, credential_id, 2)
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(current_version=2)
        )
    with runtime.begin() as c:
        _destroy(c, credential_id, 1)
        row = c.execute(
            select(ai_credential_version).where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 1,
            )
        ).one()
    assert (
        row.ciphertext is None
        and row.fingerprint is None
        and row.material_destroyed_at is not None
    )
    refused(
        runtime,
        lambda c: _destroy(c, credential_id, 2),
        "current version of a live credential",
    )
    with runtime.begin() as c:
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=4)
        )
        f.version(c, credential_id, 3)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 3,
            )
            .values(material_destroyed_at=datetime.now(UTC))
        ),
        "destroyed_has_no_material",
    )


def test_material_survives_while_an_artifact_or_sweep_obligation_needs_it(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    credential_id = world["credential_id"]
    with runtime.begin() as c:
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(next_version=3)
        )
        f.version(c, credential_id, 2)
        c.execute(
            update(ai_credential)
            .where(ai_credential.c.id == credential_id)
            .values(current_version=2)
        )
        execution_id = f.execution(c, world)
        f.artifact(c, world, execution_id)
    refused(
        runtime, lambda c: _destroy(c, credential_id, 1), "remote artifact references"
    )
    refused(
        runtime,
        lambda c: c.execute(
            delete(ai_credential_version).where(ai_credential_version.c.version == 1)
        ),
        "permission denied",
    )
    with runtime.begin() as c:
        c.execute(
            update(ai_provider_remote_artifact).values(status="uploading_unknown_id")
        )
        c.execute(delete(ai_provider_remote_artifact))
        c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 1,
            )
            .values(sweep_discharge_at=datetime.now(UTC) + timedelta(hours=1))
        )
    refused(runtime, lambda c: _destroy(c, credential_id, 1), "sweep obligation")
    with runtime.begin() as c:
        c.execute(
            update(ai_credential_version)
            .where(
                ai_credential_version.c.credential_id == credential_id,
                ai_credential_version.c.version == 1,
            )
            .values(reconciled_through=datetime.now(UTC) + timedelta(hours=2))
        )
        _destroy(c, credential_id, 1)


# --- the execution transition table (D-24) -------------------------------------

LEGAL = [
    ("receiving", "spooled"),
    ("receiving", "abandoned"),
    ("spooled", "pending"),
    ("spooled", "abandoned"),
    ("pending", "dispatching"),
    ("pending", "released"),
    ("pending", "abandoned"),
    ("dispatching", "ok"),
    ("dispatching", "failed"),
    ("dispatching", "charged_uncertain"),
    ("dispatching", "released"),
]
STATUSES = [
    "receiving",
    "spooled",
    "pending",
    "dispatching",
    "ok",
    "failed",
    "charged_uncertain",
    "released",
    "abandoned",
]


def _drive(c: Connection, world: dict[str, uuid.UUID], target: str) -> uuid.UUID:
    """An execution moved legally to ``target``."""
    now = datetime.now(UTC)
    ocr = target in ("receiving", "spooled")
    execution_id = f.execution(c, world, ocr=ocr)
    if target == "spooled":
        f.set_status(
            c,
            execution_id,
            "spooled",
            spool_file_created=True,
            spool_expires_at=now + timedelta(minutes=5),
            ocr_options={"pages": None},
        )
    if target in ("dispatching", "ok", "failed", "charged_uncertain"):
        f.set_status(
            c,
            execution_id,
            "dispatching",
            dispatched_at=now,
            dispatch_deadline_at=now + timedelta(minutes=2),
        )
    if target in ("ok", "failed", "charged_uncertain", "released", "abandoned"):
        f.set_status(c, execution_id, target, occupancy_released_at=now)
    return execution_id


def _values_for(target: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    if target in ("ok", "failed", "charged_uncertain", "released", "abandoned"):
        return {"occupancy_released_at": now}
    if target == "spooled":
        return {
            "spool_file_created": True,
            "spool_expires_at": now + timedelta(minutes=5),
            "ocr_options": {"pages": None},
        }
    if target == "dispatching":
        return {
            "dispatched_at": now,
            "dispatch_deadline_at": now + timedelta(minutes=2),
        }
    return {}


@pytest.mark.parametrize(
    ("source", "target"),
    [(s, t) for s in STATUSES for t in STATUSES if s != t and (s, t) not in LEGAL],
)
def test_every_transition_outside_the_table_is_refused(
    runtime: Engine, world: dict[str, uuid.UUID], source: str, target: str
) -> None:
    with runtime.begin() as c:
        execution_id = _drive(c, world, source)
    values = _values_for(target)
    if source == "spooled" and target in (
        "dispatching",
        "ok",
        "failed",
        "charged_uncertain",
    ):
        values |= f.reservation(world, datetime.now(UTC))
    if target in ("pending",) and source in ("receiving",):
        values |= f.reservation(world, datetime.now(UTC))
    refused(runtime, lambda c: f.set_status(c, execution_id, target, **values))


@pytest.mark.parametrize(("source", "target"), LEGAL)
def test_every_transition_in_the_table_is_allowed(
    runtime: Engine, world: dict[str, uuid.UUID], source: str, target: str
) -> None:
    with runtime.begin() as c:
        execution_id = _drive(c, world, source)
        values = _values_for(target)
        if (source, target) == ("spooled", "pending"):
            values |= f.reservation(world, datetime.now(UTC))
        assert f.set_status(c, execution_id, target, **values) == 1


def test_a_refund_after_the_first_byte_is_refused(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    with runtime.begin() as c:
        execution_id = _drive(c, world, "dispatching")
        c.execute(
            update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(first_byte_sent_at=datetime.now(UTC))
        )
    refused(
        runtime,
        lambda c: f.set_status(
            c, execution_id, "released", occupancy_released_at=datetime.now(UTC)
        ),
        "D-24",
    )
    with runtime.begin() as c:
        f.set_status(
            c,
            execution_id,
            "charged_uncertain",
            occupancy_released_at=datetime.now(UTC),
        )


def test_an_execution_starts_in_its_first_status(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    refused(
        runtime,
        lambda c: f.execution(c, world, status="dispatching"),
        "starts receiving",
    )
    refused(runtime, lambda c: f.execution(c, world, ocr=True, status="pending"))


@pytest.mark.parametrize(
    "change",
    [
        {"client_scope_id": "other"},
        {"jti": "other"},
        {"reserved_units": 99},
        {"resolved_credential_version": 2},
        {"resolved_provider_id": None},
    ],
)
def test_a_recorded_reservation_never_changes(
    runtime: Engine, world: dict[str, uuid.UUID], change: dict[str, Any]
) -> None:
    with runtime.begin() as c:
        execution_id = f.execution(c, world)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(**change)
        ),
    )


def test_a_settled_row_settles_exactly_once(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    """The handler and the sweeper both CAS on the stored status: one wins."""
    now = datetime.now(UTC)
    with runtime.begin() as c:
        execution_id = _drive(c, world, "dispatching")
    rows = []
    for _ in range(2):
        with runtime.begin() as c:
            rows.append(
                c.execute(
                    update(ai_execution)
                    .where(
                        ai_execution.c.id == execution_id,
                        ai_execution.c.status == "dispatching",
                    )
                    .values(status="charged_uncertain", occupancy_released_at=now)
                ).rowcount
            )
    assert rows == [1, 0]


def test_the_full_ocr_lifecycle(runtime: Engine, world: dict[str, uuid.UUID]) -> None:
    now = datetime.now(UTC)
    with runtime.begin() as c:
        execution_id = f.execution(c, world, ocr=True)
        c.execute(
            update(ai_spool_capacity).values(
                reserved_bytes=ai_spool_capacity.c.reserved_bytes + 4096
            )
        )
        c.execute(
            update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(spool_file_created=True)
        )
        f.set_status(
            c,
            execution_id,
            "spooled",
            spool_expires_at=now + timedelta(minutes=5),
            ocr_options={"pages": None},
        )
        f.set_status(c, execution_id, "pending", **f.reservation(world, now))
        f.set_status(
            c,
            execution_id,
            "dispatching",
            dispatched_at=now,
            dispatch_deadline_at=now + timedelta(minutes=2),
        )
        f.set_status(
            c, execution_id, "ok", occupancy_released_at=now, cleanup_pending=True
        )
        c.execute(
            update(ai_execution)
            .where(
                ai_execution.c.id == execution_id,
                ai_execution.c.cleanup_pending.is_(True),
            )
            .values(cleanup_pending=False, spool_bytes_reserved=None)
        )
        c.execute(
            update(ai_spool_capacity).values(
                reserved_bytes=ai_spool_capacity.c.reserved_bytes - 4096
            )
        )
        assert c.execute(select(ai_spool_capacity.c.reserved_bytes)).scalar_one() == 0


@pytest.mark.parametrize(
    "values",
    [
        {"status": "receiving", "spool_bytes_reserved": None},
        {"input_sha256": None},
    ],
)
def test_ocr_rows_carry_their_spool_binding(
    runtime: Engine, world: dict[str, uuid.UUID], values: dict[str, Any]
) -> None:
    refused(runtime, lambda c: f.execution(c, world, ocr=True, **values))


def test_non_ocr_rows_carry_no_spool(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    refused(
        runtime, lambda c: f.execution(c, world, cleanup_pending=True), "spool_is_ocr"
    )
    refused(
        runtime, lambda c: f.execution(c, world, input_sha256="b" * 64), "ocr_inputs"
    )


# --- the remote-artifact transition table (D-43) --------------------------------

ARTIFACT_LEGAL = [
    ("uploading", "active"),
    ("uploading", "uploading_unknown_id"),
    ("uploading_unknown_id", "pending_delete"),
    ("uploading_unknown_id", "manual_cleanup_required"),
    ("active", "pending_delete"),
    ("pending_delete", "manual_cleanup_required"),
    ("manual_cleanup_required", "pending_delete"),
]
ARTIFACT_STATUSES = [
    "uploading",
    "uploading_unknown_id",
    "active",
    "pending_delete",
    "manual_cleanup_required",
]
_PATHS = {
    "uploading": [],
    "uploading_unknown_id": ["uploading_unknown_id"],
    "active": ["active"],
    "pending_delete": ["active", "pending_delete"],
    "manual_cleanup_required": ["uploading_unknown_id", "manual_cleanup_required"],
}


def _artifact_at(c: Connection, world: dict[str, uuid.UUID], status: str) -> uuid.UUID:
    artifact_id = f.artifact(c, world, f.execution(c, world))
    for step in _PATHS[status]:
        values: dict[str, Any] = {"status": step}
        if step in ("active", "pending_delete"):
            values["remote_artifact_id"] = "file-1"
        if step == "manual_cleanup_required":
            values["status_reason"] = "absence_unproven"
        c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(**values)
        )
    return artifact_id


def _artifact_values(target: str) -> dict[str, Any]:
    values: dict[str, Any] = {"status": target, "remote_artifact_id": "file-1"}
    values["status_reason"] = (
        "absence_unproven" if target == "manual_cleanup_required" else None
    )
    return values


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (s, t)
        for s in ARTIFACT_STATUSES
        for t in ARTIFACT_STATUSES
        if s != t and (s, t) not in ARTIFACT_LEGAL
    ],
)
def test_artifact_transitions_outside_the_table_are_refused(
    runtime: Engine, world: dict[str, uuid.UUID], source: str, target: str
) -> None:
    with runtime.begin() as c:
        artifact_id = _artifact_at(c, world, source)
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(**_artifact_values(target))
        ),
    )


@pytest.mark.parametrize(("source", "target"), ARTIFACT_LEGAL)
def test_artifact_transitions_in_the_table_are_allowed(
    runtime: Engine, world: dict[str, uuid.UUID], source: str, target: str
) -> None:
    with runtime.begin() as c:
        artifact_id = _artifact_at(c, world, source)
        c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(**_artifact_values(target))
        )


def test_late_discovery_only_for_unproven_absence(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    with runtime.begin() as c:
        artifact_id = _artifact_at(c, world, "pending_delete")
        c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(
                status="manual_cleanup_required", status_reason="attempts_exhausted"
            )
        )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(status="pending_delete", status_reason=None)
        ),
        "D-43",
    )


def test_an_artifact_reaches_active_only_with_its_id(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    with runtime.begin() as c:
        artifact_id = _artifact_at(c, world, "uploading")
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(status="active")
        ),
        "has_id",
    )
    refused(
        runtime,
        lambda c: f.artifact(
            c, world, f.execution(c, world), status="active", remote_artifact_id="x"
        ),
        "starts as uploading",
    )


@pytest.mark.parametrize("status", ARTIFACT_STATUSES)
def test_an_artifact_row_closes_only_from_a_closable_state(
    runtime: Engine, world: dict[str, uuid.UUID], status: str
) -> None:
    with runtime.begin() as c:
        artifact_id = _artifact_at(c, world, status)

    def action(c):
        return c.execute(
            delete(ai_provider_remote_artifact).where(
                ai_provider_remote_artifact.c.id == artifact_id
            )
        )

    if status in ("uploading", "active"):
        refused(runtime, action, "closes only")
    else:
        with runtime.begin() as c:
            action(c)


def test_an_artifact_pins_its_execution_and_identity(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    with runtime.begin() as c:
        execution_id = f.execution(c, world)
        artifact_id = f.artifact(c, world, execution_id)
    refused(
        runtime,
        lambda c: c.execute(
            delete(ai_execution).where(ai_execution.c.id == execution_id)
        ),
        "foreign key",
    )
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_provider_remote_artifact)
            .where(ai_provider_remote_artifact.c.id == artifact_id)
            .values(credential_version=2)
        ),
        "immutable",
    )


def test_the_ocr_options_are_recorded_by_spooled_and_frozen_after(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    now = datetime.now(UTC)
    with runtime.begin() as c:
        execution_id = _drive(c, world, "receiving")
        # While receiving, the options may still be recorded.
        c.execute(
            update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(ocr_options={"pages": [0]}, expected_execution_identity="r1")
        )
    refused(
        runtime,
        lambda c: f.set_status(
            c,
            execution_id,
            "spooled",
            spool_file_created=True,
            spool_expires_at=now + timedelta(minutes=5),
            ocr_options=null(),
        ),
    )
    refused(
        runtime,
        lambda c: f.set_status(
            c,
            execution_id,
            "spooled",
            spool_file_created=True,
            spool_expires_at=now + timedelta(minutes=5),
            ocr_options=["not", "an", "object"],
        ),
    )
    with runtime.begin() as c:
        f.set_status(
            c,
            execution_id,
            "spooled",
            spool_file_created=True,
            spool_expires_at=now + timedelta(minutes=5),
        )
    for change in (
        {"ocr_options": {"pages": [1]}},
        {"expected_execution_identity": "r2"},
    ):
        refused(
            runtime,
            lambda c, change=change: c.execute(
                update(ai_execution)
                .where(ai_execution.c.id == execution_id)
                .values(**change)
            ),
        )


def test_ocr_options_belong_to_ocr_rows_only(
    runtime: Engine, world: dict[str, uuid.UUID]
) -> None:
    with runtime.begin() as c:
        execution_id = _drive(c, world, "pending")
    refused(
        runtime,
        lambda c: c.execute(
            update(ai_execution)
            .where(ai_execution.c.id == execution_id)
            .values(ocr_options={"pages": None})
        ),
    )
