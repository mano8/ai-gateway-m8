"""
Providers, models and profiles (T18): superuser-managed, every write audited.

**Providers** (D-20). ``base_url`` passes the static destination check on
every write. ``boundary`` never changes; ``base_url``, ``provider_type``,
``auth_type`` and ``auth_header_name`` freeze once the provider was first
used — its first credential or its first outbound request — and the
operator then creates a new row. ``enabled = false`` is the emergency stop.

**Models** (C-07). ``execution_identity = h(provider_id, external_model_id,
model_revision)`` is derived, never supplied. Once a reservation used the
model (``first_used_at``), ``external_model_id``, ``dimensions``,
``model_revision`` and ``model_version_label`` are frozen and
``capabilities`` may only shrink; a capability a binding relies on is never
removed.

**Profiles** (D-11). Execution-affecting configuration lives only in
immutable ``ai_profile_revision`` rows; a changed ``execution_config`` adds a
revision and moves ``current_revision``.

Each check runs under the row's ``FOR UPDATE`` lock, so an edit racing a
model's first reservation waits for it and is then refused; the schema's
triggers are the second guard.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any, Final

import sqlalchemy as sa
from ai_sdk_m8.schemas import (
    AiErrorCode,
    Capability,
    ProfilePublic,
    ProviderBoundary,
)
from ai_sdk_m8.schemas.management import (
    AuthType,
    ModelAdmin,
    ModelCreate,
    ModelUpdate,
    ProfileAdmin,
    ProfileCreate,
    ProfileRevisionAdmin,
    ProfileUpdate,
    ProviderAdmin,
    ProviderCreate,
    ProviderUpdate,
    ScopeType,
)
from pydantic import BaseModel
from sqlalchemy import Connection, RowMapping
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.core.errors import GatewayError
from ai_gateway.core.identities import (
    embedding_space_id,
    execution_config_hash,
    execution_identity,
)
from ai_gateway.core.ssrf import DestinationError, DestinationPolicy, check_static
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_profile_revision,
    ai_provider,
)

from .audit import Actor, AuditedTransaction
from .errors import Conflict, Invalid, NotFound

#: Provider fields frozen at the provider's first use.
PROVIDER_ENDPOINT: Final = frozenset(
    {"base_url", "provider_type", "auth_type", "auth_header_name"}
)
#: Model fields frozen at the model's first reservation.
MODEL_IDENTITY: Final = frozenset(
    {"external_model_id", "dimensions", "model_revision", "model_version_label"}
)
_TIMESTAMPS: Final = frozenset({"created_at", "updated_at"})

#: A database row or a merged view of one; column values are untyped.
Row = Mapping[Any, Any]


# --- shared helpers ------------------------------------------------------------


def _plain(value: object) -> object:
    """A request value as the database stores it."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _same(new: object, old: object) -> bool:
    if isinstance(new, list) and isinstance(old, list):
        return sorted(map(str, new)) == sorted(map(str, old))
    return new == old


def _fields(body: BaseModel) -> dict[str, object]:
    """Every field of a create body, defaults included."""
    return {name: _plain(getattr(body, name)) for name in type(body).model_fields}


def _changes(body: BaseModel, current: Row) -> dict[str, Any]:
    """The fields an update body sets to a value other than the current one."""
    changes: dict[str, Any] = {}
    for name in sorted(body.model_fields_set):
        value = _plain(getattr(body, name))
        if not _same(value, current[name]):
            changes[name] = value
    return changes


def _diff(current: Row, changes: Row) -> dict[str, Any]:
    return {
        name: {"before": current[name], "after": new} for name, new in changes.items()
    }


def _audited(row: Row, *exclude: str) -> dict[str, object]:
    return {k: v for k, v in row.items() if k not in _TIMESTAMPS and k not in exclude}


def _locked(connection: Connection, table: sa.Table, row_id: uuid.UUID) -> RowMapping:
    row = (
        connection.execute(
            sa.select(table).where(table.c.id == row_id).with_for_update()
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound(f"no such {table.name.removeprefix('ai_')}")
    return row


def _insert(
    connection: Connection, table: sa.Table, values: Mapping[str, object]
) -> RowMapping:
    statement = sa.insert(table).values(**values).returning(*table.c)
    return connection.execute(statement).mappings().one()


def _update(
    connection: Connection,
    table: sa.Table,
    where: sa.ColumnElement[bool],
    changes: Mapping[str, object],
) -> RowMapping:
    statement = (
        sa.update(table)
        .where(where)
        .values(**changes, updated_at=sa.func.now())
        .returning(*table.c)
    )
    return connection.execute(statement).mappings().one()


# --- providers -----------------------------------------------------------------


def _check_destination(url: str, boundary: str, policy: DestinationPolicy) -> None:
    try:
        check_static(url, ProviderBoundary(boundary), policy)
    except DestinationError as exc:
        raise Invalid(str(exc)) from None


def _check_header(provider: Row) -> None:
    needs_header = provider["auth_type"] == AuthType.API_KEY_HEADER.value
    if needs_header != (provider["auth_header_name"] is not None):
        raise Invalid(
            "auth_header_name is required for api_key_header and forbidden otherwise"
        )


def _provider_used(connection: Connection, provider: Row) -> bool:
    if provider["first_used_at"] is not None:
        return True
    referenced = sa.exists().where(ai_credential.c.provider_id == provider["id"])
    return bool(connection.execute(sa.select(referenced)).scalar())


def list_providers(connection: Connection) -> list[ProviderAdmin]:
    """Every provider, oldest first."""
    rows = connection.execute(
        sa.select(ai_provider).order_by(ai_provider.c.created_at, ai_provider.c.id)
    ).mappings()
    return [ProviderAdmin.model_validate(dict(row)) for row in rows]


def get_provider(connection: Connection, provider_id: uuid.UUID) -> ProviderAdmin:
    """One provider."""
    row = (
        connection.execute(
            sa.select(ai_provider).where(ai_provider.c.id == provider_id)
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("no such provider")
    return ProviderAdmin.model_validate(dict(row))


def create_provider(
    tx: AuditedTransaction,
    actor: Actor,
    body: ProviderCreate,
    policy: DestinationPolicy,
) -> ProviderAdmin:
    """Register a provider endpoint."""
    _check_destination(body.base_url, body.boundary.value, policy)
    row = _insert(tx.connection, ai_provider, {"id": uuid.uuid4(), **_fields(body)})
    tx.admin(actor, "provider.create", "provider", row["id"], {"after": _audited(row)})
    return ProviderAdmin.model_validate(dict(row))


def update_provider(
    tx: AuditedTransaction,
    actor: Actor,
    provider_id: uuid.UUID,
    body: ProviderUpdate,
    policy: DestinationPolicy,
) -> ProviderAdmin:
    """Change a provider: its name, its enabled flag, or an unused endpoint."""
    row = _locked(tx.connection, ai_provider, provider_id)
    changes = _changes(body, row)
    if "boundary" in changes:
        raise Conflict("a provider's boundary is fixed; create a new provider row")
    if PROVIDER_ENDPOINT & changes.keys() and _provider_used(tx.connection, row):
        raise Conflict(
            "the provider endpoint is frozen after its first use; "
            "create a new provider row"
        )
    merged = {**row, **changes}
    _check_header(merged)
    if "base_url" in changes:
        _check_destination(merged["base_url"], row["boundary"], policy)
    if not changes:
        return ProviderAdmin.model_validate(dict(row))
    updated = _update(
        tx.connection, ai_provider, ai_provider.c.id == provider_id, changes
    )
    tx.admin(
        actor,
        "provider.update",
        "provider",
        provider_id,
        {"changed": _diff(row, changes)},
    )
    return ProviderAdmin.model_validate(dict(updated))


# --- models --------------------------------------------------------------------


def _check_dimensions(model: Row) -> None:
    embedding = Capability.EMBEDDING.value in model["capabilities"]
    if embedding != (model["dimensions"] is not None):
        raise Invalid(
            "dimensions is required for embedding models and forbidden otherwise"
        )


def _check_frozen_model(model: Row, changes: Row) -> None:
    if model["first_used_at"] is None:
        return
    if MODEL_IDENTITY & changes.keys():
        raise Conflict(
            "the model identity is frozen after its first reservation; "
            "register a new model row"
        )
    new = changes.get("capabilities")
    if new is not None and not set(new) <= set(model["capabilities"]):
        raise Conflict("a used model's capabilities may only shrink")


def _check_capabilities_in_use(
    connection: Connection, model_id: uuid.UUID, removed: set[str]
) -> None:
    if not removed:
        return
    in_use = (
        sa.select(ai_profile.c.capability)
        .join(ai_profile_binding, ai_profile_binding.c.profile_id == ai_profile.c.id)
        .where(ai_profile_binding.c.model_id == model_id)
        .where(ai_profile.c.capability.in_(sorted(removed)))
        .limit(1)
    )
    if connection.execute(in_use).first() is not None:
        raise Conflict("a binding relies on a capability this change removes")


def list_models(connection: Connection) -> list[ModelAdmin]:
    """Every model, oldest first."""
    rows = connection.execute(
        sa.select(ai_model).order_by(ai_model.c.created_at, ai_model.c.id)
    ).mappings()
    return [ModelAdmin.model_validate(dict(row)) for row in rows]


def get_model(connection: Connection, model_id: uuid.UUID) -> ModelAdmin:
    """One model."""
    row = (
        connection.execute(sa.select(ai_model).where(ai_model.c.id == model_id))
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("no such model")
    return ModelAdmin.model_validate(dict(row))


def create_model(tx: AuditedTransaction, actor: Actor, body: ModelCreate) -> ModelAdmin:
    """Register a model under an existing provider."""
    provider = tx.connection.execute(
        sa.select(ai_provider.c.id).where(ai_provider.c.id == body.provider_id)
    ).first()
    if provider is None:
        raise Invalid("provider_id names no provider")
    values = {
        "id": uuid.uuid4(),
        **_fields(body),
        "execution_identity": execution_identity(
            body.provider_id, body.external_model_id, body.model_revision
        ),
    }
    row = _insert(tx.connection, ai_model, values)
    tx.admin(actor, "model.create", "model", row["id"], {"after": _audited(row)})
    return ModelAdmin.model_validate(dict(row))


def update_model(
    tx: AuditedTransaction, actor: Actor, model_id: uuid.UUID, body: ModelUpdate
) -> ModelAdmin:
    """Change a model within the C-07 freeze rules."""
    row = _locked(tx.connection, ai_model, model_id)
    changes = _changes(body, row)
    _check_frozen_model(row, changes)
    merged = {**row, **changes}
    _check_dimensions(merged)
    if "capabilities" in changes:
        removed = set(row["capabilities"]) - set(merged["capabilities"])
        _check_capabilities_in_use(tx.connection, model_id, removed)
    if {"external_model_id", "model_revision"} & changes.keys():
        changes["execution_identity"] = execution_identity(
            row["provider_id"], merged["external_model_id"], merged["model_revision"]
        )
    if not changes:
        return ModelAdmin.model_validate(dict(row))
    updated = _update(tx.connection, ai_model, ai_model.c.id == model_id, changes)
    tx.admin(actor, "model.update", "model", model_id, {"changed": _diff(row, changes)})
    return ModelAdmin.model_validate(dict(updated))


# --- profiles ------------------------------------------------------------------

_CURRENT = sa.and_(
    ai_profile_revision.c.profile_id == ai_profile.c.id,
    ai_profile_revision.c.revision == ai_profile.c.current_revision,
)


def _profile_admin(row: Row) -> ProfileAdmin:
    current = {
        "revision": row["revision"],
        "execution_config": row["execution_config"],
        "execution_config_hash": row["execution_config_hash"],
        "created_at": row["revision_created_at"],
    }
    profile = {name: row[name] for name in ("id", "profile_key", "capability")}
    return ProfileAdmin.model_validate(
        {
            **profile,
            "enabled": row["enabled"],
            "current": current,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )


def _admin_profiles(
    connection: Connection, key: str | None = None
) -> list[ProfileAdmin]:
    statement = (
        sa.select(
            ai_profile,
            ai_profile_revision.c.revision,
            ai_profile_revision.c.execution_config,
            ai_profile_revision.c.execution_config_hash,
            ai_profile_revision.c.created_at.label("revision_created_at"),
        )
        .join(ai_profile_revision, _CURRENT)
        .order_by(ai_profile.c.profile_key)
    )
    if key is not None:
        statement = statement.where(ai_profile.c.profile_key == key)
    return [_profile_admin(row) for row in connection.execute(statement).mappings()]


def list_profiles(connection: Connection) -> list[ProfileAdmin]:
    """Every profile with its current revision, published or not."""
    return _admin_profiles(connection)


def get_profile(connection: Connection, profile_key: str) -> ProfileAdmin:
    """One profile with its current revision."""
    found = _admin_profiles(connection, profile_key)
    if not found:
        raise NotFound("no such profile")
    return found[0]


def list_revisions(
    connection: Connection, profile_key: str
) -> list[ProfileRevisionAdmin]:
    """Every revision of a profile, oldest first."""
    profile = get_profile(connection, profile_key)
    rows = connection.execute(
        sa.select(
            ai_profile_revision.c.revision,
            ai_profile_revision.c.execution_config,
            ai_profile_revision.c.execution_config_hash,
            ai_profile_revision.c.created_at,
        )
        .where(ai_profile_revision.c.profile_id == profile.id)
        .order_by(ai_profile_revision.c.revision)
    ).mappings()
    return [ProfileRevisionAdmin.model_validate(dict(row)) for row in rows]


def _insert_revision(
    connection: Connection,
    profile_id: uuid.UUID,
    revision: int,
    config: Mapping[str, object],
) -> str:
    config_hash = execution_config_hash(config)
    connection.execute(
        sa.insert(ai_profile_revision).values(
            profile_id=profile_id,
            revision=revision,
            execution_config=config,
            execution_config_hash=config_hash,
        )
    )
    return config_hash


def create_profile(
    tx: AuditedTransaction, actor: Actor, body: ProfileCreate
) -> ProfileAdmin:
    """Create a profile and its first revision."""
    profile_id = uuid.uuid4()
    inserted = tx.connection.execute(
        pg_insert(ai_profile)
        .values(
            id=profile_id,
            profile_key=body.profile_key,
            capability=body.capability.value,
            enabled=body.enabled,
            current_revision=1,
        )
        .on_conflict_do_nothing(index_elements=[ai_profile.c.profile_key])
        .returning(ai_profile.c.id)
    ).first()
    if inserted is None:
        raise Conflict("a profile with this profile_key exists")
    config_hash = _insert_revision(
        tx.connection, profile_id, 1, dict(body.execution_config)
    )
    after = {
        "profile_key": body.profile_key,
        "capability": body.capability.value,
        "enabled": body.enabled,
        "revision": 1,
        "execution_config_hash": config_hash,
    }
    tx.admin(actor, "profile.create", "profile", profile_id, {"after": after})
    return get_profile(tx.connection, body.profile_key)


def _new_revision(
    connection: Connection, profile: Row, body: ProfileUpdate
) -> tuple[int, str] | None:
    """Insert a revision when ``execution_config`` changes; its number and hash."""
    if "execution_config" not in body.model_fields_set or body.execution_config is None:
        return None
    config = dict(body.execution_config)
    current = connection.execute(
        sa.select(ai_profile_revision.c.execution_config_hash).where(
            ai_profile_revision.c.profile_id == profile["id"],
            ai_profile_revision.c.revision == profile["current_revision"],
        )
    ).scalar_one()
    if execution_config_hash(config) == current:
        return None
    latest = connection.execute(
        sa.select(sa.func.max(ai_profile_revision.c.revision)).where(
            ai_profile_revision.c.profile_id == profile["id"]
        )
    ).scalar_one()
    revision = int(latest) + 1
    return revision, _insert_revision(connection, profile["id"], revision, config)


def update_profile(
    tx: AuditedTransaction, actor: Actor, profile_key: str, body: ProfileUpdate
) -> ProfileAdmin:
    """Change a profile; a changed configuration is a new revision."""
    row = (
        tx.connection.execute(
            sa.select(ai_profile)
            .where(ai_profile.c.profile_key == profile_key)
            .with_for_update()
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("no such profile")
    changes: dict[str, object] = {}
    revised = _new_revision(tx.connection, row, body)
    if revised is not None:
        changes["current_revision"] = revised[0]
    if "enabled" in body.model_fields_set and body.enabled != row["enabled"]:
        changes["enabled"] = body.enabled
    if changes:
        _update(tx.connection, ai_profile, ai_profile.c.id == row["id"], changes)
        metadata: dict[str, object] = {"changed": _diff(row, changes)}
        if revised is not None:
            metadata["execution_config_hash"] = revised[1]
        tx.admin(actor, "profile.update", "profile", row["id"], metadata)
    return get_profile(tx.connection, profile_key)


# --- the published view (readers, profiles:read clients) -------------------------


def _public(row: Row) -> ProfilePublic:
    capability = Capability(row["capability"])
    view: dict[str, object] = {
        "profile_key": row["profile_key"],
        "capability": capability,
        "revision": row["current_revision"],
        "enabled": row["enabled"],
        "identity_assurance": row["identity_assurance"],
    }
    if capability is Capability.EMBEDDING:
        view["dimensions"] = row["dimensions"]
        view["embedding_space_id"] = embedding_space_id(
            row["provider_id"],
            row["external_model_id"],
            row["model_revision"],
            row["dimensions"],
            row["execution_config_hash"],
        )
    if capability is Capability.OCR:
        view["ocr_execution_identity"] = row["execution_identity"]
    return ProfilePublic.model_validate(view)


def _published(connection: Connection, key: str | None = None) -> Sequence[Row]:
    binding = ai_profile_binding
    statement = (
        sa.select(
            ai_profile.c.profile_key,
            ai_profile.c.capability,
            ai_profile.c.enabled,
            ai_profile.c.current_revision,
            ai_profile_revision.c.execution_config_hash,
            ai_model.c.provider_id,
            ai_model.c.external_model_id,
            ai_model.c.model_revision,
            ai_model.c.dimensions,
            ai_model.c.identity_assurance,
            ai_model.c.execution_identity,
        )
        .join(ai_profile_revision, _CURRENT)
        .join(
            binding,
            sa.and_(
                binding.c.profile_id == ai_profile.c.id,
                binding.c.scope_type == ScopeType.GLOBAL.value,
            ),
        )
        .join(ai_model, ai_model.c.id == binding.c.model_id)
        .order_by(ai_profile.c.profile_key)
    )
    if key is not None:
        statement = statement.where(ai_profile.c.profile_key == key)
    return connection.execute(statement).mappings().all()


def list_public_profiles(connection: Connection) -> list[ProfilePublic]:
    """
    Every published profile: one with a global binding, whose model gives it
    an identity. Keys, capability, dimensions and identities only — never a
    credential, a provider or its ``base_url``.
    """
    return [_public(row) for row in _published(connection)]


def get_public_profile(connection: Connection, profile_key: str) -> ProfilePublic:
    """One published profile; ``profile_unknown`` when there is none."""
    rows = _published(connection, profile_key)
    if not rows:
        raise GatewayError(AiErrorCode.PROFILE_UNKNOWN)
    return _public(rows[0])


__all__ = [
    "MODEL_IDENTITY",
    "PROVIDER_ENDPOINT",
    "create_model",
    "create_profile",
    "create_provider",
    "get_model",
    "get_profile",
    "get_provider",
    "get_public_profile",
    "list_models",
    "list_profiles",
    "list_providers",
    "list_public_profiles",
    "list_revisions",
    "update_model",
    "update_profile",
    "update_provider",
]
