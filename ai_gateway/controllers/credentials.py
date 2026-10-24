"""
Provider credentials in a scope (T20, D-05, R-08, C-05).

Every operation names a :class:`~ai_gateway.controllers.scopes.Scope` taken
from the route and the token. A credential outside that scope, or deleted,
answers the same ``404`` as one that never existed, so no response says
whether an id, a key or a name exists in another scope.

* **Create.** The provider is locked for the write, so its endpoint cannot
  change underneath it, and its ``first_used_at`` is stamped, freezing the
  endpoint (D-20). Creates in one scope serialize on an advisory lock, so
  ``AI_MAX_CREDENTIALS_PER_SCOPE`` holds under concurrency (N-09, tenant and
  user scopes). The same key twice in one scope is refused; fingerprints
  are scope-bound, so another scope's copy can never be noticed.
* **Rotate** writes the next version and clears the failure count;
  ``active``, ``invalid`` and ``reprovision_required`` become ``active``.
* **Disable / enable / reconfirm / delete** move the status; every binding
  of the credential follows in the same transaction.
* ``provider_id``, ``scope_type``, ``tenant_id`` and ``owner_user_id`` are
  fixed at creation: no body can name them (``extra="forbid"``), and a
  trigger refuses the change when this controller is bypassed.

Every transition writes ``ai_credential_audit``; no response, audit row or
log line carries the secret or its fingerprint. ``secret_hint`` (the last
four characters) is kept only for secrets of at least 24 characters.
"""

from __future__ import annotations

import uuid
from typing import Any, Final

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import (
    AuthType,
    CredentialCreate,
    CredentialPublic,
    CredentialRotate,
    CredentialStatus,
    CredentialUpdate,
    RemoteArtifactPublic,
    ScopeType,
)
from pydantic import SecretStr
from sqlalchemy import Connection

from ai_gateway.credentials.store import CredentialIdentity, CredentialStore
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import ai_provider

from .audit import Actor, AuditedTransaction
from .bindings import sync_credential_status
from .errors import Conflict, Invalid, NotFound
from .registry import Row
from .scopes import Scope

#: A secret shorter than this never shows its last four characters.
HINT_MIN_LENGTH: Final = 24

_NOT_FOUND: Final = "no such credential"
_C = ai_credential
_DELETED = CredentialStatus.DELETED.value
_ACTIVE = CredentialStatus.ACTIVE.value

#: Statuses a rotation turns into ``active``.
_ROTATION_ACTIVATES: Final = frozenset(
    {
        CredentialStatus.ACTIVE.value,
        CredentialStatus.INVALID.value,
        CredentialStatus.REPROVISION_REQUIRED.value,
    }
)
#: Statuses ``:disable`` moves away from.
_DISABLEABLE: Final = frozenset(
    {
        CredentialStatus.ACTIVE.value,
        CredentialStatus.INVALID.value,
        CredentialStatus.RECONFIRM_REQUIRED.value,
        CredentialStatus.REPROVISION_REQUIRED.value,
    }
)


def _public(row: Row) -> CredentialPublic:
    return CredentialPublic.model_validate(
        {name: row[name] for name in CredentialPublic.model_fields}
    )


def _hint(secret: SecretStr) -> str | None:
    value = secret.get_secret_value()
    return value[-4:] if len(value) >= HINT_MIN_LENGTH else None


def _identity(row: Row) -> CredentialIdentity:
    return CredentialIdentity(
        credential_id=row["id"],
        provider_id=row["provider_id"],
        scope_type=ScopeType(row["scope_type"]),
        tenant_id=row["tenant_id"],
        owner_user_id=row["owner_user_id"],
    )


def _scope_of(row: Row) -> dict[str, object]:
    return {
        "scope_type": row["scope_type"],
        "tenant_id": row["tenant_id"],
        "owner_user_id": row["owner_user_id"],
    }


def _visible(scope: Scope) -> sa.ColumnElement[bool]:
    return sa.and_(scope.where(_C), _C.c.status != _DELETED)


def list_credentials(connection: Connection, scope: Scope) -> list[CredentialPublic]:
    """The scope's credentials, oldest first."""
    rows = connection.execute(
        sa.select(_C).where(_visible(scope)).order_by(_C.c.created_at, _C.c.id)
    ).mappings()
    return [_public(row) for row in rows]


def get_credential(
    connection: Connection, scope: Scope, credential_id: uuid.UUID
) -> CredentialPublic:
    """One credential of the scope."""
    row = (
        connection.execute(
            sa.select(_C).where(_C.c.id == credential_id, _visible(scope))
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound(_NOT_FOUND)
    return _public(row)


def _locked(connection: Connection, where: sa.ColumnElement[bool]) -> Row:
    row = (
        connection.execute(sa.select(_C).where(where).with_for_update())
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound(_NOT_FOUND)
    return row


def _set(connection: Connection, credential_id: uuid.UUID, **values: Any) -> Row:
    return (
        connection.execute(
            sa.update(_C)
            .where(_C.c.id == credential_id)
            .values(**values, updated_at=sa.func.now())
            .returning(*_C.c)
        )
        .mappings()
        .one()
    )


def _locked_provider(connection: Connection, provider_id: uuid.UUID) -> Row:
    provider = (
        connection.execute(
            sa.select(ai_provider.c.id, ai_provider.c.auth_type)
            .where(ai_provider.c.id == provider_id)
            .with_for_update()
        )
        .mappings()
        .first()
    )
    if provider is None:
        raise Invalid("provider_id names no provider")
    if provider["auth_type"] == AuthType.NONE.value:
        raise Invalid("this provider takes no credential")
    return provider


def _check_capacity(connection: Connection, scope: Scope, cap: int) -> None:
    """Serialize the scope's creates and refuse one past ``cap`` (N-09)."""
    connection.execute(
        sa.select(
            sa.func.pg_advisory_xact_lock(sa.func.hashtextextended(scope.lock_key(), 0))
        )
    )
    if scope.scope_type is ScopeType.GLOBAL:
        return
    held = connection.execute(
        sa.select(sa.func.count()).select_from(_C).where(_visible(scope))
    ).scalar_one()
    if held >= cap:
        raise Conflict("this scope holds the maximum number of credentials")


def _refuse_duplicate(
    connection: Connection,
    store: CredentialStore,
    identity: CredentialIdentity,
    secret: SecretStr,
) -> None:
    if store.duplicate_in_scope(connection, identity, secret):
        raise Conflict("this key is already stored in this scope")


def _insert_provisioning(
    connection: Connection,
    identity: CredentialIdentity,
    body: CredentialCreate,
    backend: str,
) -> None:
    connection.execute(
        sa.insert(_C).values(
            id=identity.credential_id,
            scope_type=identity.scope_type.value,
            tenant_id=identity.tenant_id,
            owner_user_id=identity.owner_user_id,
            provider_id=identity.provider_id,
            name=body.name,
            status=CredentialStatus.PROVISIONING.value,
            secret_backend=backend,
            secret_hint=_hint(body.secret),
        )
    )


def _stamp_first_use(connection: Connection, provider_id: uuid.UUID) -> None:
    """The first credential that references a provider freezes its endpoint."""
    connection.execute(
        sa.update(ai_provider)
        .where(ai_provider.c.id == provider_id, ai_provider.c.first_used_at.is_(None))
        .values(first_used_at=sa.func.now())
    )


def create_credential(
    tx: AuditedTransaction,
    actor: Actor,
    scope: Scope,
    body: CredentialCreate,
    store: CredentialStore,
    max_per_scope: int,
) -> CredentialPublic:
    """Store a new credential in ``scope``; it is active once this commits."""
    connection = tx.connection
    _locked_provider(connection, body.provider_id)
    _check_capacity(connection, scope, max_per_scope)
    identity = CredentialIdentity(
        uuid.uuid4(),
        body.provider_id,
        scope.scope_type,
        scope.tenant_id,
        scope.owner_user_id,
    )
    _refuse_duplicate(connection, store, identity, body.secret)
    _insert_provisioning(connection, identity, body, store.backend)
    stored = store.store(connection, identity, body.secret)
    _stamp_first_use(connection, body.provider_id)
    row = _locked(connection, _C.c.id == identity.credential_id)
    metadata = {
        "name": body.name,
        "provider_id": body.provider_id,
        "version": stored.version,
    }
    tx.credential(
        actor, "credential.create", identity.credential_id, scope.audit(), metadata
    )
    return _public(row)


def update_credential(
    tx: AuditedTransaction,
    actor: Actor,
    scope: Scope,
    credential_id: uuid.UUID,
    body: CredentialUpdate,
) -> CredentialPublic:
    """Rename a credential or change its incident-listing consent."""
    row = _locked(tx.connection, sa.and_(_C.c.id == credential_id, _visible(scope)))
    changes = {
        name: getattr(body, name)
        for name in sorted(body.model_fields_set)
        if getattr(body, name) != row[name]
    }
    if not changes:
        return _public(row)
    updated = _set(tx.connection, credential_id, **changes)
    changed = {k: {"before": row[k], "after": v} for k, v in changes.items()}
    tx.credential(
        actor, "credential.update", credential_id, scope.audit(), {"changed": changed}
    )
    return _public(updated)


def rotate_credential(
    tx: AuditedTransaction,
    actor: Actor,
    scope: Scope,
    credential_id: uuid.UUID,
    body: CredentialRotate,
    store: CredentialStore,
) -> CredentialPublic:
    """Store a new current version; the previous one is retired."""
    row = _locked(tx.connection, sa.and_(_C.c.id == credential_id, _visible(scope)))
    identity = _identity(row)
    _refuse_duplicate(tx.connection, store, identity, body.secret)
    stored = store.replace(tx.connection, identity, body.secret)
    status = _ACTIVE if row["status"] in _ROTATION_ACTIVATES else row["status"]
    updated = _set(
        tx.connection,
        credential_id,
        status=status,
        secret_hint=_hint(body.secret),
        auth_failure_count=0,
        throttled_until=None,
    )
    bindings = sync_credential_status(tx.connection, credential_id)
    metadata = {
        "version": stored.version,
        "status": {"before": row["status"], "after": status},
        "bindings_changed": bindings,
    }
    tx.credential(actor, "credential.rotate", credential_id, scope.audit(), metadata)
    return _public(updated)


def _transition(
    tx: AuditedTransaction,
    actor: Actor,
    row: Row,
    action: str,
    status: str,
) -> CredentialPublic:
    """Move ``row`` to ``status``; its bindings follow; audited."""
    updated = _set(tx.connection, row["id"], status=status)
    bindings = sync_credential_status(tx.connection, row["id"])
    metadata = {
        "status": {"before": row["status"], "after": status},
        "bindings_changed": bindings,
    }
    tx.credential(actor, action, row["id"], _scope_of(row), metadata)
    return _public(updated)


def disable_credential(
    tx: AuditedTransaction, actor: Actor, where: sa.ColumnElement[bool]
) -> CredentialPublic:
    """Stop a credential; already disabled is a no-op."""
    row = _locked(tx.connection, sa.and_(where, _C.c.status != _DELETED))
    if row["status"] not in _DISABLEABLE:
        return _public(row)
    return _transition(
        tx, actor, row, "credential.disable", CredentialStatus.DISABLED.value
    )


def enable_credential(
    tx: AuditedTransaction, actor: Actor, scope: Scope, credential_id: uuid.UUID
) -> CredentialPublic:
    """Re-enable a disabled credential (its owner only)."""
    row = _locked(tx.connection, sa.and_(_C.c.id == credential_id, _visible(scope)))
    if row["status"] != CredentialStatus.DISABLED.value:
        raise Conflict("only a disabled credential can be enabled")
    return _transition(tx, actor, row, "credential.enable", _ACTIVE)


def reconfirm_credential(
    tx: AuditedTransaction, actor: Actor, scope: Scope, credential_id: uuid.UUID
) -> CredentialPublic:
    """Re-confirm a credential after a restore (its owner only)."""
    row = _locked(tx.connection, sa.and_(_C.c.id == credential_id, _visible(scope)))
    if row["status"] != CredentialStatus.RECONFIRM_REQUIRED.value:
        raise Conflict("only a credential awaiting re-confirmation can be re-confirmed")
    return _transition(tx, actor, row, "credential.reconfirm", _ACTIVE)


def delete_credential(
    tx: AuditedTransaction,
    actor: Actor,
    where: sa.ColumnElement[bool],
    store: CredentialStore,
) -> None:
    """Delete logically; the material stays until D-43 cleanup allows."""
    row = _locked(tx.connection, sa.and_(where, _C.c.status != _DELETED))
    store.delete(tx.connection, row["id"])
    bindings = sync_credential_status(tx.connection, row["id"])
    metadata = {
        "status": {"before": row["status"], "after": _DELETED},
        "bindings_changed": bindings,
    }
    tx.credential(actor, "credential.delete", row["id"], _scope_of(row), metadata)


def in_scope(scope: Scope, credential_id: uuid.UUID) -> sa.ColumnElement[bool]:
    """``credential_id`` in exactly ``scope``."""
    return sa.and_(_C.c.id == credential_id, scope.where(_C))


def user_credential(credential_id: uuid.UUID) -> sa.ColumnElement[bool]:
    """``credential_id`` if it is user-scoped, in any tenant (A-2)."""
    return sa.and_(_C.c.id == credential_id, _C.c.scope_type == ScopeType.USER.value)


def list_user_credentials(
    connection: Connection, owner_user_id: uuid.UUID
) -> list[CredentialPublic]:
    """One user's credentials, metadata only, for the superuser's stop (A-2)."""
    rows = connection.execute(
        sa.select(_C)
        .where(
            _C.c.scope_type == ScopeType.USER.value,
            _C.c.owner_user_id == owner_user_id,
            _C.c.status != _DELETED,
        )
        .order_by(_C.c.created_at, _C.c.id)
    ).mappings()
    return [_public(row) for row in rows]


def list_remote_artifacts(
    connection: Connection, scope: Scope, credential_id: uuid.UUID
) -> list[RemoteArtifactPublic]:
    """Provider-side files under a credential: ids and status, never content."""
    get_credential(connection, scope, credential_id)
    table = ai_provider_remote_artifact
    rows = connection.execute(
        sa.select(
            table.c.id,
            table.c.credential_version,
            table.c.status,
            table.c.remote_artifact_id,
            table.c.provider_expires_at,
            table.c.created_at,
        )
        .where(table.c.credential_id == credential_id)
        .order_by(table.c.created_at, table.c.id)
    ).mappings()
    return [RemoteArtifactPublic.model_validate(dict(row)) for row in rows]


__all__ = [
    "HINT_MIN_LENGTH",
    "create_credential",
    "delete_credential",
    "disable_credential",
    "enable_credential",
    "get_credential",
    "in_scope",
    "list_credentials",
    "list_remote_artifacts",
    "list_user_credentials",
    "reconfirm_credential",
    "rotate_credential",
    "update_credential",
    "user_credential",
]
