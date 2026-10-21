"""
Profile bindings (C-04): which model and credential serve a profile in a scope.

A binding names a model that carries its profile's capability and, unless
the model's provider takes no credential, a credential of the **same scope**
and the **same provider**. Its ``status`` is ``credential_unavailable``
while that credential is not ``active``. A global binding is the last scope
of the C-04 precedence, so it has nothing to fall through to.

The scope is a parameter: ``T18`` serves the global scope (superuser);
the tenant and user scopes are ``T20a``'s routes over the same rules.
"""

from __future__ import annotations

import uuid
from typing import Any

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import (
    AuthType,
    BindingCreate,
    BindingPublic,
    BindingStatus,
    BindingUpdate,
    CredentialStatus,
    OnUnavailable,
    ScopeType,
)
from sqlalchemy import Connection
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ai_gateway.db_models.credentials import ai_credential
from ai_gateway.db_models.registry import (
    ai_model,
    ai_profile,
    ai_profile_binding,
    ai_provider,
)

from .audit import Actor, AuditedTransaction
from .errors import Conflict, Invalid, NotFound
from .registry import Row
from .scopes import GLOBAL, Scope


def _view_statement() -> sa.Select[Any]:
    return sa.select(ai_profile_binding, ai_profile.c.profile_key).join(
        ai_profile, ai_profile.c.id == ai_profile_binding.c.profile_id
    )


def _view(row: Row) -> BindingPublic:
    return BindingPublic.model_validate(
        {name: row[name] for name in BindingPublic.model_fields}
    )


def list_bindings(connection: Connection, scope: Scope) -> list[BindingPublic]:
    """Every binding of ``scope``, by profile key."""
    statement = (
        _view_statement()
        .where(scope.where(ai_profile_binding))
        .order_by(ai_profile.c.profile_key)
    )
    return [_view(row) for row in connection.execute(statement).mappings()]


def get_binding(
    connection: Connection, scope: Scope, binding_id: uuid.UUID
) -> BindingPublic:
    """One binding of ``scope``."""
    row = (
        connection.execute(
            _view_statement().where(
                ai_profile_binding.c.id == binding_id, scope.where(ai_profile_binding)
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("no such binding")
    return _view(row)


def _target_model(connection: Connection, model_id: uuid.UUID, capability: str) -> Row:
    model = (
        connection.execute(
            sa.select(
                ai_model.c.provider_id, ai_model.c.capabilities, ai_provider.c.auth_type
            )
            .join(ai_provider, ai_provider.c.id == ai_model.c.provider_id)
            .where(ai_model.c.id == model_id)
        )
        .mappings()
        .first()
    )
    if model is None:
        raise Invalid("model_id names no model")
    if capability not in model["capabilities"]:
        raise Invalid("the model does not carry the profile's capability")
    return model


def _status(
    connection: Connection,
    scope: Scope,
    model: Row,
    credential_id: uuid.UUID | None,
) -> BindingStatus:
    """Check the credential against the scope and the model's provider."""
    keyless = model["auth_type"] == AuthType.NONE.value
    if credential_id is None:
        if not keyless:
            raise Invalid("the model's provider needs a credential")
        return BindingStatus.ACTIVE
    if keyless:
        raise Invalid("the model's provider takes no credential")
    credential = (
        connection.execute(
            sa.select(ai_credential.c.provider_id, ai_credential.c.status).where(
                ai_credential.c.id == credential_id,
                ai_credential.c.status != CredentialStatus.DELETED.value,
                scope.where(ai_credential),
            )
        )
        .mappings()
        .first()
    )
    if credential is None:
        raise Invalid("credential_id names no credential in this scope")
    if credential["provider_id"] != model["provider_id"]:
        raise Invalid("the credential belongs to another provider")
    if credential["status"] == CredentialStatus.ACTIVE.value:
        return BindingStatus.ACTIVE
    return BindingStatus.CREDENTIAL_UNAVAILABLE


def _check_on_unavailable(scope: Scope, value: str) -> None:
    if (
        scope.scope_type is ScopeType.GLOBAL
        and value == OnUnavailable.FALL_THROUGH.value
    ):
        raise Invalid("a global binding has no scope to fall through to")


def _audited(row: Row, profile_key: str) -> dict[str, object]:
    return {
        "profile_key": profile_key,
        "model_id": row["model_id"],
        "credential_id": row["credential_id"],
        "on_unavailable": row["on_unavailable"],
        "status": row["status"],
    }


def create_binding(
    tx: AuditedTransaction, actor: Actor, scope: Scope, body: BindingCreate
) -> BindingPublic:
    """Bind a profile in ``scope``; one binding per profile and scope."""
    profile = (
        tx.connection.execute(
            sa.select(ai_profile.c.id, ai_profile.c.capability).where(
                ai_profile.c.profile_key == body.profile_key
            )
        )
        .mappings()
        .first()
    )
    if profile is None:
        raise Invalid("profile_key names no profile")
    model = _target_model(tx.connection, body.model_id, profile["capability"])
    status = _status(tx.connection, scope, model, body.credential_id)
    _check_on_unavailable(scope, body.on_unavailable.value)
    values = {
        "id": uuid.uuid4(),
        "profile_id": profile["id"],
        "scope_type": scope.scope_type.value,
        "tenant_id": scope.tenant_id,
        "owner_user_id": scope.owner_user_id,
        "model_id": body.model_id,
        "credential_id": body.credential_id,
        "on_unavailable": body.on_unavailable.value,
        "status": status.value,
    }
    inserted = tx.connection.execute(
        pg_insert(ai_profile_binding)
        .values(**values)
        .on_conflict_do_nothing(constraint="uq_ai_profile_binding_scope")
        .returning(ai_profile_binding.c.id)
    ).first()
    if inserted is None:
        raise Conflict("this scope already binds the profile")
    metadata = {**scope.audit(), "after": _audited(values, body.profile_key)}
    tx.admin(actor, "binding.create", "binding", values["id"], metadata)
    return get_binding(tx.connection, scope, values["id"])


def _locked_binding(connection: Connection, scope: Scope, binding_id: uuid.UUID) -> Row:
    row = (
        connection.execute(
            _view_statement()
            .add_columns(ai_profile.c.capability)
            .where(
                ai_profile_binding.c.id == binding_id, scope.where(ai_profile_binding)
            )
            .with_for_update(of=ai_profile_binding)
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("no such binding")
    return row


def update_binding(
    tx: AuditedTransaction,
    actor: Actor,
    scope: Scope,
    binding_id: uuid.UUID,
    body: BindingUpdate,
) -> BindingPublic:
    """Repoint a binding or change what it does when its credential fails."""
    row = _locked_binding(tx.connection, scope, binding_id)
    changes: dict[str, Any] = {}
    for name in sorted(body.model_fields_set):
        value = getattr(body, name)
        value = value.value if isinstance(value, OnUnavailable) else value
        if value != row[name]:
            changes[name] = value
    merged = {**row, **changes}
    model = _target_model(tx.connection, merged["model_id"], row["capability"])
    status = _status(tx.connection, scope, model, merged["credential_id"]).value
    _check_on_unavailable(scope, merged["on_unavailable"])
    if status != row["status"]:
        changes["status"] = status
    if changes:
        tx.connection.execute(
            sa.update(ai_profile_binding)
            .where(ai_profile_binding.c.id == binding_id)
            .values(**changes, updated_at=sa.func.now())
        )
        changed = {k: {"before": row[k], "after": v} for k, v in changes.items()}
        metadata = {
            **scope.audit(),
            "profile_key": row["profile_key"],
            "changed": changed,
        }
        tx.admin(actor, "binding.update", "binding", binding_id, metadata)
    return get_binding(tx.connection, scope, binding_id)


def delete_binding(
    tx: AuditedTransaction, actor: Actor, scope: Scope, binding_id: uuid.UUID
) -> None:
    """Remove a binding; the scope then falls through to the next one (C-04)."""
    row = _locked_binding(tx.connection, scope, binding_id)
    tx.connection.execute(
        sa.delete(ai_profile_binding).where(ai_profile_binding.c.id == binding_id)
    )
    metadata = {**scope.audit(), "before": _audited(row, row["profile_key"])}
    tx.admin(actor, "binding.delete", "binding", binding_id, metadata)


def sync_credential_status(connection: Connection, credential_id: uuid.UUID) -> int:
    """
    Make every binding of a credential follow its availability (T20a).

    In the transaction that changes the credential's status: ``active`` makes
    its bindings ``active``, anything else (disabled, invalid, deleted,
    awaiting re-confirmation) ``credential_unavailable``. Bindings are never
    removed. Returns how many bindings changed.
    """
    status = sa.case(
        (
            ai_credential.c.status == CredentialStatus.ACTIVE.value,
            BindingStatus.ACTIVE.value,
        ),
        else_=BindingStatus.CREDENTIAL_UNAVAILABLE.value,
    )
    current = (
        sa.select(status)
        .where(ai_credential.c.id == ai_profile_binding.c.credential_id)
        .scalar_subquery()
    )
    result = connection.execute(
        sa.update(ai_profile_binding)
        .where(
            ai_profile_binding.c.credential_id == credential_id,
            ai_profile_binding.c.status != current,
        )
        .values(status=current, updated_at=sa.func.now())
    )
    return int(result.rowcount)


def count_user_bindings(connection: Connection) -> int:
    """How many user-scope bindings exist (``/health`` while BYOK is off, A-3)."""
    statement = (
        sa.select(sa.func.count())
        .select_from(ai_profile_binding)
        .where(ai_profile_binding.c.scope_type == ScopeType.USER.value)
    )
    return int(connection.execute(statement).scalar_one())


__all__ = [
    "GLOBAL",
    "Scope",
    "count_user_bindings",
    "create_binding",
    "delete_binding",
    "get_binding",
    "list_bindings",
    "sync_credential_status",
    "update_binding",
]
