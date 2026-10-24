"""
Material destruction of retired credential versions (D-43, ``T33a``).

A version's material is destroyed — the envelope columns cleared,
``material_destroyed_at`` set, the row kept as a tombstone — only once
**all** hold:

* its material was committed and is neither destroyed, lost nor aborted;
* no ``ai_provider_remote_artifact`` row of any status references it (a
  ``manual_cleanup_required`` row included): cleanup needs the recorded
  version's secret, so destruction never precedes it;
* its sweep obligation is discharged (``sweep_discharge_at`` unset, or
  ``reconciled_through`` at or past it);
* it is not the current version of a credential that is not ``deleted``;
* no non-terminal execution resolved it (a dispatch in flight still reads
  it).

The candidate select and the destroying ``UPDATE`` carry the same predicate
and the scheduler's fence, so a row that changed in between stays; the
``ai_credential_version_guard`` trigger re-checks the first three
conditions in the database as the last guard. Destruction runs whatever the
credential's, provider's or profile's state, and each destruction writes an
``ai_credential_audit`` row (``credential.material_destroyed``, actor
``system``/``scheduler``), mirrored to the log sink once it commits.

The ``vault`` KV backend's ``metadata`` delete (confirmed by a read that
finds no path) is ``T24``'s, which this build does not serve.
"""

from __future__ import annotations

from typing import Final

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import CredentialStatus
from sqlalchemy import Engine

from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.db_models._common import TERMINAL_STATUSES
from ai_gateway.db_models.accounting import ai_execution
from ai_gateway.db_models.artifacts import ai_provider_remote_artifact
from ai_gateway.db_models.credentials import ai_credential

# Only this package may import the version table (TID251, ``ruff.toml`` here).
from ai_gateway.db_models.credential_version import ai_credential_version  # noqa: TID251

from .database import MATERIAL_COLUMNS

_V, _C, _A, _E = (
    ai_credential_version,
    ai_credential,
    ai_provider_remote_artifact,
    ai_execution,
)

_SCHEDULER: Final = Actor("system", "scheduler")

#: Versions destroyed per pass.
DESTROY_BATCH: Final = 100


def destroyable() -> sa.ColumnElement[bool]:
    """The positive predicate: ``True`` only for a version nothing still needs."""
    return sa.and_(
        _V.c.ciphertext.is_not(None),
        _V.c.material_committed_at.is_not(None),
        _V.c.material_destroyed_at.is_(None),
        _V.c.material_lost_at.is_(None),
        _V.c.aborted_at.is_(None),
        ~sa.exists().where(
            _A.c.credential_id == _V.c.credential_id,
            _A.c.credential_version == _V.c.version,
        ),
        sa.or_(
            _V.c.sweep_discharge_at.is_(None),
            _V.c.reconciled_through >= _V.c.sweep_discharge_at,
        ),
        ~sa.exists().where(
            _C.c.id == _V.c.credential_id,
            _C.c.current_version == _V.c.version,
            _C.c.status != CredentialStatus.DELETED.value,
        ),
        ~sa.exists().where(
            _E.c.resolved_credential_id == _V.c.credential_id,
            _E.c.resolved_credential_version == _V.c.version,
            _E.c.status.not_in([s.value for s in TERMINAL_STATUSES]),
        ),
    )


def destroy_retired(
    engine: Engine,
    *,
    fence: sa.ColumnElement[bool] | None = None,
    limit: int = DESTROY_BATCH,
) -> list[tuple[str, int]]:
    """Destroy up to ``limit`` retired versions; the ``(credential, version)`` pairs."""
    where = destroyable()
    if fence is not None:
        where = sa.and_(where, fence)
    picked = (
        sa.select(_V.c.credential_id, _V.c.version)
        .where(where)
        .limit(limit)
        .with_for_update(of=_V, skip_locked=True)
    )
    with audited_transaction(engine) as tx:
        rows = tx.connection.execute(
            sa.update(_V)
            .where(sa.tuple_(_V.c.credential_id, _V.c.version).in_(picked), where)
            .values(
                **{column: None for column in MATERIAL_COLUMNS},
                material_destroyed_at=sa.func.now(),
            )
            .returning(_V.c.credential_id, _V.c.version)
        ).all()
        scopes = {
            row["id"]: row
            for row in tx.connection.execute(
                sa.select(
                    _C.c.id, _C.c.scope_type, _C.c.tenant_id, _C.c.owner_user_id
                ).where(_C.c.id.in_({row[0] for row in rows}))
            ).mappings()
        }
        for credential_id, version in rows:
            scope = scopes[credential_id]
            tx.credential(
                _SCHEDULER,
                "credential.material_destroyed",
                credential_id,
                {
                    "scope_type": scope["scope_type"],
                    "tenant_id": scope["tenant_id"],
                    "owner_user_id": scope["owner_user_id"],
                },
                {"version": version},
            )
    return [(str(row[0]), int(row[1])) for row in rows]


__all__ = ["DESTROY_BATCH", "destroy_retired", "destroyable"]
