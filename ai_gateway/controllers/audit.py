"""
Audit trail of privileged changes (S-11).

Every management write runs in an :func:`audited_transaction`: its audit row
is inserted in the same transaction as the change, and once that transaction
commits each row is also emitted as one structured log event, so a restore
that rewinds ``ai_db`` does not erase the record of a later change — as
evidence, not authority. Nothing is logged for a change that rolled back.

Audit metadata carries before/after **metadata**, never a secret, and is
bounded to the 4 KiB the table's ``CHECK`` allows: when it would not fit,
long strings are replaced by their SHA-256 and length.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final

from sqlalchemy import Connection, Engine, insert

from ai_gateway.db_models.audit import ai_admin_audit, ai_credential_audit
from fastapi_m8 import UserModel

logger = logging.getLogger("ai_gateway.audit")

#: The audit tables' ``octet_length(metadata::text)`` bound.
AUDIT_METADATA_MAX_BYTES: Final = 4096

#: Strings longer than this are digested when metadata must shrink.
_DIGEST_OVER: Final = 64


@dataclass(frozen=True)
class Actor:
    """Who made a change: a non-secret identifier, never a token."""

    kind: str
    id: str | None = None
    role: str | None = None

    @classmethod
    def of_user(cls, user: UserModel) -> Actor:
        """The JWT-authenticated user ``user``."""
        return cls("user", str(user.id), user.role.value)


def _jsonb_size(value: object) -> int:
    # PostgreSQL renders jsonb::text with ", " and ": " separators.
    text = json.dumps(value, separators=(", ", ": "), ensure_ascii=False, default=str)
    return len(text.encode("utf-8"))


def _digested(value: object) -> object:
    if isinstance(value, str) and len(value) > _DIGEST_OVER:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return {"sha256": digest, "length": len(value)}
    if isinstance(value, Mapping):
        return {str(k): _digested(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_digested(v) for v in value]
    return value


def bound_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    """``metadata`` as JSON-ready values, shrunk to the table's bound."""
    plain: dict[str, object] = json.loads(json.dumps(dict(metadata), default=str))
    if _jsonb_size(plain) <= AUDIT_METADATA_MAX_BYTES:
        return plain
    reduced = _digested(plain)
    assert isinstance(reduced, dict)  # nosec B101 - a mapping digests to a dict
    if _jsonb_size(reduced) <= AUDIT_METADATA_MAX_BYTES:
        return reduced
    canonical = json.dumps(plain, sort_keys=True, separators=(",", ":"))
    return {
        "truncated": True,
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


class AuditedTransaction:
    """One transaction and the audit events to emit once it commits."""

    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self._events: list[dict[str, object]] = []

    def admin(
        self,
        actor: Actor,
        action: str,
        target_type: str,
        target_id: object,
        metadata: Mapping[str, object],
    ) -> None:
        """Insert one ``ai_admin_audit`` row."""
        values: dict[str, object] = {
            "action": action,
            "actor_kind": actor.kind,
            "actor_id": actor.id,
            "actor_role": actor.role,
            "target_type": target_type,
            "target_id": None if target_id is None else str(target_id),
            "metadata": bound_metadata(metadata),
        }
        self.connection.execute(insert(ai_admin_audit).values(**values))
        self._events.append({"trail": "admin", **values})

    def credential(
        self,
        actor: Actor,
        action: str,
        credential_id: object,
        scope: Mapping[str, object],
        metadata: Mapping[str, object],
    ) -> None:
        """Insert one ``ai_credential_audit`` row (never the secret)."""
        values: dict[str, object] = {
            "action": action,
            "actor_kind": actor.kind,
            "actor_id": actor.id,
            "actor_role": actor.role,
            "credential_id": credential_id,
            "scope_type": scope["scope_type"],
            "tenant_id": scope["tenant_id"],
            "owner_user_id": scope["owner_user_id"],
            "metadata": bound_metadata(metadata),
        }
        self.connection.execute(insert(ai_credential_audit).values(**values))
        self._events.append({"trail": "credential", **values})

    def emit(self) -> None:
        """Log every recorded event; called only after the commit."""
        for event in self._events:
            logger.info("audit %s", json.dumps(event, sort_keys=True, default=str))
        self._events.clear()


@contextmanager
def audited_transaction(engine: Engine) -> Iterator[AuditedTransaction]:
    """Run a management change; emit its audit events only if it commits."""
    with engine.begin() as connection:
        transaction = AuditedTransaction(connection)
        yield transaction
    transaction.emit()


__all__ = [
    "AUDIT_METADATA_MAX_BYTES",
    "Actor",
    "AuditedTransaction",
    "audited_transaction",
    "bound_metadata",
]
