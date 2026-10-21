"""
The scope a management request acts in (D-05, R-08, C-04).

A scope is taken from the route and the token, never from a request body:

* global — the platform's own rows, superuser only;
* tenant — ``tenant_id`` from the path, which a tenant ``ADMIN``'s token
  must carry (a superuser may name any tenant);
* user — ``owner_user_id`` is the token's ``sub`` and ``tenant_id`` the
  token's ``tenant_id``, so a user's rows serve that user in that tenant only.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import sqlalchemy as sa
from ai_sdk_m8.schemas.management import ScopeType


@dataclass(frozen=True)
class Scope:
    """One scope; ``where`` selects exactly its rows of a scoped table."""

    scope_type: ScopeType
    tenant_id: uuid.UUID | None = None
    owner_user_id: uuid.UUID | None = None

    def where(self, table: sa.Table) -> sa.ColumnElement[bool]:
        """Rows of ``table`` in exactly this scope."""
        return sa.and_(
            table.c.scope_type == self.scope_type.value,
            table.c.tenant_id.is_not_distinct_from(self.tenant_id),
            table.c.owner_user_id.is_not_distinct_from(self.owner_user_id),
        )

    def audit(self) -> dict[str, object]:
        """The scope as audit metadata."""
        return {
            "scope_type": self.scope_type.value,
            "tenant_id": self.tenant_id,
            "owner_user_id": self.owner_user_id,
        }

    def lock_key(self) -> str:
        """The advisory-lock key that serializes writes counted per scope."""
        return f"ai-scope:{self.scope_type.value}:{self.tenant_id}:{self.owner_user_id}"


#: The platform's own scope.
GLOBAL = Scope(ScopeType.GLOBAL)


__all__ = ["GLOBAL", "Scope"]
