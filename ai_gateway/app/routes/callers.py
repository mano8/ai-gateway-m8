"""
Who calls a scoped management route, and in which scope (D-05, A-1).

A *caller* dependency fixes the tier and the scope from the route and the
token — never from a request body:

* :func:`global_caller` — the platform's own scope, superuser only;
* :func:`tenant_caller` — ``v1/tenants/{tenant_id}``: an ``ADMIN`` whose
  token carries that ``tenant_id``, or a superuser; anyone else gets the
  ``404`` a missing row gets, so a tenant's rows are never disclosed;
* :func:`user_caller` — ``v1/me``: the token's own user, in the token's
  tenant, at the ``WRITER`` tier and above on the fresh-revocation path.
"""

from dataclasses import dataclass
from uuid import UUID

from ai_sdk_m8.schemas.management import ScopeType

from ai_gateway.controllers.audit import Actor
from ai_gateway.controllers.errors import Forbidden, NotFound
from ai_gateway.controllers.scopes import GLOBAL, Scope
from ai_gateway.core.config import settings
from ai_gateway.core.deps import CurrentAdmin, CurrentSuperuser, CurrentWriter
from fastapi_m8 import UserModel, has_superuser_privileges


@dataclass(frozen=True)
class Caller:
    """Who calls and in which scope; the scope comes from the route and token."""

    scope: Scope
    actor: Actor

    @property
    def subject(self) -> str:
        """The JWT ``sub`` writes are rate-limited by."""
        return str(self.actor.id)

    def require_user_byok(self) -> None:
        """Refuse a user-scope write that adds or re-activates a key (Q6, A-3)."""
        if self.scope.scope_type is ScopeType.USER and not settings.user_byok_enabled:
            raise Forbidden(
                "user-scoped keys and bindings are disabled in this deployment"
            )


def global_caller(user: CurrentSuperuser) -> Caller:
    """The platform's own scope."""
    return Caller(GLOBAL, Actor.of_user(user))


def _is_superuser(user: UserModel) -> bool:
    return has_superuser_privileges(user.role, user.is_superuser)


def tenant_caller(tenant_id: UUID, user: CurrentAdmin) -> Caller:
    """A matching-tenant ``ADMIN``, or a superuser; anyone else gets 404."""
    if not _is_superuser(user) and (
        user.tenant_id is None or user.tenant_id != tenant_id
    ):
        raise NotFound("no such credential")
    return Caller(Scope(ScopeType.TENANT, tenant_id=tenant_id), Actor.of_user(user))


def user_caller(user: CurrentWriter) -> Caller:
    """The token's own user, in the token's tenant (A-1)."""
    scope = Scope(ScopeType.USER, tenant_id=user.tenant_id, owner_user_id=user.id)
    return Caller(scope, Actor.of_user(user))


__all__ = ["Caller", "global_caller", "tenant_caller", "user_caller"]
