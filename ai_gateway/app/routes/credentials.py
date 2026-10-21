"""
Credential routes for the three scopes (T20, D-05 with A-1 and A-2).

One router factory serves each scope base of the ``ai-sdk-m8`` route table;
a *caller* dependency fixes the tier and the scope, never from the body:

* ``v1/admin`` — the platform's own credentials, superuser only;
* ``v1/tenants/{tenant_id}`` — a tenant ``ADMIN`` whose token carries that
  ``tenant_id``, or a superuser; any other caller gets ``404``, the answer a
  missing credential gets, so a tenant's existence is never disclosed;
* ``v1/me`` — the token's own user (``owner_user_id = sub``, ``tenant_id`` the
  token's), at the ``WRITER`` tier and above (A-1) on the fresh-revocation
  path. While ``AI_USER_BYOK_ENABLED`` is false, creating, rotating,
  enabling and re-confirming a user credential answer ``403``; listing,
  reading, renaming, disabling and deleting one stay open.

The superuser's only action on a user's credential is ``A-2``'s stop under
``v1/admin/user-credentials``: list one user's credentials (metadata only),
disable one, delete one — no route creates, rotates, validates, re-enables or
binds one on the owner's behalf. Creates and rotations are rate-limited per
JWT ``sub``.
"""

# No ``from __future__ import annotations`` here: the routes are built inside
# a factory, and FastAPI resolves a postponed annotation against the module
# globals, where the factory's local ``CallerDep`` does not exist. The route
# would then lose its caller dependency.
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from ai_sdk_m8.schemas.management import (
    CredentialCreate,
    CredentialPublic,
    CredentialRotate,
    CredentialUpdate,
    RemoteArtifactPublic,
    ScopeType,
)
from fastapi import APIRouter, Depends, Query, status

from ai_gateway.controllers import credentials
from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.controllers.errors import Forbidden, NotFound
from ai_gateway.controllers.ratelimit import charge_credential_write
from ai_gateway.controllers.scopes import GLOBAL, Scope
from ai_gateway.core.config import settings
from ai_gateway.core.deps import (
    CurrentAdmin,
    CurrentSuperuser,
    CurrentWriter,
    credential_store,
    db_engine,
)
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
            raise Forbidden("user-scoped credentials are disabled in this deployment")


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


def credential_router(prefix: str, caller: Callable[..., Caller]) -> APIRouter:
    """The credential routes of one scope base, for ``caller``'s scope."""
    router = APIRouter(prefix=prefix, tags=["credentials"])
    _read_routes(router, caller)
    _write_routes(router, caller)
    _status_routes(router, caller)
    return router


def _read_routes(router: APIRouter, caller: Callable[..., Caller]) -> None:
    @router.get("/credentials", response_model=list[CredentialPublic])
    def list_credentials(c: Caller = Depends(caller)) -> list[CredentialPublic]:
        """The scope's credentials."""
        with db_engine.connect() as connection:
            return credentials.list_credentials(connection, c.scope)

    @router.get("/credentials/{credential_id}", response_model=CredentialPublic)
    def get_credential(
        credential_id: UUID, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """One credential."""
        with db_engine.connect() as connection:
            return credentials.get_credential(connection, c.scope, credential_id)

    @router.get(
        "/credentials/{credential_id}/remote-artifacts",
        response_model=list[RemoteArtifactPublic],
    )
    def list_remote_artifacts(
        credential_id: UUID, c: Caller = Depends(caller)
    ) -> list[RemoteArtifactPublic]:
        """Provider-side files under it: ids and status, never content."""
        with db_engine.connect() as connection:
            return credentials.list_remote_artifacts(connection, c.scope, credential_id)


def _write_routes(router: APIRouter, caller: Callable[..., Caller]) -> None:
    @router.post(
        "/credentials",
        response_model=CredentialPublic,
        status_code=status.HTTP_201_CREATED,
    )
    def create_credential(
        body: CredentialCreate, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Store a credential."""
        c.require_user_byok()
        charge_credential_write(db_engine, c.subject)
        with audited_transaction(db_engine) as tx:
            return credentials.create_credential(
                tx,
                c.actor,
                c.scope,
                body,
                credential_store,
                settings.AI_MAX_CREDENTIALS_PER_SCOPE,
            )

    @router.patch("/credentials/{credential_id}", response_model=CredentialPublic)
    def update_credential(
        credential_id: UUID, body: CredentialUpdate, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Rename it or change its incident-listing consent."""
        with audited_transaction(db_engine) as tx:
            return credentials.update_credential(
                tx, c.actor, c.scope, credential_id, body
            )

    @router.post("/credentials/{credential_id}:rotate", response_model=CredentialPublic)
    def rotate_credential(
        credential_id: UUID, body: CredentialRotate, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Store a new current version."""
        c.require_user_byok()
        charge_credential_write(db_engine, c.subject)
        with audited_transaction(db_engine) as tx:
            return credentials.rotate_credential(
                tx, c.actor, c.scope, credential_id, body, credential_store
            )


def _status_routes(router: APIRouter, caller: Callable[..., Caller]) -> None:
    @router.post(
        "/credentials/{credential_id}:disable", response_model=CredentialPublic
    )
    def disable_credential(
        credential_id: UUID, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Disable it; its bindings become unavailable."""
        with audited_transaction(db_engine) as tx:
            return credentials.disable_credential(
                tx, c.actor, credentials.in_scope(c.scope, credential_id)
            )

    @router.post("/credentials/{credential_id}:enable", response_model=CredentialPublic)
    def enable_credential(
        credential_id: UUID, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Re-enable a disabled credential."""
        c.require_user_byok()
        with audited_transaction(db_engine) as tx:
            return credentials.enable_credential(tx, c.actor, c.scope, credential_id)

    @router.post(
        "/credentials/{credential_id}:reconfirm", response_model=CredentialPublic
    )
    def reconfirm_credential(
        credential_id: UUID, c: Caller = Depends(caller)
    ) -> CredentialPublic:
        """Re-confirm it after a restore."""
        c.require_user_byok()
        with audited_transaction(db_engine) as tx:
            return credentials.reconfirm_credential(tx, c.actor, c.scope, credential_id)

    @router.delete(
        "/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT
    )
    def delete_credential(credential_id: UUID, c: Caller = Depends(caller)) -> None:
        """Delete it (logical while a provider file needs it)."""
        with audited_transaction(db_engine) as tx:
            credentials.delete_credential(
                tx,
                c.actor,
                credentials.in_scope(c.scope, credential_id),
                credential_store,
            )


#: Superuser: the platform's own credentials (included under ``v1/admin``).
global_router = credential_router("", global_caller)
#: Tenant ``ADMIN`` (or superuser): one tenant's credentials.
tenant_router = credential_router("/tenants/{tenant_id}", tenant_caller)
#: ``WRITER`` and above: the caller's own credentials.
user_router = credential_router("/me", user_caller)

#: Superuser: the user-scope stop (A-2), under ``v1/admin``.
user_stop_router = APIRouter(prefix="/user-credentials", tags=["credentials"])
SuperuserCaller = Annotated[Caller, Depends(global_caller)]


@user_stop_router.get("", response_model=list[CredentialPublic])
def list_user_credentials(
    owner_user_id: Annotated[UUID, Query()], _c: SuperuserCaller
) -> list[CredentialPublic]:
    """One user's credentials, metadata only."""
    with db_engine.connect() as connection:
        return credentials.list_user_credentials(connection, owner_user_id)


@user_stop_router.post("/{credential_id}:disable", response_model=CredentialPublic)
def disable_user_credential(
    credential_id: UUID, c: SuperuserCaller
) -> CredentialPublic:
    """Disable a user's credential; the owner's bindings become unavailable."""
    with audited_transaction(db_engine) as tx:
        return credentials.disable_credential(
            tx, c.actor, credentials.user_credential(credential_id)
        )


@user_stop_router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user_credential(credential_id: UUID, c: SuperuserCaller) -> None:
    """Delete a user's credential."""
    with audited_transaction(db_engine) as tx:
        credentials.delete_credential(
            tx, c.actor, credentials.user_credential(credential_id), credential_store
        )
