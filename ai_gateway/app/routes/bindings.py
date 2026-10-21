"""
Binding routes for the three scopes (T18 global, T20a tenant and user, C-04).

The same rules hold in every scope: the model must carry the profile's
capability, and the credential must be one of the scope's own and of the
model's provider (or absent for a provider that takes none); a credential the
scope does not hold — another tenant's, another user's, or none — answers one
``422``, so a body can never probe another scope. ``on_unavailable`` defaults
to ``fail``; only the scope's own caller can set ``fall_through``, and a
global binding cannot. While ``AI_USER_BYOK_ENABLED`` is false a user cannot
create or change a binding; listing, reading and deleting stay open.
"""

from collections.abc import Callable
from uuid import UUID

from ai_sdk_m8.schemas.management import BindingCreate, BindingPublic, BindingUpdate
from fastapi import APIRouter, Depends, status

from ai_gateway.app.routes.callers import (
    Caller,
    global_caller,
    tenant_caller,
    user_caller,
)
from ai_gateway.controllers import bindings
from ai_gateway.controllers.audit import audited_transaction
from ai_gateway.core.deps import db_engine


def binding_router(prefix: str, caller: Callable[..., Caller]) -> APIRouter:
    """The binding routes of one scope base, for ``caller``'s scope."""
    router = APIRouter(prefix=prefix, tags=["bindings"])

    @router.get("/bindings", response_model=list[BindingPublic])
    def list_bindings(c: Caller = Depends(caller)) -> list[BindingPublic]:
        """The scope's bindings."""
        with db_engine.connect() as connection:
            return bindings.list_bindings(connection, c.scope)

    @router.post(
        "/bindings", response_model=BindingPublic, status_code=status.HTTP_201_CREATED
    )
    def create_binding(
        body: BindingCreate, c: Caller = Depends(caller)
    ) -> BindingPublic:
        """Bind a profile in the scope."""
        c.require_user_byok()
        with audited_transaction(db_engine) as tx:
            return bindings.create_binding(tx, c.actor, c.scope, body)

    @router.get("/bindings/{binding_id}", response_model=BindingPublic)
    def get_binding(binding_id: UUID, c: Caller = Depends(caller)) -> BindingPublic:
        """One binding."""
        with db_engine.connect() as connection:
            return bindings.get_binding(connection, c.scope, binding_id)

    @router.patch("/bindings/{binding_id}", response_model=BindingPublic)
    def update_binding(
        binding_id: UUID, body: BindingUpdate, c: Caller = Depends(caller)
    ) -> BindingPublic:
        """Repoint it, or change what it does when its credential fails."""
        c.require_user_byok()
        with audited_transaction(db_engine) as tx:
            return bindings.update_binding(tx, c.actor, c.scope, binding_id, body)

    @router.delete("/bindings/{binding_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_binding(binding_id: UUID, c: Caller = Depends(caller)) -> None:
        """Remove it; the scope then falls through to the next one."""
        with audited_transaction(db_engine) as tx:
            bindings.delete_binding(tx, c.actor, c.scope, binding_id)

    return router


#: Superuser: global bindings (included under ``v1/admin``).
global_router = binding_router("", global_caller)
#: Tenant ``ADMIN`` (or superuser): one tenant's bindings.
tenant_router = binding_router("/tenants/{tenant_id}", tenant_caller)
#: ``WRITER`` and above: the caller's own bindings.
user_router = binding_router("/me", user_caller)
