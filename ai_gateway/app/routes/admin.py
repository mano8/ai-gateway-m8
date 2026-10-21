"""
Superuser management: providers, models, profiles and global bindings (T18).

Every route requires the canonical superuser (``SUPERADMIN`` and
``is_superuser``, D-05) on the fresh-revocation path; every write is audited
(S-11). Paths and bodies are the ``ai-sdk-m8`` route table's and wire models.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from ai_sdk_m8.schemas._base import ProfileKey
from ai_sdk_m8.schemas.management import (
    BindingCreate,
    BindingPublic,
    BindingUpdate,
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
)
from fastapi import APIRouter, Depends, Path, status

from ai_gateway.app.routes.credentials import global_router, user_stop_router
from ai_gateway.controllers import bindings, registry
from ai_gateway.controllers.audit import Actor, audited_transaction
from ai_gateway.core.deps import (
    CurrentSuperuser,
    db_engine,
    destination_policy,
    require_superuser,
)

router = APIRouter(
    prefix="/admin", tags=["admin"], dependencies=[Depends(require_superuser)]
)

ProfileKeyPath = Annotated[ProfileKey, Path()]

# The platform's own credentials and the user-scope stop (T20).
router.include_router(global_router)
router.include_router(user_stop_router)


# --- providers -----------------------------------------------------------------


@router.get("/providers", response_model=list[ProviderAdmin])
def list_providers() -> list[ProviderAdmin]:
    """Every provider."""
    with db_engine.connect() as connection:
        return registry.list_providers(connection)


@router.post(
    "/providers", response_model=ProviderAdmin, status_code=status.HTTP_201_CREATED
)
def create_provider(body: ProviderCreate, user: CurrentSuperuser) -> ProviderAdmin:
    """Register a provider endpoint."""
    with audited_transaction(db_engine) as tx:
        return registry.create_provider(
            tx, Actor.of_user(user), body, destination_policy
        )


@router.get("/providers/{provider_id}", response_model=ProviderAdmin)
def get_provider(provider_id: UUID) -> ProviderAdmin:
    """One provider."""
    with db_engine.connect() as connection:
        return registry.get_provider(connection, provider_id)


@router.patch("/providers/{provider_id}", response_model=ProviderAdmin)
def update_provider(
    provider_id: UUID, body: ProviderUpdate, user: CurrentSuperuser
) -> ProviderAdmin:
    """Change a provider."""
    with audited_transaction(db_engine) as tx:
        return registry.update_provider(
            tx, Actor.of_user(user), provider_id, body, destination_policy
        )


# --- models --------------------------------------------------------------------


@router.get("/models", response_model=list[ModelAdmin])
def list_models() -> list[ModelAdmin]:
    """Every model."""
    with db_engine.connect() as connection:
        return registry.list_models(connection)


@router.post("/models", response_model=ModelAdmin, status_code=status.HTTP_201_CREATED)
def create_model(body: ModelCreate, user: CurrentSuperuser) -> ModelAdmin:
    """Register a model."""
    with audited_transaction(db_engine) as tx:
        return registry.create_model(tx, Actor.of_user(user), body)


@router.get("/models/{model_id}", response_model=ModelAdmin)
def get_model(model_id: UUID) -> ModelAdmin:
    """One model."""
    with db_engine.connect() as connection:
        return registry.get_model(connection, model_id)


@router.patch("/models/{model_id}", response_model=ModelAdmin)
def update_model(
    model_id: UUID, body: ModelUpdate, user: CurrentSuperuser
) -> ModelAdmin:
    """Change a model."""
    with audited_transaction(db_engine) as tx:
        return registry.update_model(tx, Actor.of_user(user), model_id, body)


# --- profiles ------------------------------------------------------------------


@router.get("/profiles", response_model=list[ProfileAdmin])
def list_profiles() -> list[ProfileAdmin]:
    """Every profile, published or not."""
    with db_engine.connect() as connection:
        return registry.list_profiles(connection)


@router.post(
    "/profiles", response_model=ProfileAdmin, status_code=status.HTTP_201_CREATED
)
def create_profile(body: ProfileCreate, user: CurrentSuperuser) -> ProfileAdmin:
    """Create a profile and its first revision."""
    with audited_transaction(db_engine) as tx:
        return registry.create_profile(tx, Actor.of_user(user), body)


@router.get("/profiles/{profile_key}", response_model=ProfileAdmin)
def get_profile(profile_key: ProfileKeyPath) -> ProfileAdmin:
    """One profile with its current revision."""
    with db_engine.connect() as connection:
        return registry.get_profile(connection, profile_key)


@router.patch("/profiles/{profile_key}", response_model=ProfileAdmin)
def update_profile(
    profile_key: ProfileKeyPath, body: ProfileUpdate, user: CurrentSuperuser
) -> ProfileAdmin:
    """Change a profile; a new configuration is a new revision."""
    with audited_transaction(db_engine) as tx:
        return registry.update_profile(tx, Actor.of_user(user), profile_key, body)


@router.get(
    "/profiles/{profile_key}/revisions", response_model=list[ProfileRevisionAdmin]
)
def list_revisions(profile_key: ProfileKeyPath) -> list[ProfileRevisionAdmin]:
    """Every revision of a profile."""
    with db_engine.connect() as connection:
        return registry.list_revisions(connection, profile_key)


# --- global bindings -----------------------------------------------------------


@router.get("/bindings", response_model=list[BindingPublic])
def list_bindings() -> list[BindingPublic]:
    """Every global binding."""
    with db_engine.connect() as connection:
        return bindings.list_bindings(connection, bindings.GLOBAL)


@router.post(
    "/bindings", response_model=BindingPublic, status_code=status.HTTP_201_CREATED
)
def create_binding(body: BindingCreate, user: CurrentSuperuser) -> BindingPublic:
    """Bind a profile globally."""
    with audited_transaction(db_engine) as tx:
        return bindings.create_binding(tx, Actor.of_user(user), bindings.GLOBAL, body)


@router.get("/bindings/{binding_id}", response_model=BindingPublic)
def get_binding(binding_id: UUID) -> BindingPublic:
    """One global binding."""
    with db_engine.connect() as connection:
        return bindings.get_binding(connection, bindings.GLOBAL, binding_id)


@router.patch("/bindings/{binding_id}", response_model=BindingPublic)
def update_binding(
    binding_id: UUID, body: BindingUpdate, user: CurrentSuperuser
) -> BindingPublic:
    """Change a global binding."""
    with audited_transaction(db_engine) as tx:
        return bindings.update_binding(
            tx, Actor.of_user(user), bindings.GLOBAL, binding_id, body
        )


@router.delete("/bindings/{binding_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_binding(binding_id: UUID, user: CurrentSuperuser) -> None:
    """Remove a global binding."""
    with audited_transaction(db_engine) as tx:
        bindings.delete_binding(tx, Actor.of_user(user), bindings.GLOBAL, binding_id)
