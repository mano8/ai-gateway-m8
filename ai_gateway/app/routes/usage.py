"""
``GET /v1/usage`` — accounting aggregates for tenant admins and the superuser (T33).

* a tenant ``ADMIN`` sees only the ``tenant_id`` its token carries; naming
  another tenant answers ``404`` (a tenant's existence is never disclosed),
  and a token with no ``tenant_id`` sees nothing (an empty report);
* a superuser sees the platform, or one tenant with ``tenant_id``.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from ai_gateway.controllers.errors import NotFound
from ai_gateway.controllers.usage import MAX_DAYS, UsageReport, usage_report
from ai_gateway.core.deps import CurrentAdmin, db_engine
from fastapi_m8 import has_superuser_privileges

router = APIRouter(tags=["usage"])


@router.get("/usage", response_model=UsageReport)
def get_usage(
    user: CurrentAdmin,
    tenant_id: UUID | None = None,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = 30,
) -> UsageReport:
    """Admission units and provider usage per UTC day, as aggregates."""
    if has_superuser_privileges(user.role, user.is_superuser):
        scope = tenant_id
    elif user.tenant_id is None:
        return UsageReport(tenant_id=None, days=[])
    elif tenant_id is not None and tenant_id != user.tenant_id:
        raise NotFound("no such tenant")
    else:
        scope = user.tenant_id
    with db_engine.connect() as connection:
        return usage_report(connection, scope, days)
