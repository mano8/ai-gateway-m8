"""
Management routes — users authenticated by the issuer's JWT (D-05).

Each route declares its tier through the dependencies re-exported by
:mod:`ai_gateway.app.deps` (reader, writer, admin, superuser), all on the
fresh-revocation path; no route accepts an API-key principal. Paths are the
``ai-sdk-m8`` route table's, under ``v1``:

* ``v1/admin/…`` — providers, models, profiles and global bindings,
  superuser only (``T18``);
* ``v1/profiles`` — the published profiles, for readers and for
  ``profiles:read`` service clients (``T18``);
* ``v1/admin/credentials``, ``v1/tenants/{tenant_id}/credentials`` and
  ``v1/me/credentials`` — credentials per scope, and the superuser's
  ``v1/admin/user-credentials`` stop (``T20``);
* ``v1/admin/bindings``, ``v1/tenants/{tenant_id}/bindings`` and
  ``v1/me/bindings`` — bindings per scope (``T18``, ``T20a``).
"""

from fastapi import APIRouter

from ai_gateway.app.routes import admin, bindings, credentials, profiles

router = APIRouter(prefix="/v1")
router.include_router(admin.router)
router.include_router(credentials.tenant_router)
router.include_router(credentials.user_router)
router.include_router(bindings.tenant_router)
router.include_router(bindings.user_router)
# The service-client variant must be tried before the reader one.
router.include_router(profiles.service_router)
router.include_router(profiles.router)
