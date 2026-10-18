"""Management routes — users authenticated by the issuer's JWT.

Each route declares its tier through the dependencies re-exported by
:mod:`ai_gateway.app.deps` (reader, writer, admin, superuser). No route is
defined yet.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/manage", tags=["management"])
