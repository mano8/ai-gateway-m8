"""
Build-once site for auth and database dependencies.

Import ``auth``, ``engine``, the tier dependencies and ``SessionDep`` from here.
Never call ``build_auth_deps`` or ``create_db_engine`` a second time.

User authentication applies to management routes only. Execution routes depend
on :mod:`ai_gateway.core.execution_guard` instead and never accept a user JWT.
No API-key principal is wired: no gateway route accepts one.
"""

from typing import Annotated

from fastapi import Depends
from sqlmodel import Session

from fastapi_m8 import AuthDeps, DbEngine, build_auth_deps, create_db_engine

from .clock import ClockSkewMonitor
from .config import settings
from .utc_session import pin_utc_session

# Single instances shared across the entire process.
auth: AuthDeps = build_auth_deps(settings)
engine: DbEngine = create_db_engine(settings)
# Every PostgreSQL session this engine opens runs in UTC.
pin_utc_session(engine._engine)
# Application–database clock skew, checked by /health and every execution.
clock = ClockSkewMonitor(lambda: engine._engine, settings.AI_MAX_CLOCK_SKEW_SECONDS)

CurrentUser = auth.CurrentUser
get_current_user = auth.get_current_user
get_current_active_reader = auth.get_current_active_reader
get_current_active_writer = auth.get_current_active_writer
get_current_active_admin = auth.get_current_active_admin
get_current_active_superuser = auth.get_current_active_superuser
get_db = engine.session_dep
SessionDep = Annotated[Session, Depends(get_db)]
