"""Re-export public dependencies consumed by route modules."""

__all__ = [
    "CurrentAdmin",
    "CurrentReader",
    "CurrentSuperuser",
    "CurrentUser",
    "CurrentWriter",
    "JobContextDep",
    "SessionDep",
    "get_current_active_reader",
    "get_current_active_writer",
    "get_current_active_admin",
    "get_current_active_superuser",
    "require_job_context",
    "require_superuser",
]

from ai_gateway.core.deps import (
    CurrentAdmin as CurrentAdmin,
    CurrentReader as CurrentReader,
    CurrentSuperuser as CurrentSuperuser,
    CurrentUser as CurrentUser,
    CurrentWriter as CurrentWriter,
    SessionDep as SessionDep,
    get_current_active_admin as get_current_active_admin,
    get_current_active_reader as get_current_active_reader,
    get_current_active_superuser as get_current_active_superuser,
    get_current_active_writer as get_current_active_writer,
    require_superuser as require_superuser,
)
from ai_gateway.core.execution_guard import (
    JobContextDep as JobContextDep,
    require_job_context as require_job_context,
)
