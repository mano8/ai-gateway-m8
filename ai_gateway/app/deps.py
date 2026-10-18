"""Re-export public dependencies consumed by route modules."""

__all__ = [
    "CurrentUser",
    "SessionDep",
    "get_current_active_reader",
    "get_current_active_writer",
    "get_current_active_admin",
    "get_current_active_superuser",
    "require_job_context",
]

from ai_gateway.core.deps import (
    CurrentUser as CurrentUser,
    SessionDep as SessionDep,
    get_current_active_admin as get_current_active_admin,
    get_current_active_reader as get_current_active_reader,
    get_current_active_superuser as get_current_active_superuser,
    get_current_active_writer as get_current_active_writer,
)
from ai_gateway.core.execution_guard import require_job_context as require_job_context
