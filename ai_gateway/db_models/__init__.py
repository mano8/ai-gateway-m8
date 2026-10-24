"""
The gateway's tables (``ai_db``, D-04), defined on SQLModel's metadata.

Importing this package registers every table except the credential versions,
which only ``ai_gateway/credentials/`` may import (``ruff`` ``TID251``); that
package registers them. Alembic's environment imports both.
"""

from . import accounting, artifacts, audit, credentials, installation, registry
from ._common import TERMINAL_STATUSES, ExecutionStatus, metadata

__all__ = [
    "TERMINAL_STATUSES",
    "ExecutionStatus",
    "accounting",
    "artifacts",
    "audit",
    "credentials",
    "installation",
    "metadata",
    "registry",
]
