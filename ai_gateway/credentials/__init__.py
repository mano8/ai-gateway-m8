"""
Credential store, KEK providers and envelope encryption.

The only package allowed to import ``ai_gateway.db_models.credential_version``;
``ruff.toml`` (TID251) enforces the boundary for every other module. Importing
this package registers the version table on the shared metadata.
"""

# TID251 is lifted here by this package's own ruff.toml; the inline noqa keeps
# analyzers that read only the root configuration in agreement.
from ai_gateway.db_models import credential_version as _credential_version  # noqa: F401, TID251
