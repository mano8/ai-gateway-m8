"""``ai_credential_version`` is private to ``ai_gateway/credentials/`` (T21)."""

from __future__ import annotations

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "ai_gateway"

#: Where the table may be named: its own package, its schema and migrations.
ALLOWED = ("credentials", "db_models", "alembic")


def test_no_other_module_names_the_version_table() -> None:
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        relative = path.relative_to(PACKAGE)
        if relative.parts[0] in ALLOWED:
            continue
        text = path.read_text(encoding="utf-8")
        if re.search(r"\bai_credential_version\b|db_models\.credential_version", text):
            offenders.append(str(relative))
    assert offenders == []


def test_the_schema_names_it_only_as_a_foreign_key_target() -> None:
    for name in ("credentials.py", "artifacts.py"):
        text = (PACKAGE / "db_models" / name).read_text(encoding="utf-8")
        assert "import" not in "\n".join(
            line for line in text.splitlines() if "credential_version" in line
        )
