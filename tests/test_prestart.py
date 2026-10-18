"""D-04 run-mode checks: database wait and the read-only revision check."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.pool import StaticPool

from ai_gateway import prestart, scheduler
from ai_gateway.core import deps

REVISION = """revision = "{rev}"
down_revision = {down}
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
"""


def _engine(*revisions: str) -> Engine:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    if revisions:
        with engine.begin() as connection:
            connection.execute(
                text(f"CREATE TABLE {prestart.VERSION_TABLE} (version_num TEXT)")
            )
            for revision in revisions:
                connection.execute(
                    text(f"INSERT INTO {prestart.VERSION_TABLE} VALUES (:r)"),
                    {"r": revision},
                )
    return engine


def _ini(tmp_path: Path, *revisions: tuple[str, str | None]) -> Path:
    versions = tmp_path / "alembic" / "versions"
    versions.mkdir(parents=True)
    script = Path(prestart.__file__).parent / "alembic" / "script.py.mako"
    (tmp_path / "alembic" / "script.py.mako").write_bytes(script.read_bytes())
    for rev, down in revisions:
        (versions / f"{rev}.py").write_text(
            REVISION.format(rev=rev, down=repr(down)), encoding="utf-8"
        )
    ini = tmp_path / "alembic.ini"
    ini.write_text(
        "[alembic]\n"
        "script_location = %(here)s/alembic\n"
        "version_locations = %(here)s/alembic/versions\n",
        encoding="utf-8",
    )
    return ini


def test_the_packaged_scripts_have_no_head_yet() -> None:
    assert prestart.packaged_head() is None


def test_the_packaged_version_table_is_the_gateways_own() -> None:
    ini = prestart.ALEMBIC_INI.read_text(encoding="utf-8")
    assert "version_table = alembic_version_ai" in ini


def test_a_single_head_is_found(tmp_path: Path) -> None:
    ini = _ini(tmp_path, ("aaa111", None), ("bbb222", "aaa111"))
    assert prestart.packaged_head(ini) == "bbb222"


def test_two_heads_are_refused(tmp_path: Path) -> None:
    ini = _ini(tmp_path, ("aaa111", None), ("bbb222", None))
    with pytest.raises(RuntimeError, match="more than one head"):
        prestart.packaged_head(ini)


def test_an_absent_or_empty_version_table_reads_as_none() -> None:
    assert prestart.database_revision(_engine()) is None
    empty = _engine("x")
    with empty.begin() as connection:
        connection.execute(text(f"DELETE FROM {prestart.VERSION_TABLE}"))
    assert prestart.database_revision(empty) is None


def test_two_recorded_revisions_are_refused() -> None:
    with pytest.raises(RuntimeError, match="more than one revision"):
        prestart.database_revision(_engine("a", "b"))


@pytest.mark.parametrize(
    ("recorded", "head", "ok"),
    [
        ((), None, True),
        (("bbb222",), "bbb222", True),
        (("aaa111",), "bbb222", False),
        (("ccc333",), None, False),
        ((), "bbb222", False),
    ],
)
def test_the_revision_must_equal_the_packaged_head(
    recorded: tuple[str, ...], head: str | None, ok: bool
) -> None:
    assert prestart.check_schema_revision(_engine(*recorded), head) is ok


def test_main_exits_on_a_mismatched_database(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(deps.engine, "_engine", _engine("deadbeef"))
    with caplog.at_level(logging.ERROR):
        assert prestart.main() == 1
    assert "ai-migrate" in caplog.text


def test_main_passes_on_a_matching_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deps.engine, "_engine", _engine())
    assert prestart.main() == 0


def test_the_revision_check_writes_nothing() -> None:
    engine = _engine()
    prestart.check_schema_revision(engine, None)
    assert prestart.database_revision(engine) is None
    with engine.connect() as connection:
        tables = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).all()
    assert tables == []


def test_the_scheduler_refuses_to_run() -> None:
    assert scheduler.main() == 1
