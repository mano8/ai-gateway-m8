"""SECURITY.md cites real tests, and every control section cites one or says where it is proven."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECURITY = ROOT / "SECURITY.md"
TESTS = ROOT / "tests"

#: A cited test: ``test_<file>.py::test_<name>``.
_CITATION = re.compile(r"`(test_\w+\.py)::(test_\w+)`")

#: How a section whose proof lives in another repository or a deployed stack
#: says where it is proven, instead of citing a test here.
_PROVEN_ELSEWHERE = "Proven outside this repository:"


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _control_sections(text: str) -> dict[str, str]:
    """The ``###`` sections of ``## Controls``, by heading."""
    controls = text.split("\n## Controls\n", 1)[1].split("\n## ", 1)[0]
    sections: dict[str, str] = {}
    for chunk in controls.split("\n### ")[1:]:
        heading, _, body = chunk.partition("\n")
        sections[heading] = body
    return sections


def test_every_cited_test_exists() -> None:
    citations = _CITATION.findall(SECURITY.read_text(encoding="utf-8"))
    assert citations
    missing = [
        f"{file}::{name}"
        for file, name in citations
        if not (TESTS / file).is_file() or name not in _test_names(TESTS / file)
    ]
    assert not missing


def test_every_control_section_cites_a_test_or_where_it_is_proven() -> None:
    sections = _control_sections(SECURITY.read_text(encoding="utf-8"))
    assert sections
    uncited = [
        heading
        for heading, body in sections.items()
        if not _CITATION.search(body) and _PROVEN_ELSEWHERE not in body
    ]
    assert not uncited
