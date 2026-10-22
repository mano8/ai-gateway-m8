"""
The output validator every adapter result passes before settlement (D-20).

A provider answer is untrusted input (LLM05): an adapter only extracts the
values, and the execution core runs them through these checks before it
settles the call or returns anything. A failed check is
``provider_rejected``; nothing partial is returned.

* embeddings: exactly one vector per input, each of the model's declared
  dimensions (another dimension is also an audited incident), every
  component a finite number (``NaN``, ``inf`` and booleans refused);
* rerank: each hit's index an integer inside the candidate list, at most
  once, its score finite, no more hits than candidates (or ``top_n``);
* OCR: at most the pages the gateway reserved and requested, each one of
  them, in increasing order.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Final

from ai_sdk_m8.schemas import AiErrorCode, OcrPage, RerankHit, RerankResult
from ai_sdk_m8.schemas.errors import ProviderStatusClass

from .errors import Incident, ProviderFailure

#: A raw hit as an adapter extracted it: (index, score), either possibly bad.
RawHit = tuple[object, object]

_JCS_INT_MAX: Final = 2**53 - 1


def rejected() -> ProviderFailure:
    """The one refusal of an answer that failed validation."""
    return ProviderFailure(
        AiErrorCode.PROVIDER_REJECTED, status_class=ProviderStatusClass.SUCCESS
    )


def _finite(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise rejected()
    number = float(value)
    if not math.isfinite(number):
        raise rejected()
    return number


def embeddings(
    vectors: object, *, count: int, dimensions: int
) -> tuple[tuple[float, ...], ...]:
    """One finite vector of ``dimensions`` per input, in input order."""
    if not isinstance(vectors, list | tuple) or len(vectors) != count:
        raise rejected()
    checked: list[tuple[float, ...]] = []
    for vector in vectors:
        if not isinstance(vector, list | tuple):
            raise rejected()
        if len(vector) != dimensions:
            # The provider serves another model than the one registered.
            raise ProviderFailure(
                AiErrorCode.PROVIDER_REJECTED,
                status_class=ProviderStatusClass.SUCCESS,
                incident=Incident.DIMENSION_MISMATCH,
            )
        checked.append(tuple(_finite(component) for component in vector))
    return tuple(checked)


def _index(value: object, candidates: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise rejected()
    if not 0 <= value < candidates:
        raise rejected()
    return value


def rerank(
    hits: Sequence[RawHit], *, candidates: int, top_n: int | None = None
) -> RerankResult:
    """Hits with in-range, unique indexes and finite scores, at most ``top_n``."""
    limit = candidates if top_n is None else min(top_n, candidates)
    if len(hits) > limit:
        raise rejected()
    seen: set[int] = set()
    checked: list[RerankHit] = []
    for raw_index, raw_score in hits:
        index = _index(raw_index, candidates)
        if index in seen:
            raise rejected()
        seen.add(index)
        checked.append(RerankHit(index=index, relevance_score=_finite(raw_score)))
    return RerankResult(hits=tuple(checked))


def ocr_pages(
    pages: Sequence[OcrPage], *, requested: Sequence[int]
) -> tuple[OcrPage, ...]:
    """At most the reserved pages, each a requested one, in increasing order."""
    allowed = set(requested)
    if not pages or len(pages) > len(allowed):
        raise rejected()
    previous = -1
    for page in pages:
        if page.index not in allowed or page.index <= previous:
            raise rejected()
        previous = page.index
    return tuple(pages)


def bounded_count(value: object) -> int | None:
    """A provider-reported count, kept only when it is a sane integer."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if not 0 <= value <= _JCS_INT_MAX:
        return None
    return value


__all__ = ["RawHit", "bounded_count", "embeddings", "ocr_pages", "rejected", "rerank"]
