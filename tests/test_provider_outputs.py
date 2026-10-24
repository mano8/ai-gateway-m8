"""
The output validator every adapter result passes (T26, §6.2 *Provider outputs*).

A provider answer is untrusted: wrong counts, wrong dimensions, non-finite
numbers, out-of-range or repeated rerank indexes and unrequested OCR pages
are all ``provider_rejected``, with nothing partial returned.
"""

from __future__ import annotations

import pytest
from ai_sdk_m8.schemas import AiErrorCode, OcrPage, RerankHit
from ai_sdk_m8.schemas.errors import ProviderStatusClass

from ai_gateway.providers import outputs
from ai_gateway.providers.errors import ProviderFailure


def rejects(fn: object, *args: object, **kwargs: object) -> None:
    with pytest.raises(ProviderFailure) as caught:
        fn(*args, **kwargs)  # type: ignore[operator]
    assert caught.value.code is AiErrorCode.PROVIDER_REJECTED
    assert caught.value.status_class is ProviderStatusClass.SUCCESS


def test_embeddings_one_finite_vector_per_input() -> None:
    vectors = outputs.embeddings([[0.5, 1], [2, -3.25]], count=2, dimensions=2)
    assert vectors == ((0.5, 1.0), (2.0, -3.25))
    assert all(isinstance(c, float) for vector in vectors for c in vector)


@pytest.mark.parametrize(
    "vectors",
    [
        [[0.1, 0.2]],  # one vector for two inputs
        [[0.1, 0.2], [0.3, 0.4], [0.5, 0.6]],  # three
        [[0.1, 0.2], [0.3]],  # wrong dimension
        [[0.1, float("nan")], [0.3, 0.4]],
        [[0.1, float("inf")], [0.3, 0.4]],
        [[0.1, -float("inf")], [0.3, 0.4]],
        [[True, 0.2], [0.3, 0.4]],
        [["0.1", 0.2], [0.3, 0.4]],
        [[None, 0.2], [0.3, 0.4]],
        [{"a": 1}, [0.3, 0.4]],
        "not a list",
        None,
    ],
)
def test_bad_embeddings_are_rejected(vectors: object) -> None:
    rejects(outputs.embeddings, vectors, count=2, dimensions=2)


def test_rerank_hits_keep_order_and_validated_scores() -> None:
    result = outputs.rerank([(2, 0.9), (0, 0.4), (1, -1)], candidates=3)
    assert result.hits == (
        RerankHit(index=2, relevance_score=0.9),
        RerankHit(index=0, relevance_score=0.4),
        RerankHit(index=1, relevance_score=-1.0),
    )
    assert outputs.rerank([], candidates=3).hits == ()
    assert len(outputs.rerank([(0, 1.0)], candidates=3, top_n=1).hits) == 1


@pytest.mark.parametrize(
    ("hits", "top_n"),
    [
        ([(3, 0.1)], None),  # out of range
        ([(-1, 0.1)], None),
        ([(0, 0.1), (0, 0.2)], None),  # duplicate
        ([(None, 0.1)], None),  # missing index
        ([(True, 0.1)], None),
        ([("1", 0.1)], None),
        ([(0, float("nan"))], None),
        ([(0, float("inf"))], None),
        ([(0, None)], None),
        ([(0, 0.1), (1, 0.2), (2, 0.3), (1, 0.1)], None),  # more hits than candidates
        ([(0, 0.1), (1, 0.2)], 1),  # more than top_n
    ],
)
def test_bad_rerank_hits_are_rejected(
    hits: list[tuple[object, object]], top_n: int | None
) -> None:
    rejects(outputs.rerank, hits, candidates=3, top_n=top_n)


def page(index: int) -> OcrPage:
    return OcrPage(index=index, width_px=10, height_px=10, markdown="x")


def test_ocr_pages_within_the_reserved_list() -> None:
    pages = (page(0), page(2))
    assert outputs.ocr_pages(pages, requested=[0, 1, 2]) == pages


@pytest.mark.parametrize(
    "pages",
    [
        (),
        (page(0), page(1), page(2), page(3)),  # more than reserved
        (page(5),),  # never requested
        (page(2), page(1)),  # out of order
        (page(1), page(1)),
    ],
)
def test_ocr_pages_beyond_the_reservation_are_rejected(
    pages: tuple[OcrPage, ...],
) -> None:
    rejects(outputs.ocr_pages, pages, requested=[0, 1, 2])


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (12, 12),
        (0, 0),
        (-1, None),
        (True, None),
        ("3", None),
        (2**53, None),
        (None, None),
    ],
)
def test_reported_counts_are_kept_only_when_sane(
    value: object, expected: int | None
) -> None:
    assert outputs.bounded_count(value) == expected
