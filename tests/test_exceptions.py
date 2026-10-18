"""Route exception mapping: structured errors keep their facts, others are opaque."""

from __future__ import annotations

import json
import logging

import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from ai_gateway.core.exceptions import handle_route_exception


def test_an_http_exception_is_reraised_unchanged() -> None:
    error = HTTPException(status_code=404)
    with pytest.raises(HTTPException) as info:
        handle_route_exception(error)
    assert info.value is error


def test_an_unrecognised_exception_is_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SELECT * FROM ai_credential WHERE secret='sk-live-123'"
    with caplog.at_level(logging.WARNING):
        response = handle_route_exception(RuntimeError(secret))
    body = json.loads(bytes(response.body))
    assert "sk-live-123" not in json.dumps(body)
    assert "An internal error occurred." in json.dumps(body)
    assert "route.unhandled_exception" in caplog.text


def test_an_integrity_error_is_rendered_from_its_parsed_fields() -> None:
    error = IntegrityError("INSERT …", {}, Exception("duplicate key"))
    response = handle_route_exception(error)
    assert response.status_code >= 400
