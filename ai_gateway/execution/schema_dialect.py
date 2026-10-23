"""
The closed JSON-Schema dialect of structured output (``T31``, D-17, D-18).

A request's ``json_schema`` is accepted only when every node uses the D-18
keyword set — ``type`` (one of ``string``, ``number``, ``integer``,
``boolean``, ``array``, ``object``), ``enum``, ``required``, ``minimum``,
``maximum``, ``minLength``, ``maxLength``, ``format`` (``date``,
``date-time``, ``uri``) and ``description`` — with the structure an object
or array needs (``properties``, ``additionalProperties`` as a boolean,
``items``) and **local** references only: ``$defs`` at the root, ``$ref``
exactly ``#/$defs/<name>`` naming an existing entry that is not itself a
reference. Nothing else: no ``pattern``, ``patternProperties``, regex-bearing
``format``, combinator, remote or relative reference, or unknown keyword.
The schema's compact JSON is at most ``AI_MAX_SCHEMA_BYTES`` and its nesting
at most ``AI_MAX_SCHEMA_DEPTH`` levels; the root is an object schema.

The validator is this module's own: it resolves only ``#/$defs`` names from
the schema in hand, so no reference can reach the network or a file. Every
value is checked on its type (``true`` is never ``1``), and recursion
through a reference always consumes a level of the (finite) value, because a
``$defs`` entry is never a bare reference.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from datetime import date, datetime
from typing import Final

from pydantic import JsonValue

from ai_gateway.providers import outputs

#: Keywords any node may carry.
_COMMON: Final = frozenset({"type", "enum", "description"})
#: Keywords per ``type`` beyond the common ones.
_BY_TYPE: Final[Mapping[str, frozenset[str]]] = {
    "string": frozenset({"minLength", "maxLength", "format"}),
    "number": frozenset({"minimum", "maximum"}),
    "integer": frozenset({"minimum", "maximum"}),
    "boolean": frozenset(),
    "array": frozenset({"items"}),
    "object": frozenset({"properties", "required", "additionalProperties"}),
}
_FORMATS: Final = frozenset({"date", "date-time", "uri"})
_DEF_NAME: Final = re.compile(r"[A-Za-z0-9_-]{1,64}")
_REF_PREFIX: Final = "#/$defs/"
_DATE: Final = re.compile(r"\d{4}-\d{2}-\d{2}")
_DATE_TIME: Final = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d{1,9})?([Zz]|[+-]\d{2}:\d{2})"
)
_SCHEME: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
#: The most entries one ``enum`` may list.
MAX_ENUM: Final = 256


class SchemaRefused(ValueError):
    """The schema is outside the dialect; the message names the rule, not data."""


def _number(value: object) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _scalars(values: JsonValue) -> bool:
    return (
        isinstance(values, list)
        and 0 < len(values) <= MAX_ENUM
        and not any(isinstance(v, dict | list) for v in values)
    )


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# --- checking a schema ----------------------------------------------------------------


class _Checker:
    def __init__(self, defs: Mapping[str, JsonValue], max_depth: int) -> None:
        self._defs = defs
        self._max_depth = max_depth

    def node(self, node: JsonValue, depth: int) -> None:
        if depth > self._max_depth:
            raise SchemaRefused("the schema nests too deeply")
        if not isinstance(node, dict):
            raise SchemaRefused("a schema node must be an object")
        if "$ref" in node:
            self._ref(node)
            return
        kind = node.get("type")
        if not isinstance(kind, str) or kind not in _BY_TYPE:
            raise SchemaRefused("every node names one supported type")
        unknown = set(node) - _COMMON - _BY_TYPE[kind]
        if unknown:
            raise SchemaRefused("a keyword outside the dialect")
        self._annotations(node)
        self._bounds(node)
        if kind == "array":
            self.node(node.get("items", {"type": "string"}), depth + 1)
        if kind == "object":
            self._object(node, depth)

    def _ref(self, node: Mapping[str, JsonValue]) -> None:
        if set(node) - {"$ref", "description"}:
            raise SchemaRefused("a reference carries nothing else")
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith(_REF_PREFIX):
            raise SchemaRefused("only local #/$defs references")
        if ref.removeprefix(_REF_PREFIX) not in self._defs:
            raise SchemaRefused("a reference names no definition")

    def _annotations(self, node: Mapping[str, JsonValue]) -> None:
        if "description" in node and not isinstance(node["description"], str):
            raise SchemaRefused("description is text")
        if "enum" in node and not _scalars(node["enum"]):
            raise SchemaRefused("enum lists up to 256 scalars")
        if "format" in node and node["format"] not in _FORMATS:
            raise SchemaRefused("format is date, date-time or uri")

    def _bounds(self, node: Mapping[str, JsonValue]) -> None:
        for name in ("minimum", "maximum"):
            if name in node and not _number(node[name]):
                raise SchemaRefused("a bound is a finite number")
        for name in ("minLength", "maxLength"):
            if name in node and not _count(node[name]):
                raise SchemaRefused("a length is a non-negative integer")

    def _object(self, node: Mapping[str, JsonValue], depth: int) -> None:
        properties = node.get("properties", {})
        if not isinstance(properties, dict):
            raise SchemaRefused("properties is an object")
        for child in properties.values():
            self.node(child, depth + 1)
        required = node.get("required", [])
        if (
            not isinstance(required, list)
            or len(set(map(str, required))) != len(required)
            or not all(isinstance(r, str) and r in properties for r in required)
        ):
            raise SchemaRefused("required names declared properties once")
        extra = node.get("additionalProperties", True)
        if not isinstance(extra, bool):
            raise SchemaRefused("additionalProperties is a boolean")


def check_schema(
    schema: Mapping[str, JsonValue], *, max_bytes: int, max_depth: int
) -> None:
    """Refuse ``schema`` unless it is inside the dialect and its bounds."""
    encoded = json.dumps(schema, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise SchemaRefused("the schema is too large")
    root = dict(schema)
    defs = root.pop("$defs", {})
    if not isinstance(defs, dict) or not all(_DEF_NAME.fullmatch(k) for k in defs):
        raise SchemaRefused("$defs maps simple names to schemas")
    checker = _Checker(defs, max_depth)
    for definition in defs.values():
        if isinstance(definition, dict) and "$ref" in definition:
            raise SchemaRefused("a definition is never a bare reference")
        checker.node(definition, 1)
    if root.get("type") != "object":
        raise SchemaRefused("the root is an object schema")
    checker.node(root, 0)


# --- validating a value ---------------------------------------------------------------


class _Validator:
    def __init__(self, schema: Mapping[str, JsonValue]) -> None:
        defs = schema.get("$defs", {})
        self._defs: Mapping[str, JsonValue] = defs if isinstance(defs, dict) else {}
        self._root = schema

    def check(self, node: Mapping[str, JsonValue], value: JsonValue) -> bool:
        if "$ref" in node:
            target = self._defs[str(node["$ref"]).removeprefix(_REF_PREFIX)]
            assert isinstance(target, dict)  # nosec B101 - checked by check_schema
            return self.check(target, value)
        if "enum" in node and not _member(value, node["enum"]):
            return False
        kind = node["type"]
        return _TYPE_CHECKS[str(kind)](self, node, value)

    def object(self, node: Mapping[str, JsonValue], value: JsonValue) -> bool:
        if not isinstance(value, dict):
            return False
        properties = node.get("properties", {})
        assert isinstance(properties, dict)  # nosec B101 - checked by check_schema
        required = node.get("required", [])
        assert isinstance(required, list)  # nosec B101 - checked by check_schema
        if any(name not in value for name in required):
            return False
        if node.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(
            self.check(_node(properties[k]), v)
            for k, v in value.items()
            if k in properties
        )

    def array(self, node: Mapping[str, JsonValue], value: JsonValue) -> bool:
        items = _node(node.get("items", {"type": "string"}))
        return isinstance(value, list) and all(self.check(items, v) for v in value)


def _node(value: JsonValue) -> Mapping[str, JsonValue]:
    assert isinstance(value, dict)  # nosec B101 - checked by check_schema
    return value


def _same(a: JsonValue, b: JsonValue) -> bool:
    return type(a) is type(b) and a == b or (_number(a) and _number(b) and a == b)


def _member(value: JsonValue, values: JsonValue) -> bool:
    assert isinstance(values, list)  # nosec B101 - checked by check_schema
    return any(_same(value, v) for v in values)


def _within(node: Mapping[str, JsonValue], value: float) -> bool:
    low, high = node.get("minimum"), node.get("maximum")
    return (low is None or value >= low) and (high is None or value <= high)  # type: ignore[operator]


def _string(_v: _Validator, node: Mapping[str, JsonValue], value: JsonValue) -> bool:
    if not isinstance(value, str):
        return False
    low, high = node.get("minLength", 0), node.get("maxLength")
    if len(value) < low or (high is not None and len(value) > high):  # type: ignore[operator]
        return False
    return _formatted(node.get("format"), value)


def _date(value: str) -> bool:
    try:
        return bool(_DATE.fullmatch(value)) and bool(date.fromisoformat(value))
    except ValueError:
        return False


def _date_time(value: str) -> bool:
    try:
        return bool(_DATE_TIME.fullmatch(value)) and bool(
            datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
        )
    except ValueError:
        return False


def _uri(value: str) -> bool:
    scheme, colon, rest = value.partition(":")
    return bool(colon and rest and _SCHEME.fullmatch(scheme)) and not any(
        c.isspace() for c in value
    )


_FORMAT_CHECKS: Final[Mapping[str, Callable[[str], bool]]] = {
    "date": _date,
    "date-time": _date_time,
    "uri": _uri,
}


def _formatted(kind: JsonValue, value: str) -> bool:
    check = _FORMAT_CHECKS.get(str(kind)) if kind is not None else None
    return check is None or check(value)


def _number_check(
    _v: _Validator, node: Mapping[str, JsonValue], value: JsonValue
) -> bool:
    return _number(value) and _within(node, float(value))  # type: ignore[arg-type]


def _integer(_v: _Validator, node: Mapping[str, JsonValue], value: JsonValue) -> bool:
    return (
        isinstance(value, int) and not isinstance(value, bool) and _within(node, value)
    )


def _boolean(_v: _Validator, _node: Mapping[str, JsonValue], value: JsonValue) -> bool:
    return isinstance(value, bool)


_TYPE_CHECKS: Final[
    Mapping[str, Callable[[_Validator, Mapping[str, JsonValue], JsonValue], bool]]
] = {
    "string": _string,
    "number": _number_check,
    "integer": _integer,
    "boolean": _boolean,
    "array": _Validator.array,
    "object": _Validator.object,
}


def validator(
    schema: Mapping[str, JsonValue],
) -> Callable[[JsonValue], dict[str, JsonValue]]:
    """A validator of model output against a checked ``schema``."""
    checker = _Validator(schema)

    def validate(value: JsonValue) -> dict[str, JsonValue]:
        if not isinstance(value, dict) or not checker.check(schema, value):
            raise outputs.rejected()
        return value

    return validate


__all__ = ["MAX_ENUM", "SchemaRefused", "check_schema", "validator"]
