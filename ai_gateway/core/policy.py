"""
The data-class policy table (D-08, Q4).

Every execution carries a signed ``data_class``; the gateway decides from it
which destinations the resolved provider and credential may be:

* ``local`` — a provider whose boundary is ``local``, whatever the credential;
* ``external_byok`` — an ``external`` provider reached with the context's own
  tenant's or user's credential;
* ``external_platform`` — an ``external`` provider reached with a platform
  (global) credential, or with none.

The ratified default lets ``public`` go anywhere and keeps ``internal`` and
``restricted`` on ``local`` providers or the context's own BYOK credential.
``AI_DATA_CLASS_POLICY`` may widen ``internal`` explicitly; ``restricted`` can
never reach ``external_platform``. ``rerank`` is ``local``-only whatever this
table says — that rule is hard-wired at resolution, not here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from ai_sdk_m8.schemas import DataClass
from ai_sdk_m8.signed import canonicalize


class Destination(StrEnum):
    """Where a resolved execution would send data."""

    LOCAL = "local"
    EXTERNAL_BYOK = "external_byok"
    EXTERNAL_PLATFORM = "external_platform"


#: The ratified first-deployment table (Q4, ``T1`` 2026-10-10).
DEFAULT_POLICY: Final[Mapping[DataClass, frozenset[Destination]]] = {
    DataClass.PUBLIC: frozenset(Destination),
    DataClass.INTERNAL: frozenset({Destination.LOCAL, Destination.EXTERNAL_BYOK}),
    DataClass.RESTRICTED: frozenset({Destination.LOCAL, Destination.EXTERNAL_BYOK}),
}


class PolicyConfigError(ValueError):
    """``AI_DATA_CLASS_POLICY`` is malformed or widens ``restricted``."""


@dataclass(frozen=True)
class DataClassPolicy:
    """The effective table: the destinations each class may reach."""

    allowed: Mapping[DataClass, frozenset[Destination]]

    def allows(self, data_class: DataClass, destination: Destination) -> bool:
        """Whether ``data_class`` may reach ``destination``."""
        return destination in self.allowed[data_class]

    def canonical(self) -> dict[str, list[str]]:
        """The table as sorted JSON-ready lists."""
        return {
            data_class.value: sorted(d.value for d in self.allowed[data_class])
            for data_class in DataClass
        }

    def sha256(self) -> str:
        """SHA-256 of the canonical table, reported in ``/meta``."""
        return hashlib.sha256(canonicalize(self.canonical())).hexdigest()

    def is_default(self) -> bool:
        """Whether this is the ratified default table."""
        return dict(self.allowed) == dict(DEFAULT_POLICY)


def parse_data_class_policy(raw: str | None) -> DataClassPolicy:
    """
    Parse ``AI_DATA_CLASS_POLICY``; ``None`` yields the ratified default.

    The value is a JSON object naming exactly the three classes, each with a
    list of destinations. ``restricted`` may not include
    ``external_platform``.
    """
    if raw is None:
        return DataClassPolicy(dict(DEFAULT_POLICY))
    try:
        document = json.loads(raw)
    except ValueError:
        raise PolicyConfigError("AI_DATA_CLASS_POLICY is not valid JSON") from None
    if not isinstance(document, dict) or set(document) != {c.value for c in DataClass}:
        raise PolicyConfigError(
            "AI_DATA_CLASS_POLICY must name exactly public, internal and restricted"
        )
    allowed: dict[DataClass, frozenset[Destination]] = {}
    for name, values in document.items():
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise PolicyConfigError(f"AI_DATA_CLASS_POLICY[{name}] must be a list")
        try:
            destinations = frozenset(Destination(v) for v in values)
        except ValueError:
            raise PolicyConfigError(
                f"AI_DATA_CLASS_POLICY[{name}] names an unknown destination"
            ) from None
        if len(destinations) != len(values):
            raise PolicyConfigError(f"AI_DATA_CLASS_POLICY[{name}] repeats a value")
        allowed[DataClass(name)] = destinations
    if Destination.EXTERNAL_PLATFORM in allowed[DataClass.RESTRICTED]:
        raise PolicyConfigError(
            "AI_DATA_CLASS_POLICY may never let restricted data reach an external "
            "provider without the context's own BYOK credential"
        )
    return DataClassPolicy(allowed)


def default_policy_json() -> str:
    """The ratified default as an ``AI_DATA_CLASS_POLICY`` value."""
    return json.dumps(DataClassPolicy(dict(DEFAULT_POLICY)).canonical())


__all__ = [
    "DEFAULT_POLICY",
    "DataClassPolicy",
    "Destination",
    "PolicyConfigError",
    "default_policy_json",
    "parse_data_class_policy",
]
