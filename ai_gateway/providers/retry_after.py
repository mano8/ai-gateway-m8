"""
A provider's ``Retry-After``, parsed and bounded (D-20).

A provider 429 backs off the credential that received it: settlement sets
``ai_credential.throttled_until = now() + min(Retry-After,
AI_PROVIDER_MAX_BACKOFF_SECONDS)`` on the database clock. The header is
untrusted input: delta-seconds and HTTP-dates are honoured within the cap,
an absent or unparsable value falls back to 60 s, and a date in the past is
zero.
"""

from __future__ import annotations

import math
from email.utils import parsedate_to_datetime
from typing import Final

#: Cooldown when a 429 carries no usable ``Retry-After``.
DEFAULT_RETRY_AFTER_SECONDS: Final = 60

#: Longest delta-seconds value read; anything longer is capped anyway.
_MAX_DIGITS: Final = 12


def _delta_seconds(value: str, cap_seconds: int) -> int | None:
    if not (value.isascii() and value.isdigit()):
        return None
    # A longer number than any cap is the cap; it is never converted.
    return cap_seconds if len(value) > _MAX_DIGITS else int(value)


def _http_date_seconds(value: str, now: float) -> int | None:
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when.tzinfo is None:
        return None
    return max(0, math.ceil(when.timestamp() - now))


def parse_retry_after(value: str | None, *, cap_seconds: int, now: float) -> int:
    """
    The cooldown in whole seconds that a ``Retry-After`` value asks for.

    Parameters
    ----------
    value
        The raw header value, or ``None`` when the answer carried none.
    cap_seconds
        ``AI_PROVIDER_MAX_BACKOFF_SECONDS``: no answer backs off longer.
    now
        The gateway's clock (epoch seconds) an HTTP-date is measured from;
        the clock skew against the database is bounded by
        ``AI_MAX_CLOCK_SKEW_SECONDS``.

    Returns
    -------
    int
        Seconds in ``[0, cap_seconds]``.

    """
    seconds: int | None = None
    if value is not None:
        text = value.strip()
        seconds = _delta_seconds(text, cap_seconds)
        if seconds is None:
            seconds = _http_date_seconds(text, now)
    if seconds is None:
        seconds = DEFAULT_RETRY_AFTER_SECONDS
    return min(seconds, cap_seconds)


__all__ = ["DEFAULT_RETRY_AFTER_SECONDS", "parse_retry_after"]
