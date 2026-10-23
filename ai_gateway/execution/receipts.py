"""
The C-01 signed OCR provenance receipt (D-47).

Every ``ok`` OCR execution carries one: an ``m8.ai.ocr-receipt.v1`` compact
signed object, signed under the C-03 rule with the web service's receipt
seed (``AI_EXECUTION_RECEIPT_KEY_FILE``). ``result_sha256`` is SHA-256 over
the JCS bytes of the exact float-free ``OcrResult`` the response returns,
so a consumer recomputes it from the body it received. The job context's
``job_ref``, ``attempt``, ``azp``, ``profile_key``, ``input_sha256`` and
``ocr_options_hash`` are copied verbatim: the receipt binds the result to
the document and options the context signed.

**JCS of the result.** The SDK's ``canonicalize`` is the signed-payload
encoder and refuses nesting beyond four levels, while an ``OcrResult``
nests six (``pages[].images[].bbox``). :func:`jcs` is RFC 8785 under the
same integer-only rule — every scalar encoded by the SDK's own encoder,
object keys sorted by UTF-16 code units — bounded only by the response depth
cap (:data:`~ai_gateway.providers.http.MAX_RESPONSE_JSON_DEPTH`).
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from ai_sdk_m8.jobcontext import JobContextPayload, OcrReceiptPayload
from ai_sdk_m8.schemas import OcrResult
from ai_sdk_m8.signed import Domain, canonicalize, sign_object

from ai_gateway.core.keyfiles import KeyMaterial
from ai_gateway.providers.http import MAX_RESPONSE_JSON_DEPTH


def _utf16(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _jcs(value: object, depth: int) -> bytes:
    if isinstance(value, Mapping):
        if depth >= MAX_RESPONSE_JSON_DEPTH:
            raise ValueError("nesting too deep")
        members = sorted(value.items(), key=lambda item: _utf16(str(item[0])))
        return (
            b"{"
            + b",".join(
                canonicalize(str(k)) + b":" + _jcs(v, depth + 1) for k, v in members
            )
            + b"}"
        )
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        if depth >= MAX_RESPONSE_JSON_DEPTH:
            raise ValueError("nesting too deep")
        return b"[" + b",".join(_jcs(item, depth + 1) for item in value) + b"]"
    return canonicalize(value)  # the SDK's scalar rule: no float, JCS range


def jcs(value: object) -> bytes:
    """RFC 8785 bytes of an integer-only JSON value, nested at most 32 deep."""
    return _jcs(value, 0)


def result_sha256(result: OcrResult) -> str:
    """``SHA-256(JCS(OcrResult))``, lower-case hex."""
    return hashlib.sha256(jcs(result.model_dump(mode="json"))).hexdigest()


@dataclass(frozen=True)
class ReceiptSigner:
    """Signs OCR receipts for one installation with its receipt seed."""

    seed: KeyMaterial
    kid: str
    deployment_id: str
    clock: Callable[[], float] = field(default=time.time)

    def sign(
        self,
        *,
        execution_id: UUID,
        context: JobContextPayload,
        execution_identity: str,
        result: OcrResult,
    ) -> str:
        """The compact receipt of one ``ok`` execution."""
        assert context.input_sha256 is not None  # nosec B101 - an ocr context
        assert context.ocr_options_hash is not None  # nosec B101 - an ocr context
        payload = OcrReceiptPayload(
            kid=self.kid,
            iss=f"ai-gateway/{self.deployment_id}",
            execution_id=str(execution_id),
            job_ref=context.job_ref,
            attempt=context.attempt,
            azp=context.azp,
            profile_key=context.profile_key,
            input_sha256=context.input_sha256,
            ocr_options_hash=context.ocr_options_hash,
            execution_identity=execution_identity,
            result_sha256=result_sha256(result),
            produced_at=int(self.clock()),
        )
        return sign_object(payload, domain=Domain.OCR_RECEIPT, seed=self.seed.reveal())


__all__ = ["ReceiptSigner", "jcs", "result_sha256"]
