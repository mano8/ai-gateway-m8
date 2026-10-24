"""
The adapter serving each ``provider_type``.

An execution whose recorded provider has no adapter here is refused with
``capability_unsupported`` before any credential material or provider
request (``pending → released``).
"""

from __future__ import annotations

from ai_sdk_m8.schemas.management import ProviderType

from .base import ProviderAdapter
from .mistral import MistralAdapter
from .ollama import OllamaAdapter
from .openai_compatible import OpenAiCompatibleAdapter

#: The Ollama adapter; the digest reader uses the same instance.
OLLAMA = OllamaAdapter()

#: The OpenAI-compatible adapter (stateless).
OPENAI_COMPATIBLE = OpenAiCompatibleAdapter()


def build_adapters(
    *, inline_threshold_bytes: int, file_expiry_seconds: int
) -> dict[ProviderType, ProviderAdapter]:
    """Every adapter of this build, by the provider type it speaks."""
    return {
        ProviderType.OLLAMA: OLLAMA,
        ProviderType.OPENAI_COMPATIBLE: OPENAI_COMPATIBLE,
        ProviderType.MISTRAL: MistralAdapter(
            inline_threshold_bytes=inline_threshold_bytes,
            file_expiry_seconds=file_expiry_seconds,
        ),
    }


__all__ = ["OLLAMA", "OPENAI_COMPATIBLE", "build_adapters"]
