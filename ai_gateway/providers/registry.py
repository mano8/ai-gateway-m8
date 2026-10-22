"""
The adapter serving each ``provider_type``.

An execution whose recorded provider has no adapter here is refused with
``capability_unsupported`` before any credential material or provider
request (``pending → released``).
"""

from __future__ import annotations

from ai_sdk_m8.schemas.management import ProviderType

from .base import ProviderAdapter
from .ollama import OllamaAdapter
from .openai_compatible import OpenAiCompatibleAdapter

#: The Ollama adapter; the digest reader uses the same instance.
OLLAMA = OllamaAdapter()

#: Every adapter of this build, by the provider type it speaks.
ADAPTERS: dict[ProviderType, ProviderAdapter] = {
    ProviderType.OLLAMA: OLLAMA,
    ProviderType.OPENAI_COMPATIBLE: OpenAiCompatibleAdapter(),
}

__all__ = ["ADAPTERS", "OLLAMA"]
