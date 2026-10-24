"""
Provider access: the hardened HTTP client, its breakers and the adapters.

Only the gateway reaches a provider (D-02, D-21), and only through
:class:`~ai_gateway.providers.http.ProviderHttpClient` (D-20): the
destination guard on every request, no redirects, no proxy environment, TLS
verification always on, bounded bodies, a total deadline per call, closed
failures. Adapters (:mod:`ai_gateway.providers.base`) speak one
``provider_type`` each; their results are validated by
:mod:`ai_gateway.providers.outputs` before any settlement.
"""
