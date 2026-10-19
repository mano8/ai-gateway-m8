"""T19: the provider destination guard (D-20, S-02)."""

from __future__ import annotations

import pytest
from ai_sdk_m8.schemas import ProviderBoundary

from ai_gateway.core.config import settings
from ai_gateway.core.ssrf import (
    DestinationError,
    DestinationPolicy,
    check_resolved,
    check_static,
    default_resolver,
    parse_target,
)

LOCAL = ProviderBoundary.LOCAL
EXTERNAL = ProviderBoundary.EXTERNAL
HOSTS = frozenset({("ollama", 11434), ("tei.ai-net", 8080)})
DEV = DestinationPolicy(
    production=False, internal_hosts=HOSTS, external_ports=frozenset({443})
)
PROD = DestinationPolicy(
    production=True, internal_hosts=HOSTS, external_ports=frozenset({443})
)


def answers(*ips: str):
    return lambda _host: list(ips)


def test_policy_from_settings() -> None:
    policy = DestinationPolicy.from_settings(settings)
    assert policy.production is False
    assert policy.external_ports == {443}
    assert policy.internal_hosts == frozenset()


# --- parsing ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "match"),
    [
        ("ftp://host/x", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("http:///path", "no host"),
        ("https://user:pw@api.example.com", "userinfo"),
        ("https://user@api.example.com", "userinfo"),
        ("https://api.example.com/?x=1", "query"),
        ("https://api.example.com/#f", "query or a fragment"),
        ("https://api.example.com:99999", "port"),
        ("https://api.example.com/a b", "whitespace"),
        ("https://api.example.com/\x00", "control"),
        ("https://exa­mple..com", "valid domain"),
    ],
)
def test_malformed_urls_are_refused(url: str, match: str) -> None:
    with pytest.raises(DestinationError, match=match):
        check_static(url, EXTERNAL, DEV)


def test_hosts_are_normalised() -> None:
    target = parse_target("HTTPS://API.Example.COM./v1/", EXTERNAL)
    assert (target.scheme, target.host, target.port, target.path) == (
        "https",
        "api.example.com",
        443,
        "/v1",
    )
    assert target.origin() == "https://api.example.com:443"
    unicode = parse_target("https://bücher.example/", EXTERNAL)
    assert unicode.host == "xn--bcher-kva.example"
    v6 = parse_target("https://[2606:4700::1111]:443", EXTERNAL)
    assert v6.origin() == "https://[2606:4700::1111]:443"


# --- always blocked ----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://169.254.169.254/latest/meta-data",
        "https://0.0.0.0/",
        "https://224.0.0.1/",
        "https://[::ffff:127.0.0.1]/",
        "https://[fe80::1]/",
        "https://240.0.0.1/",
    ],
)
def test_dangerous_literals_are_blocked_everywhere(url: str) -> None:
    with pytest.raises(DestinationError, match="blocked address"):
        check_static(url, EXTERNAL, DEV)


def test_loopback_through_an_allowlisted_name_is_refused() -> None:
    with pytest.raises(DestinationError, match="blocked address"):
        check_resolved("http://ollama:11434", LOCAL, DEV, answers("127.0.0.1"))
    with pytest.raises(DestinationError, match="blocked address"):
        check_resolved("http://ollama:11434", LOCAL, DEV, answers("169.254.169.254"))


# --- external providers -------------------------------------------------------------


@pytest.mark.parametrize(
    "ip", ["10.0.0.5", "172.16.3.4", "192.168.1.10", "100.64.0.1", "fd00::1"]
)
@pytest.mark.parametrize("policy", [DEV, PROD])
def test_external_providers_need_global_addresses(
    ip: str, policy: DestinationPolicy
) -> None:
    with pytest.raises(DestinationError, match="non-global"):
        check_resolved("https://api.example.com", EXTERNAL, policy, answers(ip))


def test_cgnat_and_ipv4_mapped_private_are_refused_under_production() -> None:
    with pytest.raises(DestinationError, match="non-global"):
        check_static("https://100.64.0.1/", EXTERNAL, PROD)
    with pytest.raises(DestinationError, match="non-global"):
        check_static("https://[::ffff:10.0.0.1]/", EXTERNAL, PROD)
    with pytest.raises(DestinationError, match="non-global"):
        check_resolved(
            "https://api.example.com", EXTERNAL, PROD, answers("::ffff:10.0.0.1")
        )


def test_every_answer_must_pass() -> None:
    with pytest.raises(DestinationError, match="non-global"):
        check_resolved(
            "https://api.example.com",
            EXTERNAL,
            PROD,
            answers("93.184.216.34", "2606:4700::1111", "10.1.2.3"),
        )
    assert [
        str(ip)
        for ip in check_resolved(
            "https://api.example.com",
            EXTERNAL,
            PROD,
            answers("93.184.216.34", "2606:4700::1111"),
        )
    ] == ["93.184.216.34", "2606:4700::1111"]


def test_scoped_ipv6_answers_are_normalised() -> None:
    with pytest.raises(DestinationError, match="blocked address"):
        check_resolved(
            "https://api.example.com", EXTERNAL, PROD, answers("fe80::1%eth0")
        )


def test_external_https_under_production_only() -> None:
    with pytest.raises(DestinationError, match="https"):
        check_static(
            "http://api.example.com",
            EXTERNAL,
            PROD.__class__(True, HOSTS, frozenset({80, 443})),
        )
    check_static("http://api.example.com:443", EXTERNAL, DEV)


def test_external_port_allowlist() -> None:
    with pytest.raises(DestinationError, match="AI_PROVIDER_ALLOWED_EXTERNAL_PORTS"):
        check_static("https://api.example.com:8443", EXTERNAL, PROD)
    wide = DestinationPolicy(True, HOSTS, frozenset({443, 8443}))
    assert check_static("https://api.example.com:8443", EXTERNAL, wide).port == 8443


def test_a_global_external_address_is_accepted() -> None:
    assert check_resolved("https://8.8.8.8/", EXTERNAL, PROD)[0].is_global


# --- local providers ----------------------------------------------------------------


def test_local_providers_need_an_allowlisted_name_and_port() -> None:
    assert check_static("http://ollama:11434", LOCAL, PROD).host == "ollama"
    assert check_resolved("http://OLLAMA:11434/", LOCAL, PROD, answers("172.18.0.4"))
    with pytest.raises(
        DestinationError, match="not in AI_PROVIDER_ALLOWED_INTERNAL_HOSTS"
    ):
        check_static("http://ollama:8080", LOCAL, PROD)
    with pytest.raises(
        DestinationError, match="not in AI_PROVIDER_ALLOWED_INTERNAL_HOSTS"
    ):
        check_static("http://other:11434", LOCAL, PROD)
    with pytest.raises(DestinationError, match="allowlisted name, not an address"):
        check_static("http://172.18.0.4:11434", LOCAL, DEV)


def test_an_allowlisted_local_name_does_not_widen_external() -> None:
    with pytest.raises(DestinationError, match="non-global"):
        check_resolved("https://ollama:443", EXTERNAL, PROD, answers("172.18.0.4"))


# --- resolution failures ---------------------------------------------------------------


def test_resolution_failures_are_refusals() -> None:
    def broken(_host: str) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(DestinationError, match="could not be resolved"):
        check_resolved("https://api.example.com", EXTERNAL, PROD, broken)
    with pytest.raises(DestinationError, match="could not be resolved"):
        check_resolved("https://api.example.com", EXTERNAL, PROD, answers())
    with pytest.raises(DestinationError, match="non-address"):
        check_resolved("https://api.example.com", EXTERNAL, PROD, answers("not-an-ip"))


def test_the_default_resolver_uses_the_system_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, _port: [
            (0, 0, 0, "", ("93.184.216.34", 0)),
            (0, 0, 0, "", ("2606:4700::1111", 0, 0, 0)),
        ],
    )
    assert default_resolver("api.example.com") == ["93.184.216.34", "2606:4700::1111"]


# --- the documented residual -------------------------------------------------------------


def test_rebinding_between_check_and_connect_is_the_recorded_residual() -> None:
    """The check passes on its own answer; a later, different answer at
    connect time is outside this module (D-20 residual, R-11). TLS hostname
    verification on the external provider is the mitigation; connect-time
    enforcement is the named follow-on (Q13)."""
    sequence = iter([["93.184.216.34"], ["10.0.0.5"]])
    resolver = lambda _host: next(sequence)  # noqa: E731
    assert check_resolved("https://api.example.com", EXTERNAL, PROD, resolver)
    # The connection would resolve again and could get the private answer;
    # a second check catches it, the connection itself does not.
    with pytest.raises(DestinationError, match="non-global"):
        check_resolved("https://api.example.com", EXTERNAL, PROD, resolver)
