"""
Provider destination guard (D-20, R-11, S-02).

A provider's ``base_url`` is superuser-set and is the one place outbound
traffic carrying a credential goes, so it is checked twice: a static pass when
it is written (scheme, userinfo, port, allowlist, literal addresses) and a
resolved pass before every call, which inspects **every** A/AAAA answer.

Rules, in this order:

1. IPv4-mapped IPv6 is normalised to its IPv4 form.
2. Always blocked, whatever the boundary and before any allowlist: loopback,
   link-local (``169.254.169.254`` included), multicast, reserved and
   unspecified addresses.
3. ``external`` providers: every answer must be globally routable
   (``is_global`` — RFC 1918, ULA and CGNAT ``100.64.0.0/10`` are refused),
   the port must be 443 or listed in ``AI_PROVIDER_ALLOWED_EXTERNAL_PORTS``,
   and HTTPS is required under ``production``/strict.
4. ``local`` providers: the ``(name, port)`` pair must be listed in
   ``AI_PROVIDER_ALLOWED_INTERNAL_HOSTS``; only that pair is exempt from the
   private-address rule, never from rule 2. Plain ``http`` stays allowed
   there (isolated compose network).
5. No userinfo, query or fragment; host names are compared after IDNA
   normalisation.

**Residual (stated, not closed).** The resolved pass and the connection
resolve separately, so a DNS answer that changes between them (rebinding) is
not caught here; TLS hostname verification on ``external`` providers
mitigates it. Closing it needs connect-time destination enforcement (an
egress proxy), a named follow-on (Q13). None of this constrains code running
inside a compromised gateway.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from ai_sdk_m8.schemas import ProviderBoundary

#: Resolve a host to every IP address string it points at.
Resolver = Callable[[str], list[str]]

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_DEFAULT_PORTS = {"http": 80, "https": 443}


class DestinationError(ValueError):
    """A provider destination is refused; the message is operator-actionable."""


@dataclass(frozen=True)
class DestinationPolicy:
    """The destination posture of this deployment."""

    production: bool
    internal_hosts: frozenset[tuple[str, int]]
    external_ports: frozenset[int]

    @classmethod
    def from_settings(cls, settings: object) -> DestinationPolicy:
        """Build the policy from gateway ``Settings``."""
        return cls(
            production=bool(getattr(settings, "is_production")),
            internal_hosts=frozenset(getattr(settings, "internal_hosts")),
            external_ports=frozenset(getattr(settings, "external_ports")),
        )


@dataclass(frozen=True)
class ProviderTarget:
    """A checked, normalised provider endpoint."""

    scheme: str
    host: str
    port: int
    path: str
    boundary: ProviderBoundary

    def origin(self) -> str:
        """``scheme://host:port`` with the normalised host."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def default_resolver(host: str) -> list[str]:
    """Every A/AAAA answer of ``host`` from the system resolver."""
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def _normalise_ip(raw: str) -> IpAddress:
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _literal(host: str) -> IpAddress | None:
    try:
        return _normalise_ip(host)
    except ValueError:
        return None


def _normalise_host(host: str) -> str:
    host = host.rstrip(".").lower()
    if _literal(host) is not None:
        return str(_literal(host))
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise DestinationError("provider host is not a valid domain name") from None


def _always_blocked(ip: IpAddress) -> bool:
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _check_address(ip: IpAddress, boundary: ProviderBoundary) -> None:
    if _always_blocked(ip):
        raise DestinationError(f"provider host resolves to a blocked address ({ip})")
    if boundary is ProviderBoundary.EXTERNAL and not ip.is_global:
        raise DestinationError(
            f"an external provider resolves to a non-global address ({ip})"
        )


def parse_target(url: str, boundary: ProviderBoundary) -> ProviderTarget:
    """Split and normalise ``url``; refuse userinfo, query, fragment, bad ports."""
    if not isinstance(url, str) or any(c.isspace() or ord(c) < 0x20 for c in url):
        raise DestinationError("provider URL contains whitespace or control characters")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise DestinationError("provider URL scheme must be http or https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise DestinationError("provider URL must not carry userinfo")
    if parts.query or parts.fragment:
        raise DestinationError("provider URL must not carry a query or a fragment")
    if not parts.hostname:
        raise DestinationError("provider URL has no host")
    try:
        port = parts.port or _DEFAULT_PORTS[scheme]
    except ValueError:
        raise DestinationError("provider URL port is not valid") from None
    return ProviderTarget(
        scheme=scheme,
        host=_normalise_host(parts.hostname),
        port=port,
        path=parts.path.rstrip("/"),
        boundary=boundary,
    )


def check_static(
    url: str, boundary: ProviderBoundary, policy: DestinationPolicy
) -> ProviderTarget:
    """
    The write-time pass: everything that needs no DNS.

    A literal address is checked here; a name is resolved by
    :func:`check_resolved` before every call.
    """
    target = parse_target(url, boundary)
    literal = _literal(target.host)
    if boundary is ProviderBoundary.LOCAL:
        if literal is not None:
            raise DestinationError(
                "a local provider must use an allowlisted name, not an address"
            )
        if (target.host, target.port) not in policy.internal_hosts:
            raise DestinationError(
                f"{target.host}:{target.port} is not in "
                "AI_PROVIDER_ALLOWED_INTERNAL_HOSTS"
            )
        return target
    if target.port not in policy.external_ports:
        raise DestinationError(
            f"port {target.port} is not in AI_PROVIDER_ALLOWED_EXTERNAL_PORTS"
        )
    if policy.production and target.scheme != "https":
        raise DestinationError(
            "an external provider must use https under production or strict mode"
        )
    if literal is not None:
        _check_address(literal, boundary)
    return target


def check_resolved(
    url: str,
    boundary: ProviderBoundary,
    policy: DestinationPolicy,
    resolver: Resolver = default_resolver,
) -> list[IpAddress]:
    """
    The call-time pass: the static rules, then every resolved answer.

    Returns the checked addresses. An empty or failing resolution is a
    refusal.
    """
    target = check_static(url, boundary, policy)
    literal = _literal(target.host)
    if literal is not None:
        return [literal]
    try:
        answers = resolver(target.host)
    except OSError:
        raise DestinationError("provider host could not be resolved") from None
    if not answers:
        raise DestinationError("provider host could not be resolved")
    addresses = []
    for raw in answers:
        try:
            ip = _normalise_ip(raw)
        except ValueError:
            raise DestinationError("provider host resolved to a non-address") from None
        _check_address(ip, boundary)
        addresses.append(ip)
    return addresses


__all__ = [
    "DestinationError",
    "DestinationPolicy",
    "ProviderTarget",
    "Resolver",
    "check_resolved",
    "check_static",
    "default_resolver",
    "parse_target",
]
