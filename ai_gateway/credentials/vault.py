"""
The Vault client (D-20) and the ``vault_transit`` KEK provider (D-23, T23).

**Client.** ``hvac`` runs on a dedicated ``requests.Session`` with
``trust_env = False`` — no proxy variables, no ``.netrc`` — TLS verification
always on (``AI_VAULT_CA_FILE`` or the system store, never off) and
redirects refused: ``requests`` strips ``Authorization`` on a cross-host
redirect but not ``X-Vault-Token``, so ``AI_VAULT_ADDR`` names the active node
or its load balancer and nothing else is ever contacted. Every call is
bounded by ``AI_CREDENTIAL_RESOLVE_TIMEOUT_SECONDS``.

**Authentication.** ``token_file`` reads the token from its file (a Vault
Agent may rewrite it); ``approle`` logs in with the role and secret ids read
from their files, and logs in again before the token's lease runs out. A
``403`` re-authenticates once and retries. Neither the token nor the
``secret_id`` is ever logged or put in an exception.

**Transit.** A data key is wrapped by ``transit/encrypt`` and unwrapped by
``transit/decrypt``, both with the version's AAD as ``associated_data``, so
a wrapped key moved to another row never unwraps. The generation label is
``transit-v<n>``, learnt from the encrypt answers. ``rewrap`` decrypts and
encrypts again: Vault's ``transit/rewrap`` takes no associated data. Health
uses only what execution needs — ``auth/token/lookup-self`` and an encrypt →
decrypt round trip of a constant — never a read of the key's metadata, which
the documented policy does not grant. Vault being unreachable is a
:class:`~ai_gateway.credentials.kek.KekError` (``credential_unavailable``),
never a fallback.
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, TypeVar

import hvac
import requests
from hvac import exceptions as hvac_exceptions

from ai_gateway.core.keyfiles import KeyFileError, load_secret_text

from .kek import KekError, WrappedKey

T = TypeVar("T")

#: Prefix of every transit generation label.
TRANSIT_PREFIX: Final = "transit-v"

#: Fraction of an AppRole lease after which the gateway logs in again.
RELOGIN_AT: Final = 0.8

#: The non-secret probe ``health`` round-trips.
_PROBE: Final = b"m8.ai.transit-probe.v1"


def vault_session(ca_file: Path | None) -> requests.Session:
    """A session that ignores the environment and verifies TLS (D-20)."""
    session = requests.Session()
    session.trust_env = False
    session.verify = str(ca_file) if ca_file is not None else True
    session.max_redirects = 0
    return session


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class VaultAccess:
    """An authenticated ``hvac`` client, renewed as its token requires."""

    def __init__(
        self,
        addr: str,
        auth_method: str,
        *,
        token_file: Path | None = None,
        role_id_file: Path | None = None,
        secret_id_file: Path | None = None,
        ca_file: Path | None = None,
        timeout_seconds: float = 5.0,
        session_factory: Callable[[Path | None], requests.Session] = vault_session,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._addr = addr
        self._auth_method = auth_method
        self._files = {
            "token": token_file,
            "role": role_id_file,
            "secret": secret_id_file,
        }
        self._ca_file = ca_file
        self._timeout = timeout_seconds
        self._session_factory = session_factory
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._client: hvac.Client | None = None
        self._renew_after: float | None = None

    def __repr__(self) -> str:
        return f"VaultAccess(addr={self._addr!r}, auth_method={self._auth_method!r})"

    def _read(self, name: str) -> str:
        path = self._files[name]
        if path is None:
            raise KekError("a Vault authentication file is not configured")
        try:
            return load_secret_text(path, what=f"the Vault {name} file")
        except KeyFileError:
            raise KekError("a Vault authentication file is not readable") from None

    def _new_client(self, token: str | None = None) -> hvac.Client:
        verify: bool | str = str(self._ca_file) if self._ca_file is not None else True
        return hvac.Client(
            url=self._addr,
            token=token,
            verify=verify,
            timeout=self._timeout,
            allow_redirects=False,
            session=self._session_factory(self._ca_file),
        )

    def _login(self) -> hvac.Client:
        if self._auth_method == "token_file":
            self._renew_after = None
            return self._new_client(self._read("token"))
        client = self._new_client()
        answer = client.auth.approle.login(
            role_id=self._read("role"), secret_id=self._read("secret")
        )
        # hvac raises unless the login answered JSON (it reads the token from
        # it), so ``answer`` is the parsed body here.
        auth = answer.get("auth") if isinstance(answer, dict) else None
        lease = int((auth or {}).get("lease_duration") or 0)
        self._renew_after = self._monotonic() + lease * RELOGIN_AT if lease else None
        return client

    def _current(self, *, fresh: bool) -> hvac.Client:
        with self._lock:
            expired = (
                self._renew_after is not None and self._monotonic() >= self._renew_after
            )
            if fresh or expired or self._client is None:
                self._client = self._login()
            return self._client

    def call(self, operation: Callable[[hvac.Client], T]) -> T:
        """Run ``operation``; log in again once on a ``403``; never a fallback."""
        try:
            try:
                return operation(self._current(fresh=False))
            except hvac_exceptions.Forbidden:
                return operation(self._current(fresh=True))
        except KekError:
            raise
        except (
            hvac_exceptions.VaultError,
            requests.RequestException,
            ValueError,
            KeyError,
            TypeError,
        ):
            raise KekError("the Vault call failed") from None


def _data(answer: object) -> dict[str, Any]:
    """The ``data`` of a 200 answer; anything else (a 3xx, …) is a failure."""
    if not isinstance(answer, dict) or not isinstance(answer.get("data"), dict):
        raise KekError("Vault gave no usable answer")
    data: dict[str, Any] = answer["data"]
    return data


class VaultTransitKekProvider:
    """Data keys wrapped by a Vault transit key."""

    provider = "vault_transit"

    def __init__(self, access: VaultAccess, *, mount: str, key: str) -> None:
        self._access = access
        self._mount = mount
        self.key_id = key
        self._active: str | None = None

    def __repr__(self) -> str:
        return f"VaultTransitKekProvider(key={self.key_id!r}, access={self._access!r})"

    @property
    def active_version(self) -> str:
        """The generation the last encrypt used (probed when unknown)."""
        if self._active is None:
            self.probe()
        assert self._active is not None  # nosec B101 - set by a successful probe
        return self._active

    def covers(self, version: str) -> bool:
        """Every transit generation; Vault holds them until a verified rewrap."""
        return version.startswith(TRANSIT_PREFIX)

    def wrap(self, dek: bytes, aad: bytes) -> WrappedKey:
        """``transit/encrypt`` with the AAD as associated data."""
        data = _data(
            self._access.call(
                lambda client: client.secrets.transit.encrypt_data(
                    name=self.key_id,
                    plaintext=_b64(dek),
                    associated_data=_b64(aad),
                    mount_point=self._mount,
                )
            )
        )
        ciphertext = str(data["ciphertext"])
        self._active = f"{TRANSIT_PREFIX}{int(data['key_version'])}"
        return WrappedKey(ciphertext.encode("ascii"), None, self.key_id, self._active)

    def unwrap(self, wrapped: WrappedKey, aad: bytes) -> bytes:
        """``transit/decrypt`` with the AAD as associated data."""
        if not self.covers(wrapped.key_version) or wrapped.key_id != self.key_id:
            raise KekError("the KEK generation this row needs is not configured")
        data = _data(
            self._access.call(
                lambda client: client.secrets.transit.decrypt_data(
                    name=self.key_id,
                    ciphertext=wrapped.wrapped_dek.decode("ascii"),
                    associated_data=_b64(aad),
                    mount_point=self._mount,
                )
            )
        )
        return base64.b64decode(str(data["plaintext"]), validate=True)

    def rewrap(self, wrapped: WrappedKey, aad: bytes) -> WrappedKey:
        """Decrypt, then encrypt under the latest transit version."""
        dek = bytearray(self.unwrap(wrapped, aad))
        try:
            return self.wrap(bytes(dek), aad)
        finally:
            dek[:] = bytes(len(dek))

    def probe(self) -> None:
        """``lookup-self`` and an encrypt → decrypt round trip of a constant."""
        self._access.call(lambda client: _data(client.auth.token.lookup_self()))
        self.unwrap(self.wrap(_PROBE, _PROBE), _PROBE)


__all__ = [
    "RELOGIN_AT",
    "TRANSIT_PREFIX",
    "VaultAccess",
    "VaultTransitKekProvider",
    "vault_session",
]
