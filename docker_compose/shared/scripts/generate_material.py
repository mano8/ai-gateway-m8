"""
Generate a stack's secret material, inside the gateway image (T87).

``init.sh`` pipes this file to ``python -`` in a throwaway container built
from this repository's image: no network, read-only root, no capabilities,
the host user's uid, and the stack's ``secrets/`` directory mounted at
``/out``. It needs nothing on the host but Docker.

Every file is created once with ``O_EXCL`` and mode ``0600`` and is never
overwritten, so re-running ``init.sh`` keeps every value. In particular
``ai_deployment_id`` is generated only when absent: the installation id is
never regenerated or rotated (C-14), and it is kept with the deployment's
secrets.

Non-secret derived values (key ids, public keys) go to ``/out/derived.env``,
which ``init.sh`` copies into the env files. No secret is ever printed.

Environment:
    STACK_VAULT   "1" when the stack runs the learning Vault (TLS material).
    STACK_DOMAIN  the stack's DOMAIN, named in Traefik's certificate.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import sys
import uuid
from pathlib import Path

from ai_sdk_m8.signed import (
    derive_kid,
    encode_public_key,
    generate_seed,
    load_seed_file,
    public_key_from_seed,
    write_seed_file,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from fastapi_m8 import ConsumerCredential

OUT = Path("/out")

#: The gateway's consumer id at the issuer (INTERNAL_CLIENT_ID).
GATEWAY_CLIENT_ID = "ai-gateway"
#: The scopes the issuer grants the gateway on its private API.
GATEWAY_ISSUER_SCOPES = ["introspection", "event-stream"]
#: The security suite's service client (T88) and its scopes.
TEST_CLIENT_ID = "security-tests"
TEST_CLIENT_SCOPES = [
    "execute:embedding",
    "execute:ocr",
    "execute:rerank",
    "execute:structured_output",
    "job-context:issue",
    "profiles:read",
]


def _create(name: str, data: bytes) -> bool:
    """Write ``data`` to a new ``0600`` file; ``False`` if it already exists."""
    try:
        fd = os.open(OUT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return True


def _exists(name: str) -> bool:
    return (OUT / name).exists()


#: The fleet's password alphabet: letters, digits and - _ . ~ (no shell, env
#: or URL metacharacters), and every class it requires.
_CLASSES = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "-_.~",
)
_ALPHABET = "".join(_CLASSES)


def _token(length: int = 48) -> bytes:
    """
    A random secret of ``length`` characters (> 300 bits) with every class.

    The fleet's settings refuse a password without an upper-case letter, a
    lower-case letter, a digit and a symbol, so one of each is guaranteed and
    the rest is drawn from the whole alphabet, then shuffled.
    """
    chars = [secrets.choice(group) for group in _CLASSES]
    chars += [secrets.choice(_ALPHABET) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars).encode("ascii")


def _key32() -> bytes:
    """A 32-byte key as its 44-character base64 text (the gateway's key-file form)."""
    return base64.b64encode(secrets.token_bytes(32))


def random_material() -> None:
    _create("ai_deployment_id", str(uuid.uuid4()).encode("ascii"))
    for name in (
        "postgres_password",
        "ai_owner_db_password",
        "ai_runtime_db_password",
        "auth_db_password",
        "redis_password",
        "gateway_secret_key",
        "gateway_refresh_secret_key",
        "gateway_access_secret_key",
        "event_signing_key",
        "issuer_refresh_secret_key",
        "issuer_private_api_secret",
        "issuer_session_secret",
        "issuer_tokens_encryption_key",
        "issuer_superuser_password",
        "health_detail_credential",
        "metrics_scrape_credential",
    ):
        _create(name, _token())
    if os.environ.get("STACK_VAULT") != "1":
        _create("ai_kek", _key32())
    _create("ai_fingerprint_key", _key32())


def _seed_file(name: str) -> bytes:
    """Create an Ed25519 seed file once, as ``jobcontext keygen`` writes it."""
    if not _exists(name):
        write_seed_file(OUT / name, generate_seed())
    return load_seed_file(OUT / name)


def signing_keys(derived: dict[str, str]) -> None:
    receipt = public_key_from_seed(_seed_file("ai_receipt_seed"))
    derived["AI_EXECUTION_RECEIPT_KID"] = derive_kid(receipt)
    issuer = public_key_from_seed(_seed_file("test_issuer_seed"))
    derived["TEST_ISSUER_KID"] = derive_kid(issuer)
    derived["TEST_ISSUER_PUBLIC_KEY"] = encode_public_key(issuer)


def _client_secret(name: str) -> str:
    _create(name, _token())
    return (OUT / name).read_text("ascii").strip()


def service_clients(derived: dict[str, str]) -> None:
    """The gateway's AI_SERVICE_CLIENTS and the issuer's PRIVATE_API_CONSUMERS."""
    if not _exists("ai_service_clients.json"):
        secret = _client_secret("test_client_secret")
        entry = {
            "secret": ConsumerCredential.create(TEST_CLIENT_ID, secret).encoded_secret,
            "scopes": TEST_CLIENT_SCOPES,
            "job_context_public_keys": {
                derived["TEST_ISSUER_KID"]: derived["TEST_ISSUER_PUBLIC_KEY"]
            },
        }
        _create(
            "ai_service_clients.json",
            json.dumps({TEST_CLIENT_ID: entry}, separators=(",", ":")).encode(),
        )
    # The issuer's row for the gateway holds only the salted digest; init.sh
    # writes it inline into auth.env (the issuer does not JSON-decode a
    # PRIVATE_API_CONSUMERS_FILE value).
    if not _exists("issuer_private_api_consumers.json"):
        secret = _client_secret("gateway_private_api_secret")
        entry = {
            "secret": ConsumerCredential.create(
                GATEWAY_CLIENT_ID, secret
            ).encoded_secret,
            "scopes": GATEWAY_ISSUER_SCOPES,
        }
        _create(
            "issuer_private_api_consumers.json",
            json.dumps({GATEWAY_CLIENT_ID: entry}, separators=(",", ":")).encode(),
        )
    derived["PRIVATE_API_CONSUMERS"] = (
        (OUT / "issuer_private_api_consumers.json").read_text("ascii").strip()
    )


def issuer_keys(derived: dict[str, str]) -> None:
    """The issuer's RS256 pair; the kid is the fleet's DER SHA-256 prefix."""
    if not _exists("issuer_private_key.pem"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _create(
            "issuer_private_key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _create(
            "issuer_public_key.pem",
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
    public = serialization.load_pem_public_key(
        (OUT / "issuer_public_key.pem").read_bytes()
    )
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    derived["ACCESS_KEY_ID"] = hashlib.sha256(der).hexdigest()[:16]


def _certificate(
    subject: str,
    public_key: ec.EllipticCurvePublicKey,
    issuer: x509.Name,
    signer: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    names: list[x509.GeneralName] | None = None,
) -> x509.Certificate:
    """
    An RFC 5280 certificate that passes strict verification.

    Python 3.13+ verifies with ``VERIFY_X509_STRICT``, which needs the key
    identifiers and key usage below; a minimal certificate is refused there
    even though Go and curl accept it.
    """
    now = datetime.datetime.now(datetime.UTC)
    usage = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    usage.update(key_cert_sign=ca, crl_sign=ca, digital_signature=not ca)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825 if not ca else 3650))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**usage), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
    )
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    return builder.sign(signer, hashes.SHA256())


def _server_pair(
    prefix: str,
    hostnames: list[str],
    ca_name: x509.Name,
    ca_key: ec.EllipticCurvePrivateKey,
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = [x509.DNSName(name) for name in hostnames]
    names.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    cert = _certificate(
        hostnames[0], key.public_key(), ca_name, ca_key, ca=False, names=names
    )
    _create(
        f"{prefix}_tls.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _create(f"{prefix}_tls.crt", cert.public_bytes(serialization.Encoding.PEM))


def stack_tls(vault: bool) -> None:
    """
    A stack-local CA, Traefik's certificate and, with Vault, Vault's.

    Learning-only: the CA key is discarded once both certificates exist, and a
    browser or client must trust ``stack_ca.pem`` explicitly.
    """
    if _exists("stack_ca.pem"):
        return
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "ai-gateway-m8 stack CA")]
    )
    ca = _certificate(
        "ai-gateway-m8 stack CA", ca_key.public_key(), ca_name, ca_key, ca=True
    )
    domain = os.environ.get("STACK_DOMAIN", "localhost")
    _server_pair("traefik", sorted({domain, "localhost"}), ca_name, ca_key)
    if vault:
        _server_pair("vault", ["vault", "localhost"], ca_name, ca_key)
    # The CA is created last: its presence marks the TLS set complete.
    _create("stack_ca.pem", ca.public_bytes(serialization.Encoding.PEM))


def main() -> int:
    derived: dict[str, str] = {}
    random_material()
    signing_keys(derived)
    service_clients(derived)
    issuer_keys(derived)
    stack_tls(vault=os.environ.get("STACK_VAULT") == "1")
    # Replaced, not rewritten: a stack start leaves it read-only (0400).
    (OUT / "derived.env").unlink(missing_ok=True)
    _create(
        "derived.env",
        "".join(f"{key}={value}\n" for key, value in sorted(derived.items())).encode(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
