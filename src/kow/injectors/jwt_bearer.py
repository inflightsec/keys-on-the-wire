"""JWT bearer minting (RFC 7519 structure; RFC 7515 JWS signing).

Mints a signed compact JWS (``header.payload.signature``) from a vault-held
signing key and operator-declared claims, for APIs / RFC 7523 flows that accept
a self-signed JWT. Supports ``HS256`` (shared secret, stdlib), ``RS256`` (RSA
PKCS#1 v1.5) and ``ES256`` (ECDSA P-256, raw R||S per RFC 7518 §3.4). The RSA/EC
signing uses the ``cryptography`` library already required by the daemon.

The minting core is pure (claims + key + algorithm in, token out); the resolver
stamps ``iat``/``exp`` from the request clock and calls it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from mitmproxy import http

from kow._fail_closed import emit_allowed, emit_denial_and_503
from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.denials import SigningKeyUnavailableError

if TYPE_CHECKING:
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.jwt_bearer")

_ES256_COORD_BYTES = 32  # P-256: r and s are each 32 bytes, big-endian.


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_compact(obj: dict[str, Any]) -> bytes:
    # JWS/JWT use compact JSON (no whitespace). Key order follows insertion.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encode(*, payload: dict[str, Any], key: str, algorithm: str) -> str:
    """Build and sign a compact JWT. ``payload`` is the full claim set."""
    header = {"alg": algorithm, "typ": "JWT"}
    signing_input = f"{_b64url(_json_compact(header))}.{_b64url(_json_compact(payload))}"
    signature = _sign(signing_input.encode("ascii"), key, algorithm)
    return f"{signing_input}.{_b64url(signature)}"


def _sign(signing_input: bytes, key: str, algorithm: str) -> bytes:
    if algorithm == "HS256":
        return hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if algorithm == "RS256":
        private_key = serialization.load_pem_private_key(key.encode("utf-8"), password=None)
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("jwt_bearer RS256 requires an RSA private key (PEM)")
        return private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    if algorithm == "ES256":
        private_key = serialization.load_pem_private_key(key.encode("utf-8"), password=None)
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ValueError("jwt_bearer ES256 requires an EC P-256 private key (PEM)")
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        # JOSE wants the raw fixed-width R||S concatenation, not the DER the
        # cryptography lib returns (RFC 7518 §3.4).
        return r.to_bytes(_ES256_COORD_BYTES, "big") + s.to_bytes(_ES256_COORD_BYTES, "big")
    raise ValueError(f"unsupported jwt_bearer algorithm {algorithm!r}")


class JwtResolver:
    """Mints a signed JWT and injects it as a bearer credential. Runs in the
    addon ``request`` hook — JWT does not need the body, but it rides the same
    computed-injector seam as sigv4/hmac for a single dispatch. Fail-closed on a
    key-fetch failure or a signing error (bad key / algorithm mismatch)."""

    def sign_and_apply(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        injector = decision.jwt_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            key = client.get(injector.signing_key_secret)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=SigningKeyUnavailableError.client_message,
                target_host=target_host,
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception("jwt signing-key fetch failed for %s: %s", secret_name, type(e).__name__)
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=SigningKeyUnavailableError.client_message,
                target_host=target_host,
            )
            return

        now = int(time.time())
        claims: dict[str, Any] = {}
        if injector.issuer is not None:
            claims["iss"] = injector.issuer
        if injector.subject is not None:
            claims["sub"] = injector.subject
        if injector.audience is not None:
            claims["aud"] = injector.audience
        claims["iat"] = now
        claims["exp"] = now + injector.ttl_seconds
        if injector.extra_claims:
            claims.update(injector.extra_claims)

        try:
            token = encode(payload=claims, key=key.reveal(), algorithm=injector.algorithm)
        except Exception as e:  # noqa: BLE001  (bad key / algorithm mismatch)
            _log.exception("jwt minting failed for %s: %s", secret_name, type(e).__name__)
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"jwt_signing_error:{type(e).__name__}",
                secret_name=secret_name,
                message=SigningKeyUnavailableError.client_message,
                target_host=target_host,
            )
            return

        flow.request.headers[header_name] = injector.format.replace("{jwt}", token)
        emit_allowed(
            audit=audit,
            flow=flow,
            request_id=request_id,
            secret_name=secret_name,
            binding_source=secret_spec.binding_source,
            target_host=target_host,
        )
