"""Generic HMAC request signing (RFC 2104).

Signs an operator-defined string, assembled from request parts, with
``HMAC-<hash>`` and emits the digest (hex or base64) into a header. HMAC signing
schemes are service-specific in *what* they sign, so the operator declares the
signing string via a small fixed token set (``{method}``, ``{path}``, ``{query}``,
``{host}``, ``{body_sha256}``, ``{timestamp}``); the signer does no further
service-specific canonicalisation. Pure and dependency-free (stdlib ``hmac``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import time
from typing import TYPE_CHECKING

from mitmproxy import http

from kow._fail_closed import emit_allowed, emit_denial_and_503
from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.denials import SigningKeyUnavailableError

if TYPE_CHECKING:
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.hmac_signer")

_HASHES = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# The tokens an operator may reference in ``signing_string``. Substituted by
# literal str.replace (never a format-language) so an operator template cannot
# reach attributes or execute anything.
SIGNING_STRING_TOKENS = ("{method}", "{path}", "{query}", "{host}", "{body_sha256}", "{timestamp}")


def build_signing_string(
    template: str,
    *,
    method: str,
    path: str,
    query: str,
    host: str,
    body: bytes,
    timestamp: str,
) -> str:
    """Substitute the request-part tokens in ``template``. ``{body_sha256}`` is
    the hex SHA-256 of the request body; unknown ``{...}`` text is left as-is."""
    body_sha256 = hashlib.sha256(body).hexdigest()
    return (
        template.replace("{method}", method)
        .replace("{path}", path)
        .replace("{query}", query)
        .replace("{host}", host)
        .replace("{body_sha256}", body_sha256)
        .replace("{timestamp}", timestamp)
    )


def hmac_sign(*, key: str, signing_string: str, algorithm: str, encoding: str) -> str:
    """HMAC-sign ``signing_string`` with ``key``. ``algorithm`` is one of
    :data:`_HASHES`; ``encoding`` is ``hex`` or ``base64``."""
    digest = hmac.new(
        key.encode("utf-8"), signing_string.encode("utf-8"), _HASHES[algorithm]
    ).digest()
    if encoding == "base64":
        return base64.b64encode(digest).decode("ascii")
    return digest.hex()


class HmacResolver:
    """Signs a ``hmac``-bound request in the addon ``request`` hook (after the
    body has buffered — the signing string may include ``{body_sha256}``) and
    writes the digest header. Fail-closed on a key-fetch failure."""

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
        injector = decision.hmac_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None

        try:
            key = client.get(injector.secret_key_secret)
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
            _log.exception("hmac key fetch failed for %s: %s", secret_name, type(e).__name__)
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

        timestamp = str(int(time.time()))
        path, _, query = flow.request.path.partition("?")
        signing_string = build_signing_string(
            injector.signing_string,
            method=flow.request.method,
            path=path,
            query=query,
            host=flow.request.host,
            body=flow.request.raw_content or b"",
            timestamp=timestamp,
        )
        signature = hmac_sign(
            key=key.reveal(),
            signing_string=signing_string,
            algorithm=injector.algorithm,
            encoding=injector.encoding,
        )
        flow.request.headers[injector.header] = signature
        if injector.timestamp_header is not None:
            flow.request.headers[injector.timestamp_header] = timestamp
        emit_allowed(
            audit=audit,
            flow=flow,
            request_id=request_id,
            secret_name=secret_name,
            binding_source=secret_spec.binding_source,
            target_host=target_host,
        )
