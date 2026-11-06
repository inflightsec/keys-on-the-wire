"""AWS Signature Version 4 request signing.

Pure, dependency-free implementation of the AWS SigV4 signing process
(``AWS4-HMAC-SHA256``): canonical request -> string to sign -> derived signing
key -> signature -> ``Authorization`` header. Written from the published AWS
SigV4 specification; verified against the AWS SigV4 test-suite ``get-vanilla``
vector in tests.

The signing function is pure (the request timestamp is passed in, not read from
a clock) so it is deterministic and testable against fixed vectors. The addon
handler stamps the real ``X-Amz-Date`` from the request clock and calls it.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlsplit

from mitmproxy import http

from kow._fail_closed import emit_allowed, emit_denial_and_503
from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.denials import Sigv4CredentialUnavailableError

if TYPE_CHECKING:
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.sigv4")

_ALGORITHM = "AWS4-HMAC-SHA256"

# The empty-string SHA-256, the payload hash for a body-less request.
EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True)
class Sigv4Result:
    """Headers the signer produces. The handler sets each on the outbound
    request. ``security_token`` is present only for temporary (STS) credentials."""

    authorization: str
    amz_date: str
    content_sha256: str
    security_token: str | None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _uri_encode(value: str, *, encode_slash: bool) -> str:
    # AWS: leave RFC 3986 unreserved (A-Za-z0-9-_.~) as-is; percent-encode
    # everything else with UPPERCASE hex. `quote` already uppercases and leaves
    # the unreserved set; `safe` decides whether '/' is preserved.
    safe = "" if encode_slash else "/"
    return quote(value, safe=safe)


def _canonical_uri(path: str) -> str:
    # A proxy signs the path as the service will receive it. Empty path -> "/".
    # Segments are URI-encoded but the separators are not.
    if not path:
        return "/"
    return _uri_encode(path, encode_slash=False)


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    # Sort by encoded key then encoded value; each name/value URI-encoded.
    pairs = [
        (_uri_encode(k, encode_slash=True), _uri_encode(v, encode_slash=True))
        for k, v in parse_qsl(query, keep_blank_values=True)
    ]
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def _canonical_headers(
    signed: dict[str, str],
) -> tuple[str, str]:
    # signed: already-lowercased header name -> value. Trim + collapse internal
    # whitespace runs, sort by name. Returns (canonical_headers_block,
    # signed_headers_list).
    names = sorted(signed)
    block = "".join(f"{n}:{_trim(signed[n])}\n" for n in names)
    return block, ";".join(names)


def _trim(value: str) -> str:
    # Strip leading/trailing whitespace and collapse sequential spaces to one
    # (AWS canonicalization for non-quoted header values).
    return " ".join(value.split())


def _derive_signing_key(secret_access_key: str, date: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sign(
    *,
    method: str,
    url: str,
    body: bytes,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service: str,
    amz_date: str,
    session_token: str | None = None,
    sign_content_sha256: bool = False,
    signed_headers_extra: dict[str, str] | None = None,
) -> Sigv4Result:
    """Sign a request per AWS SigV4. ``amz_date`` is the ``YYYYMMDDTHHMMSSZ``
    request timestamp (passed in so the function stays pure).

    Always signs ``host`` + ``x-amz-date`` (+ ``x-amz-security-token`` for
    temporary credentials). Two options extend the signed set:

    - ``sign_content_sha256`` adds ``x-amz-content-sha256`` (the payload hash) to
      both the signed set and the returned result. S3 *requires* this header to
      be present and signed; sending it is spec-valid for every service, so the
      request path always sets it. It stays off by default so the AWS
      ``get-vanilla`` conformance vector (a minimal-header case) still reproduces.
    - ``signed_headers_extra`` folds in any ``x-amz-*`` header the client already
      set. AWS rejects a request that carries an *unsigned* ``x-amz-*`` header,
      so the resolver passes through whatever the agent's SDK added (e.g.
      ``x-amz-acl``, ``x-amz-storage-class``). kow's computed headers take
      precedence over anything passed here.

    Returns the header values to set."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port is not None and not _is_default_port(parts.scheme, parts.port):
        host = f"{host}:{parts.port}"
    date = amz_date[:8]  # YYYYMMDD

    payload_hash = EMPTY_PAYLOAD_HASH if not body else _sha256_hex(body)

    signed_headers: dict[str, str] = {}
    if signed_headers_extra:
        for name, value in signed_headers_extra.items():
            signed_headers[name.lower()] = value
    # kow-computed headers overwrite any client-supplied collision.
    signed_headers["host"] = host
    signed_headers["x-amz-date"] = amz_date
    if sign_content_sha256:
        signed_headers["x-amz-content-sha256"] = payload_hash
    if session_token is not None:
        signed_headers["x-amz-security-token"] = session_token
    canonical_headers, signed_header_list = _canonical_headers(signed_headers)

    canonical_request = "\n".join(
        [
            method.upper(),
            _canonical_uri(parts.path),
            _canonical_query(parts.query),
            canonical_headers,
            signed_header_list,
            payload_hash,
        ]
    )

    credential_scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            _ALGORITHM,
            amz_date,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )

    signing_key = _derive_signing_key(secret_access_key, date, region, service)
    signature = _hmac(signing_key, string_to_sign).hex()

    authorization = (
        f"{_ALGORITHM} "
        f"Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_header_list}, "
        f"Signature={signature}"
    )
    return Sigv4Result(
        authorization=authorization,
        amz_date=amz_date,
        content_sha256=payload_hash,
        security_token=session_token,
    )


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (scheme == "http" and port == 80)


# x-amz-* headers kow computes and sets itself; never folded in from the client
# (we overwrite them with freshly computed values).
_MANAGED_AMZ_HEADERS = frozenset({"x-amz-date", "x-amz-content-sha256", "x-amz-security-token"})


def _client_amz_headers(headers: http.Headers) -> dict[str, str]:
    """The ``x-amz-*`` headers the client already set, minus the ones kow
    computes. These MUST be signed (AWS rejects an unsigned ``x-amz-*`` header),
    and are left on the outbound request verbatim so the signed value matches
    the value on the wire."""
    extra: dict[str, str] = {}
    for name in headers:
        lname = name.lower()
        if lname.startswith("x-amz-") and lname not in _MANAGED_AMZ_HEADERS:
            extra[lname] = headers[name]
    return extra


class Sigv4Resolver:
    """Signs a ``sigv4``-bound request and applies the AWS auth headers.

    Runs in the addon ``request`` hook (NOT ``requestheaders``) because SigV4
    hashes the full request body, which is only buffered by then. Mirrors
    ``OauthResolver``'s fetch -> compute -> inject -> audit shape, minus the
    network exchange and derived-token cache (signing is local + deterministic).
    Fail-closed: a credential-fetch failure denies with 503 and audits, exactly
    like the header/oauth paths.
    """

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
        injector = decision.sigv4_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            access_key_id = client.get(injector.access_key_id_secret)
            secret_access_key = client.get(injector.secret_access_key_secret)
            session_token = (
                client.get(injector.session_token_secret)
                if injector.session_token_secret is not None
                else None
            )
        except (BackendUnavailableError, SecretNotFoundError) as e:
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=Sigv4CredentialUnavailableError.client_message,
                target_host=target_host,
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception(
                "unexpected backend exception fetching sigv4 credentials for %s: %s",
                secret_name,
                type(e).__name__,
            )
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=Sigv4CredentialUnavailableError.client_message,
                target_host=target_host,
            )
            return

        amz_date = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        # Hash the RAW bytes that go on the wire (what the service receives and
        # hashes), not the content-decoded view — SigV4 signs the payload as
        # sent. kow does not mutate a sigv4 request's body, so raw_content is
        # forwarded verbatim.
        result = sign(
            method=flow.request.method,
            url=flow.request.url,
            body=flow.request.raw_content or b"",
            access_key_id=access_key_id.reveal(),
            secret_access_key=secret_access_key.reveal(),
            region=injector.region,
            service=injector.service,
            amz_date=amz_date,
            session_token=session_token.reveal() if session_token is not None else None,
            sign_content_sha256=True,
            signed_headers_extra=_client_amz_headers(flow.request.headers),
        )

        # Mutate in place. No bytes leave the proxy until this hook returns, so
        # the G6 audit-before-write ordering holds with the emit below.
        flow.request.headers[header_name] = result.authorization
        flow.request.headers["x-amz-date"] = result.amz_date
        # S3 requires x-amz-content-sha256 be present AND signed; we signed it
        # above, so it must go on the wire with the exact value we hashed.
        flow.request.headers["x-amz-content-sha256"] = result.content_sha256
        if result.security_token is not None:
            flow.request.headers["x-amz-security-token"] = result.security_token

        emit_allowed(
            audit=audit,
            flow=flow,
            request_id=request_id,
            secret_name=secret_name,
            binding_source=secret_spec.binding_source,
            target_host=target_host,
        )
