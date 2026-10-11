"""Google service-account authority, brokered three ways (ADR-0050).

``self_signed_jwt``
    Sign an RS256 assertion with the vault-held service-account key and present
    it directly as the bearer credential. No network call, no token cache.

``jwt_bearer_grant``
    Sign the same assertion with ``aud`` set to Google's token endpoint and
    exchange it there under RFC 7523 §2.1 for an access token.

``impersonate`` (default)
    Call IAM Credentials ``generateAccessToken`` on the target service account.
    No key exists for the target. The *source* identity is either the daemon's
    Application Default Credentials or a vault-held impersonation-seat key, per
    ADR-0050 decision 4.

All three end in the same place: an ``Authorization`` header on the upstream
request that the agent never saw. Signing reuses :mod:`kow.injectors.jwt_bearer`;
egress reuses the SSRF-guarded, address-pinned transport shared by the other
token-minting injectors; caching reuses :class:`DerivedTokenCache` with every
mint input folded into the key, so a rotated credential invalidates the cache.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import quote, urlencode, urlparse

from mitmproxy import http

from kow._derived_token_cache import KeyInputs
from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.config import GcpServiceAccountInjector
from kow.denials import GcpKeyUnavailableError, GcpMintFailedError
from kow.injectors._token_transport import TokenResult, post
from kow.injectors.jwt_bearer import encode as jwt_encode

if TYPE_CHECKING:
    from kow._derived_token_cache import DerivedTokenCache
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.gcp_service_account")

_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# The seat only ever needs to call generateAccessToken; cloud-platform is the
# scope that authorizes it. The TARGET's reach is bounded by its own IAM roles
# and by the scopes requested for the minted token, not by this one.
_SOURCE_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# iat is backdated for clock skew, the same margin the App JWT uses.
_IAT_SKEW_SECONDS = 60
# A self-signed assertion is the credential itself, so its own exp is the TTL.
_SELF_SIGNED_SAFETY_SECONDS = 30
# Google access tokens live at most an hour; a longer claimed expiry is either a
# broken endpoint or a hostile one, and either way must not pin the cache.
_MAX_TOKEN_TTL_SECONDS = 3600


def _assertion(
    injector: GcpServiceAccountInjector,
    key_pem: str,
    *,
    audience: str | None,
    self_signed: bool,
) -> str:
    """The RS256 assertion.

    ``sub`` is present ONLY for the two cases Google defines it for: a delegated
    Workspace user (domain-wide delegation), and the self-signed JWT form where
    ``sub`` equals ``iss``. On an ordinary RFC 7523 exchange Google reads ``sub``
    as "act as this user" and rejects the assertion when that user is the service
    account itself, which is why google-auth omits it there (Oracle review,
    2026-09-11 — the first draft sent it on every assertion).

    ``exp`` is computed from the backdated ``iat`` rather than from now, so the
    total assertion lifetime can never exceed Google's one-hour ceiling.
    """
    iat = int(time.time()) - _IAT_SKEW_SECONDS
    claims: dict[str, object] = {
        "iss": injector.service_account_email,
        "iat": iat,
        "exp": iat + injector.assertion_ttl_seconds,
    }
    if audience is not None:
        claims["aud"] = audience
    if injector.subject is not None:
        claims["sub"] = injector.subject
    elif self_signed:
        claims["sub"] = injector.service_account_email
    if injector.scopes:
        claims["scope"] = injector.scopes
    return jwt_encode(payload=claims, key=key_pem, algorithm="RS256")


def _seat_assertion(injector: GcpServiceAccountInjector, key_pem: str) -> str:
    """The assertion the impersonation seat signs for itself. It requests only
    the scope needed to call generateAccessToken, never the target's scopes."""
    now = int(time.time())
    assert injector.source_service_account_email is not None
    iat = now - _IAT_SKEW_SECONDS
    return jwt_encode(
        payload={
            # No `sub`: this is an ordinary RFC 7523 exchange, not delegation.
            "iss": injector.source_service_account_email,
            "aud": str(injector.token_url),
            "scope": _SOURCE_SCOPE,
            "iat": iat,
            "exp": iat + injector.assertion_ttl_seconds,
        },
        key=key_pem,
        algorithm="RS256",
    )


def mint_self_signed(injector: GcpServiceAccountInjector, key_pem: str) -> TokenResult:
    """Mode 1: the signed assertion IS the credential. No network call.

    Google defines two self-signed forms: ``aud`` set to the service endpoint, or
    ``scope`` with no ``aud`` at all. The config validator requires one of them;
    sending a token-endpoint ``aud`` in the scopes-only form (the first draft's
    behaviour) is neither.
    """
    try:
        token = _assertion(injector, key_pem, audience=injector.audience, self_signed=True)
    except Exception as e:  # noqa: BLE001  (malformed / non-RSA key)
        _log.exception("gcp self-signed JWT mint failed: %s", type(e).__name__)
        return TokenResult(outcome=f"assertion_error:{type(e).__name__}")
    # exp is iat + ttl, and iat is backdated, so the usable window from now is
    # ttl - skew; take a further safety margin off before caching.
    expires_at = (
        time.time() + injector.assertion_ttl_seconds - _IAT_SKEW_SECONDS
    ) - _SELF_SIGNED_SAFETY_SECONDS
    return TokenResult(outcome="success", token=token, expires_at=expires_at)


def _parse_oauth_token(body: bytes, injector: GcpServiceAccountInjector) -> TokenResult:
    """Parse an RFC 6749 §5.1 success body, strictly.

    A 200 with a malformed body is a failure, not a credential: coercing whatever
    arrived into a token and caching it is how a broken or hostile endpoint gets
    its content injected into upstream requests.
    """
    try:
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return TokenResult(outcome="response_parse_failed")
    if not isinstance(payload, dict):
        return TokenResult(outcome="response_parse_failed")
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        return TokenResult(outcome="response_parse_failed")
    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        return TokenResult(outcome="response_parse_failed")
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)):
        return TokenResult(outcome="response_parse_failed")
    if expires_in <= 0:
        return TokenResult(outcome="response_parse_failed")
    ttl = min(float(expires_in), float(_MAX_TOKEN_TTL_SECONDS))
    ttl = max(0.0, ttl - injector.cache_ttl_safety_seconds)
    return TokenResult(outcome="success", token=token, expires_at=time.time() + ttl)


def exchange_jwt_bearer(
    injector: GcpServiceAccountInjector, key_pem: str, *, assertion: str | None = None
) -> TokenResult:
    """Mode 2 (and the seat leg of mode 3): RFC 7523 §2.1 assertion exchange."""
    try:
        signed = (
            assertion
            if assertion is not None
            else _assertion(injector, key_pem, audience=str(injector.token_url), self_signed=False)
        )
    except Exception as e:  # noqa: BLE001
        _log.exception("gcp assertion mint failed: %s", type(e).__name__)
        return TokenResult(outcome=f"assertion_error:{type(e).__name__}")
    body = urlencode({"grant_type": _JWT_BEARER_GRANT, "assertion": signed}).encode("ascii")
    return post(
        url=str(injector.token_url),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        on_success=lambda raw: _parse_oauth_token(raw, injector),
    )


def adc_access_token() -> str:
    """The daemon's own Application Default Credentials, as a bearer token.

    Lazy ``google-auth`` import so importing this module never requires the
    optional dependency, and so tests can patch this function wholesale. This is
    the single egress seam for the ADC source leg.
    """
    from kow.backends import require

    with require("gsm", "google-auth", "gsm"):
        import google.auth
        from google.auth.transport.requests import Request as GoogleAuthRequest

    creds, _ = google.auth.default(scopes=[_SOURCE_SCOPE])
    if not creds.valid:
        creds.refresh(GoogleAuthRequest())
    if not creds.token:
        raise BackendUnavailableError("application-default credentials produced no token")
    return str(creds.token)


def _generate_access_token_url(injector: GcpServiceAccountInjector) -> str:
    # The wildcard project ('-') is Google's documented form: the target service
    # account's own project is resolved from its email.
    target = quote(injector.service_account_email, safe="")
    return (
        f"{injector.iam_credentials_base_url}/v1/projects/-/serviceAccounts/"
        f"{target}:generateAccessToken"
    )


def _parse_iam_token(body: bytes, injector: GcpServiceAccountInjector) -> TokenResult:
    """Parse a generateAccessToken response, strictly, and CLAMP the lifetime.

    The clamp matters: a response claiming an expiry years away would otherwise
    pin one token in the cache for that long, so the cached TTL can never exceed
    what this binding actually requested.
    """
    try:
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return TokenResult(outcome="response_parse_failed")
    if not isinstance(payload, dict):
        return TokenResult(outcome="response_parse_failed")
    token = payload.get("accessToken")
    if not isinstance(token, str) or not token:
        return TokenResult(outcome="response_parse_failed")
    now = time.time()
    expire_time = payload.get("expireTime")
    exp_unix: float | None = None
    if isinstance(expire_time, str):
        try:
            exp_unix = datetime.fromisoformat(expire_time.replace("Z", "+00:00")).timestamp()
        except ValueError:
            exp_unix = None
    ceiling = now + injector.lifetime_seconds
    if exp_unix is None or exp_unix <= now:
        exp_unix = ceiling
    exp_unix = min(exp_unix, ceiling)
    ttl = max(0.0, exp_unix - now - injector.cache_ttl_safety_seconds)
    return TokenResult(outcome="success", token=token, expires_at=now + ttl)


def impersonate(injector: GcpServiceAccountInjector, source_token: str) -> TokenResult:
    """Mode 3: mint a token for the target service account with the source
    identity's authority. No key for the target exists anywhere."""
    assert injector.scopes is not None
    body = json.dumps(
        {
            "scope": injector.scopes.split(),
            "lifetime": f"{injector.lifetime_seconds}s",
        }
    ).encode("utf-8")
    return post(
        url=_generate_access_token_url(injector),
        data=body,
        headers={
            "Authorization": f"Bearer {source_token}",
            "Content-Type": "application/json",
        },
        on_success=lambda raw: _parse_iam_token(raw, injector),
    )


def mint(injector: GcpServiceAccountInjector, key_pem: str | None) -> TokenResult:
    """Dispatch one mint attempt for the configured mode. Pure apart from the
    egress the two network modes perform through the shared transport."""
    if injector.mode == "self_signed_jwt":
        assert key_pem is not None
        return mint_self_signed(injector, key_pem)
    if injector.mode == "jwt_bearer_grant":
        assert key_pem is not None
        return exchange_jwt_bearer(injector, key_pem)
    # impersonate
    if injector.source == "seat_key":
        assert key_pem is not None
        try:
            seat_assertion = _seat_assertion(injector, key_pem)
        except Exception as e:  # noqa: BLE001
            _log.exception("gcp seat assertion mint failed: %s", type(e).__name__)
            return TokenResult(outcome=f"assertion_error:{type(e).__name__}")
        seat = exchange_jwt_bearer(injector, key_pem, assertion=seat_assertion)
        if seat.outcome != "success" or seat.token is None:
            return TokenResult(outcome=f"source_token_failed:{seat.outcome}")
        source_token = seat.token
    else:
        try:
            source_token = adc_access_token()
        except Exception as e:  # noqa: BLE001  (missing dep, no ADC, refresh failure)
            _log.warning("gcp ADC source token unavailable: %s", type(e).__name__)
            return TokenResult(outcome=f"source_token_failed:{type(e).__name__}")
    return impersonate(injector, source_token)


def _cache_identity(injector: GcpServiceAccountInjector) -> str:
    """Every mint-affecting field, length-prefixed so values cannot collide."""
    parts = [
        injector.mode,
        injector.source,
        injector.service_account_email,
        injector.source_service_account_email or "",
        injector.subject or "",
        injector.audience or "",
        str(injector.token_url),
        injector.iam_credentials_base_url,
        str(injector.assertion_ttl_seconds),
        str(injector.lifetime_seconds),
    ]
    return "|".join(f"{len(p)}:{p}" for p in parts)


def _mint_endpoint(injector: GcpServiceAccountInjector) -> str:
    """The endpoint this mode actually talks to — audited as a host, and folded
    into the cache key so a retargeted binding cannot reuse a cached token."""
    if injector.mode == "impersonate":
        return _generate_access_token_url(injector)
    return str(injector.token_url)


class GcpServiceAccountResolver:
    """Executes a gcp_service_account verdict at requestheaders: fetch the key
    (when the mode has one), cache-or-mint, inject. Fail-closed with 503."""

    def resolve(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        companion_headers: dict[str, dict[str, str]],
        token_cache: DerivedTokenCache,
    ) -> None:
        injector = decision.gcp_sa_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        key_pem: str | None = None
        if injector.private_key_secret is not None:
            try:
                key_pem = client.get(injector.private_key_secret).reveal()
            except (BackendUnavailableError, SecretNotFoundError) as e:
                self._deny(
                    flow, audit, request_id, secret_name, target_host, e, "secret_unavailable"
                )
                return
            except Exception as e:  # noqa: BLE001
                _log.exception("gcp key fetch failed for %s: %s", secret_name, type(e).__name__)
                self._deny(
                    flow, audit, request_id, secret_name, target_host, e, "secret_fetch_error"
                )
                return

        # Every input that changes the minted credential is in the key: mode,
        # target, delegated subject, scopes, endpoint, and the key material's
        # hash (or the literal 'adc' when there is none).
        cache_inputs = KeyInputs(
            binding_name=secret_name,
            token_url=_mint_endpoint(injector),
            scopes=injector.scopes,
            # Every field that changes what gets minted, length-prefixed so no
            # combination of values can collide by concatenation. The full-reload
            # path drops the cache anyway, but the ADR-0032 background notes
            # refresh keeps it warm, so completeness here is load-bearing rather
            # than belt-and-braces (Oracle review, 2026-09-11).
            client_id_value=_cache_identity(injector),
            refresh_token_value=(
                hashlib.sha256(key_pem.encode("utf-8")).hexdigest() if key_pem else "adc"
            ),
        )
        cached = token_cache.get(cache_inputs)
        if cached is not None:
            self._inject(
                flow,
                audit,
                request_id,
                target_host,
                secret_name,
                secret_spec,
                injector,
                header_name,
                cached,
                companion_headers,
            )
            return

        holder: list[TokenResult] = []

        def _fetch() -> tuple[str, float]:
            result = mint(injector, key_pem)
            holder.append(result)
            if result.outcome != "success":
                raise GcpMintFailedError(result)
            assert result.token is not None
            assert result.expires_at is not None
            return result.token, result.expires_at

        try:
            token = token_cache.dedup_or_fetch(cache_inputs, _fetch)
        except GcpMintFailedError as exc:
            result = exc.result
        else:
            if holder:
                self._emit_token_exchange(audit, request_id, secret_name, injector, holder[0])
            self._inject(
                flow,
                audit,
                request_id,
                target_host,
                secret_name,
                secret_spec,
                injector,
                header_name,
                token,
                companion_headers,
            )
            return

        self._emit_token_exchange(audit, request_id, secret_name, injector, result)
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "denied",
                "reason": f"token_exchange_failed:{result.outcome}",
                "secret_name": secret_name,
                "destination": {"host": target_host, "port": flow.request.port},
            }
        )
        flow.response = http.Response.make(
            503, GcpMintFailedError.client_message, {"Content-Type": "text/plain"}
        )

    def _inject(
        self,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        secret_name: str,
        secret_spec: object,
        injector: GcpServiceAccountInjector,
        header_name: str,
        token: str,
        companion_headers: dict[str, dict[str, str]],
    ) -> None:
        flow.request.headers[header_name] = injector.render_value(access_token=token)
        for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
            if companion_name not in flow.request.headers:
                flow.request.headers[companion_name] = companion_value
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                "binding_source": secret_spec.binding_source,  # type: ignore[attr-defined]
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    def _emit_token_exchange(
        self,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        injector: GcpServiceAccountInjector,
        result: TokenResult,
    ) -> None:
        event: dict[str, object] = {
            "type": "token_exchange",
            "request_id": request_id,
            "binding_name": secret_name,
            # ``mode`` is security-relevant, not cosmetic: the three modes are
            # materially different trust paths, and without this an auditor
            # cannot tell a keyless network mint (`impersonate`) from one that
            # used a vault-held private key (`jwt_bearer_grant`) from one that
            # never made a network call at all (`self_signed_jwt`). They would
            # all read as an identical `token_exchange`. Adding a FIELD to an
            # existing event keeps ADR-0023's closed set of event TYPES intact.
            # (Oracle review, 2026-09-16.)
            "mode": injector.mode,
            "token_url_host": urlparse(_mint_endpoint(injector)).hostname,
            "outcome": result.outcome,
        }
        if result.outcome == "success" and result.expires_at is not None:
            event["cache_ttl_effective_seconds"] = int(result.expires_at - time.time())
        # Deliberately NOT audited: ``result.error_description`` is provider
        # text. The IAM leg sends a real source token in the request, so a
        # compromised or misconfigured endpoint can reflect it in an error body,
        # and the audit log is durable. Only the locally-derived outcome label
        # goes in (Oracle review, 2026-09-11).
        audit.emit(event)

    def _deny(
        self,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        target_host: str,
        err: Exception,
        reason_prefix: str,
    ) -> None:
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "denied",
                "reason": f"{reason_prefix}:{type(err).__name__}",
                "secret_name": secret_name,
                "destination": {"host": target_host, "port": flow.request.port},
            }
        )
        flow.response = http.Response.make(
            503, GcpKeyUnavailableError.client_message, {"Content-Type": "text/plain"}
        )
