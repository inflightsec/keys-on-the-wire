"""OAuth 2.0 client-credentials grant injector (RFC 6749 §4.4).

Exchanges a vault-held client id + secret for a short-lived access token at the
configured token endpoint, caches it per-binding, and injects it as a bearer
credential. The machine-to-machine sibling of ``oauth2_refresh`` — same exchange
transport, TTL cache and audit shape, minus the refresh token and its rotation /
write-back. Resolves at ``requestheaders`` (no request body needed).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from mitmproxy import http

from kow._derived_token_cache import KeyInputs
from kow._fail_closed import emit_denial_and_503
from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.config import Oauth2ClientCredentialsInjector
from kow.denials import (
    OauthCcExchangeFailedError,
    OauthCcSecretUnavailableError,
)
from kow.injectors._minted import emit_token_exchange, inject_minted, mint_through_cache
from kow.injectors._token_transport import TokenResult, post

if TYPE_CHECKING:
    from kow._derived_token_cache import DerivedTokenCache
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.oauth2_client_credentials")


def exchange(
    spec: Oauth2ClientCredentialsInjector, client_id: str, client_secret: str
) -> TokenResult:
    """POST the client-credentials grant to the token endpoint (RFC 6749 §4.4)."""
    body_params: dict[str, str] = {"grant_type": "client_credentials"}
    if spec.scopes is not None:
        body_params["scope"] = spec.scopes
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if spec.client_auth_method == "basic":
        creds = f"{client_id}:{client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(creds).decode("ascii")
    else:
        body_params["client_id"] = client_id
        body_params["client_secret"] = client_secret
    return post(
        url=str(spec.token_url),
        data=urlencode(body_params).encode("utf-8"),
        headers=headers,
        on_success=lambda body: _parse_success(body, spec),
    )


def _parse_success(body_bytes: bytes, spec: Oauth2ClientCredentialsInjector) -> TokenResult:
    try:
        payload = json.loads(body_bytes)
    except (ValueError, json.JSONDecodeError):
        return TokenResult(outcome="response_parse_failed")
    if not isinstance(payload, dict) or "access_token" not in payload:
        return TokenResult(outcome="response_parse_failed")
    token_type = payload.get("token_type")
    if token_type is not None and (
        not isinstance(token_type, str) or token_type.lower() != "bearer"
    ):
        return TokenResult(outcome="unsupported_token_type")
    access_token = str(payload["access_token"])
    now = time.time()
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, int) and expires_in > 0:
        ttl = max(0, min(expires_in - spec.cache_ttl_safety_seconds, spec.cache_ttl_max_seconds))
        return TokenResult(outcome="success", token=access_token, expires_at=now + ttl)
    return TokenResult(
        outcome="success", token=access_token, expires_at=now + spec.cache_ttl_max_seconds
    )


class Oauth2CcResolver:
    """Executes a client-credentials verdict at requestheaders: fetch id+secret,
    cache-or-exchange, inject the access token. Fail-closed with 503 + audit."""

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
        injector = decision.oauth2_cc_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            client_id_value = client.get(injector.client_id_secret)
            client_secret_value = client.get(injector.client_secret_secret)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=OauthCcSecretUnavailableError.client_message,
                target_host=target_host,
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception("cc secret fetch failed for %s: %s", secret_name, type(e).__name__)
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=OauthCcSecretUnavailableError.client_message,
                target_host=target_host,
            )
            return

        # client_secret is folded into the cache key (repurposed refresh slot) so
        # a rotated secret invalidates the cached token (Oracle C4 invariant).
        cache_inputs = KeyInputs(
            binding_name=secret_name,
            token_url=str(injector.token_url),
            scopes=injector.scopes,
            client_id_value=client_id_value.reveal(),
            refresh_token_value=client_secret_value.reveal(),
        )
        token, result = mint_through_cache(
            token_cache,
            cache_inputs,
            lambda: exchange(injector, client_id_value.reveal(), client_secret_value.reveal()),
            OauthCcExchangeFailedError,
        )
        if result is not None:
            emit_token_exchange(
                audit,
                request_id,
                secret_name,
                str(injector.token_url),
                result,
            )
        if token is None:
            assert result is not None
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"token_exchange_failed:{result.outcome}",
                secret_name=secret_name,
                message=OauthCcExchangeFailedError.client_message,
                target_host=target_host,
            )
            return
        inject_minted(
            flow,
            audit,
            request_id,
            target_host,
            secret_name,
            secret_spec.binding_source,
            header_name,
            injector.render_value(access_token=token),
            companion_headers,
        )
