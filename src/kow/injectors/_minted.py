"""Shared steps for the token-minting resolvers (oauth2_cc, github_app,
gcp_service_account).

Each resolver keeps what is specific to it: which secrets it fetches, what
goes in the cache key, and how it mints. Everything after the mint lives here
once, so a fix to the deny path, the header write or the audit event lands in
every resolver at the same time. The three copies that existed before drifted
apart one resolver at a time (Oracle C1, C9). The CR/LF check is
NOT here: it runs at config load and at token parse.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from kow._fail_closed import emit_allowed
from kow.denials import ExchangeFailedError

if TYPE_CHECKING:
    from mitmproxy import http

    from kow._derived_token_cache import DerivedTokenCache, KeyInputs
    from kow.audit import AuditWriter
    from kow.injectors._token_transport import TokenResult


def mint_through_cache(
    token_cache: DerivedTokenCache,
    cache_inputs: KeyInputs,
    mint: Callable[[], TokenResult],
    error_cls: type[ExchangeFailedError],
) -> tuple[str | None, TokenResult | None]:
    """Cache-or-mint with one concurrent mint per key.

    Returns ``(token, result)``. ``result`` is the TokenResult to audit: set when
    this call minted (success) or when the mint failed, ``None`` on a cache hit
    or when another caller minted. ``token`` is ``None`` only on failure.
    """
    cached = token_cache.get(cache_inputs)
    if cached is not None:
        return cached, None

    holder: list[TokenResult] = []

    def _fetch() -> tuple[str, float]:
        result = mint()
        holder.append(result)
        if result.outcome != "success":
            raise error_cls(result)
        assert result.token is not None
        assert result.expires_at is not None
        return result.token, result.expires_at

    try:
        token = token_cache.dedup_or_fetch(cache_inputs, _fetch)
    except error_cls as exc:
        return None, exc.result
    # Only the leader that actually minted audits the exchange.
    return token, holder[0] if holder else None


def emit_token_exchange(
    audit: AuditWriter,
    request_id: str,
    secret_name: str,
    token_url: str,
    result: TokenResult,
    *,
    extra: Mapping[str, Any] | None = None,
    include_error_description: bool = True,
) -> None:
    """The ``token_exchange`` audit event. ``extra`` fields land after
    ``binding_name`` to keep the established field order."""
    event: dict[str, object] = {
        "type": "token_exchange",
        "request_id": request_id,
        "binding_name": secret_name,
        **(dict(extra) if extra else {}),
        "token_url_host": urlparse(token_url).hostname,
        "outcome": result.outcome,
    }
    if result.outcome == "success" and result.expires_at is not None:
        event["cache_ttl_effective_seconds"] = int(result.expires_at - time.time())
    if include_error_description and result.error_description is not None:
        event["error_description"] = result.error_description
    audit.emit(event)


def inject_minted(
    flow: http.HTTPFlow,
    audit: AuditWriter,
    request_id: str,
    target_host: str,
    secret_name: str,
    binding_source: str,
    header_name: str,
    header_value: str,
    companion_headers: dict[str, dict[str, str]],
) -> None:
    """Write the minted credential header, then audit the allow."""
    flow.request.headers[header_name] = header_value
    # Companion headers are DEFAULTS: set only when the client did not send one.
    for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
        if companion_name not in flow.request.headers:
            flow.request.headers[companion_name] = companion_value
    # G6 ORDERING — DO NOT REORDER. The header write above is in-memory only;
    # mitmproxy writes nothing upstream until requestheaders() returns, and
    # audit.emit() fsyncs synchronously, so the allow is durable first. Do not
    # defer the emit or return between the write and the emit.
    emit_allowed(
        audit=audit,
        flow=flow,
        request_id=request_id,
        secret_name=secret_name,
        binding_source=binding_source,
        target_host=target_host,
    )
