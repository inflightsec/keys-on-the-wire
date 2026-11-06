"""OAuth2 refresh-token exchange (ADR-0017 slice 5).

Synchronous core of the resolution step that lands in slice 6. Given
the spec + the three resolved BWS-held secrets, this module:

  1. Re-runs the SSRF guard on ``spec.token_url`` (DNS rebinding
     defense — config-load-time check is not enough; a public name
     can resolve to a private address minutes later).
  2. Builds an RFC 6749 §6 refresh-token grant POST body. Client
     auth method (body_post / basic) per the spec.
  3. Issues one POST via the shared pinned token transport. One retry
     on 5xx with 1 s backoff; no retry on 4xx (credential / scope,
     not transient).
  4. Parses the response per §5.1 (success) and §5.2 (error JSON).
     Categorises the outcome into the audit vocabulary fixed by the
     ADR §7 event taxonomy.

The async wrapper :func:`exchange_async` dispatches the synchronous
:func:`exchange` through ``loop.run_in_executor`` so a slow token
endpoint does not block the mitmproxy asyncio loop.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
import unicodedata
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse

from mitmproxy import http

from kow._derived_token_cache import DerivedTokenCache, KeyInputs
from kow._ssrf_guard import SsrfBlockedError, check_url_not_internal
from kow._textguard import has_forbidden_char
from kow.backends import (
    BackendNotWritableError,
    BackendUnavailableError,
    BackendWriteConflictError,
    SecretNotFoundError,
)
from kow.config import Oauth2RefreshInjector, SecretSpec
from kow.denials import (
    OauthExchangeFailedError,
    OauthInputFetchFailedError,
    OauthInputUnavailableError,
)
from kow.injectors._token_transport import transport_open

if TYPE_CHECKING:
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.policy import Decision

_log = logging.getLogger("kow.injectors.oauth2_refresh")

_RETRY_BACKOFF_SECONDS = 1.0


# Refresh-token shape guard (slice 7 hardening — Oracle F1 / Silas #2).
# An upstream returning a junk ``refresh_token`` field (single byte,
# all-zero, 10 MB blob, control chars) can otherwise drive kow into
# PUTing that value to BWS and permanently bricking the binding — the
# prior value is overwritten with no live backup. Bounds are RFC 6749
# §A.17 (vschar = %x20-7E) plus a generous length envelope.
_MIN_REFRESH_TOKEN_LEN = 8
_MAX_REFRESH_TOKEN_LEN = 4096


def is_well_formed_refresh_token(value: str) -> bool:
    if not _MIN_REFRESH_TOKEN_LEN <= len(value) <= _MAX_REFRESH_TOKEN_LEN:
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in value)


# Provider-supplied ``error_description`` is attacker-influenceable (a hostile or compromised
# public token endpoint passes the SSRF guard, which only blocks internal hosts) and lands in the
# fsynced audit stream. Strip control/format chars and cap the length before it is emitted, so a
# reflected secret / injected control sequence can't ride into the "no secret material" log (Silas
# M2 — mirrors the CLI's clean+cap discipline).
_MAX_ERROR_DESCRIPTION = 200
_ERR_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _sanitize_error_description(text: str) -> str:
    cleaned = "".join(ch for ch in text if unicodedata.category(ch) not in _ERR_UNSAFE_CATEGORIES)
    return cleaned[:_MAX_ERROR_DESCRIPTION]


@dataclass(frozen=True)
class ExchangeResult:
    """One token-exchange attempt's outcome.

    ``outcome`` is the audit-event vocabulary label fixed by the ADR.
    Every successful exchange populates ``access_token`` and
    ``expires_at``; failures populate ``error_description`` when the
    upstream supplied one (RFC 6749 §5.2). ``new_refresh_token`` is
    non-None ONLY when the upstream issued one that differs from the
    one fed in — write-back path (slice 7) keys off that exact
    semantic.

    ``used_default_expiry`` flips true when the upstream omits
    ``expires_in`` and we fell back to ``spec.cache_ttl_max_seconds``;
    the audit layer surfaces this distinctly so operators can flag
    under-spec providers.
    """

    outcome: str
    access_token: str | None = None
    expires_at: float | None = None
    new_refresh_token: str | None = None
    error_description: str | None = None
    used_default_expiry: bool = False


# Shared executor for the async path. ``run_in_executor(None, ...)``
# would use the default loop executor, but we want a small dedicated
# pool so a refresh-storm at boot doesn't starve other loop-side work.
_SHARED_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="kow-oauth-exchange")


def _transport_open(req: urllib.request.Request, timeout: float) -> Any:
    """Single egress seam for the token exchange — tests patch THIS name.

    Forwards to the shared pinned token transport and remains as the
    local patch point the refresh-token tests intercept.
    """
    return transport_open(req, timeout)


def exchange(  # noqa: C901  # SSRF + retry + redirect-check branches inherent to the spec
    spec: Oauth2RefreshInjector,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    *,
    timeout_seconds: float = 10.0,
) -> ExchangeResult:
    """Synchronous token exchange — one POST, with one retry on 5xx.

    Returns an :class:`ExchangeResult`; never raises (except for
    programmer errors). The categorised outcome is the audit signal.
    """
    # Request-time SSRF re-check. The config-load check was a starting
    # point; DNS rebinding makes "passed once" insufficient.
    assert spec.token_url is not None  # config XOR validator guarantees
    try:
        check_url_not_internal(spec.token_url)
    except SsrfBlockedError as e:
        _log.warning("token_url SSRF-blocked at runtime: %s", e)
        return ExchangeResult(outcome="ssrf_blocked")

    body_params: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if spec.scopes is not None:
        body_params["scope"] = spec.scopes
    headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    if spec.client_auth_method == "basic":
        creds = f"{client_id}:{client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(creds).decode("ascii")
    else:
        body_params["client_id"] = client_id
        body_params["client_secret"] = client_secret

    body = urlencode(body_params).encode("utf-8")
    # Linter suppressions on the urllib calls below: the scheme is
    # constrained to https by ``Oauth2RefreshInjector.resolve_preset_xor``
    # (Pydantic ``HttpUrl`` + explicit https assertion) and the URL is then
    # re-checked at request time against the SSRF guard. file://, gopher://,
    # data://, etc. cannot reach this code path.
    # User-Agent: identify kow rather than ship the default
    # ``Python-urllib/3.X`` (some providers block stock urllib UA outright,
    # producing confusing 4xx; identifying kow also helps providers
    # whitelist explicitly when needed).
    headers["User-Agent"] = "kow/oauth2-refresh"
    req = urllib.request.Request(  # noqa: S310  # nosec
        str(spec.token_url),
        data=body,
        headers=headers,
        method="POST",
    )
    # One initial attempt; one retry only on 5xx. Transport goes through
    # the module-level no-redirect seam: a 3xx is never followed and
    # surfaces as ``HTTPError`` below (ADR-0017 hardening series — this
    # replaces the former ``resp.geturl()`` post-check, which could only
    # distrust a redirected response AFTER the redirected host had
    # already been contacted).
    for attempt in (0, 1):
        try:
            with _transport_open(req, timeout=timeout_seconds) as resp:
                return _parse_success(resp.read(), refresh_token, spec)
        except SsrfBlockedError as e:
            _log.warning("token_url SSRF-blocked during transport resolve: %s", e)
            return ExchangeResult(outcome="ssrf_blocked")
        except HTTPError as e:
            status = e.code
            body_bytes = _safe_read(e)
            if 300 <= status < 400:
                # Redirect refused at the opener, never followed. A
                # redirecting token endpoint is deterministic misconfig
                # or hostility — no retry.
                _log.warning(
                    "token endpoint answered %d redirect; refused (never followed)",
                    status,
                )
                return _parse_error(status, body_bytes)
            if 400 <= status < 500:
                return _parse_error(status, body_bytes)
            # 5xx — retry once with backoff.
            if attempt == 0:
                # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            return _parse_error(status, body_bytes)
        except (URLError, TimeoutError) as e:
            # Transport-level. URLError covers both DNS and refused;
            # TimeoutError catches the urlopen timeout. Retry once.
            if attempt == 0:
                # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            _log.info("token endpoint unreachable: %s", e)
            return ExchangeResult(outcome="token_endpoint_unreachable")

    # Loop fell through both attempts without returning — shouldn't
    # happen but defensive.
    return ExchangeResult(outcome="token_endpoint_unreachable")


def _safe_read(err: HTTPError) -> bytes:
    """Read the error response body; never raise. ``HTTPError`` carries
    the body as an ``fp`` whose ``.read()`` is single-shot."""
    try:
        return err.read()
    except Exception:  # noqa: BLE001
        return b""


def _parse_success(
    body_bytes: bytes,
    refresh_token_in: str,
    spec: Oauth2RefreshInjector,
) -> ExchangeResult:
    """Parse a 200 response per RFC 6749 §5.1.

    ``access_token`` is REQUIRED, ``token_type`` is REQUIRED (we
    accept only Bearer per RFC 6750), ``expires_in`` is OPTIONAL —
    when omitted, fall back to the spec's ``cache_ttl_max_seconds``
    and flag the result.
    """
    try:
        payload = json.loads(body_bytes)
    except (ValueError, json.JSONDecodeError):
        return ExchangeResult(outcome="response_parse_failed")
    if not isinstance(payload, dict) or "access_token" not in payload:
        return ExchangeResult(outcome="response_parse_failed")

    # RFC 6749 §5.1 says ``token_type`` is REQUIRED in the response.
    # RFC 6750 §1.2 says the "Bearer" scheme is case-insensitive. kow
    # only knows how to inject a Bearer token (its ``access_token_format``
    # default is ``"Bearer {access_token}"``); if the upstream returned
    # a different scheme — legacy MAC tokens, vendor extensions like
    # ``DPoP`` — injecting it as a Bearer header would either fail
    # upstream auth or, worse, silently send credentials in a
    # malformed scheme. Reject upfront so the operator sees a clean
    # ``unsupported_token_type`` audit signal rather than a confused
    # upstream 401. ``token_type`` ABSENT (some providers omit it
    # despite the RFC) is accepted with a warning — being strict would
    # break legitimate exchanges against under-spec providers.
    token_type = payload.get("token_type")
    if token_type is not None:
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            _log.warning(
                "token endpoint returned unsupported token_type=%r; kow only injects Bearer",
                token_type,
            )
            return ExchangeResult(outcome="unsupported_token_type")
    else:
        _log.info(
            "token endpoint omitted ``token_type`` (RFC 6749 §5.1 REQUIRED); "
            "accepting and assuming Bearer"
        )

    access_token = str(payload["access_token"])
    # The resolver injects this straight into a header (C1, review of 1.2.0).
    if has_forbidden_char(access_token):
        return ExchangeResult(outcome="response_parse_failed")
    expires_in = payload.get("expires_in")
    now = time.time()
    if isinstance(expires_in, int) and expires_in > 0:
        ttl_raw = expires_in - spec.cache_ttl_safety_seconds
        ttl = max(0, min(ttl_raw, spec.cache_ttl_max_seconds))
        return ExchangeResult(
            outcome="success",
            access_token=access_token,
            expires_at=now + ttl,
            new_refresh_token=_detect_rotation(payload, refresh_token_in),
        )
    # No expires_in: use the cap, flag the result.
    return ExchangeResult(
        outcome="success",
        access_token=access_token,
        expires_at=now + spec.cache_ttl_max_seconds,
        new_refresh_token=_detect_rotation(payload, refresh_token_in),
        used_default_expiry=True,
    )


def _detect_rotation(payload: dict[str, Any], refresh_token_in: str) -> str | None:
    """Return the new refresh token if and only if the upstream issued
    one that DIFFERS from the input. An echoed-back identical value is
    not a rotation; write-back must skip in that case."""
    new = payload.get("refresh_token")
    if not isinstance(new, str) or not new:
        return None
    if new == refresh_token_in:
        return None
    return new


def _parse_error(status: int, body_bytes: bytes) -> ExchangeResult:
    """Categorise a 4xx/5xx response.

    RFC 6749 §5.2 specifies the JSON shape ``{error,
    error_description?, error_uri?}``. Map the ``error`` code into the
    outcome verbatim so the audit taxonomy preserves provider-level
    distinctions (``invalid_grant`` vs ``invalid_client`` vs
    ``invalid_scope`` vs vendor extensions). Non-JSON body falls back
    to ``token_endpoint_status:<code>`` so operators still see the
    HTTP status.
    """
    error_description: str | None = None
    try:
        payload = json.loads(body_bytes)
        if isinstance(payload, dict) and isinstance(payload.get("error"), str):
            desc = payload.get("error_description")
            if isinstance(desc, str):
                error_description = _sanitize_error_description(desc)
            return ExchangeResult(
                outcome=f"token_endpoint_error:{payload['error']}",
                error_description=error_description,
            )
    except (ValueError, json.JSONDecodeError):
        pass
    return ExchangeResult(outcome=f"token_endpoint_status:{status}")


async def exchange_async(
    spec: Oauth2RefreshInjector,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    *,
    timeout_seconds: float = 10.0,
) -> ExchangeResult:
    """Off-thread :func:`exchange` so the mitmproxy asyncio loop is
    not blocked by a slow token endpoint. The exchange runs on the
    module-level :data:`_SHARED_EXECUTOR` pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        _SHARED_EXECUTOR,
        lambda: exchange(
            spec,
            client_id,
            client_secret,
            refresh_token,
            timeout_seconds=timeout_seconds,
        ),
    )


class OauthResolver:
    """Executes an ``oauth2_refresh`` allowed verdict end-to-end
    (ADR-0017 §11): resolve inputs from the vault, run the token
    exchange (with derived-token cache dedup), handle refresh-token
    rotation write-back, inject the access token into the request
    header, and emit the two new audit shapes (``token_exchange`` +
    ``refresh_token_rotated``) alongside the existing
    ``inject_decision`` under the G6 audit-before-action ordering."""

    def __init__(self) -> None:
        import threading

        # Per-binding floor between write-back PUTs (ADR-0017 hardening
        # series). Keyed by secret name; survives config reloads
        # deliberately — a reload must not reset the bound on vault
        # write pressure. Mutated from the exchange thread pool, so the
        # check-then-set below MUST be atomic under this lock — without it
        # N concurrent rotations of one binding all read a stale timestamp
        # and each issue a PUT, defeating the rate limit (concurrency-audit
        # surface 4).
        self._write_back_last: dict[str, float] = {}
        self._write_back_lock = threading.Lock()

    def resolve(  # noqa: C901
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
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        oauth_injector = decision.oauth2_injector
        header_name = decision.header_name
        assert secret_name is not None
        assert secret_spec is not None
        assert oauth_injector is not None
        assert header_name is not None
        assert oauth_injector.token_url is not None

        # Resolve the three vault-held secrets through the existing
        # CachingSecretsClient. Any failure here mirrors the
        # HeaderInjector path's secret_unavailable / secret_fetch_error
        # categorisation — the operator audits look identical regardless
        # of which injector type triggered them.
        try:
            client_id_value = client.get(oauth_injector.client_id_secret)
            client_secret_value = client.get(oauth_injector.client_secret_secret)
            refresh_token_value = client.get(oauth_injector.refresh_token_secret)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": f"secret_unavailable:{type(e).__name__}",
                    "secret_name": secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                OauthInputUnavailableError.client_message,
                {"Content-Type": "text/plain"},
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception(
                "unexpected backend exception fetching oauth2 inputs for %s: %s",
                secret_name,
                type(e).__name__,
            )
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": f"secret_fetch_error:{type(e).__name__}",
                    "secret_name": secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                OauthInputFetchFailedError.client_message,
                {"Content-Type": "text/plain"},
            )
            return

        cache_inputs = KeyInputs(
            binding_name=secret_name,
            token_url=str(oauth_injector.token_url),
            scopes=oauth_injector.scopes,
            client_id_value=client_id_value.reveal(),
            refresh_token_value=refresh_token_value.reveal(),
        )

        # Cache hit short-circuits the exchange entirely — no
        # token_exchange audit (no exchange happened), only the
        # standard inject_decision: allowed event below.
        cached = token_cache.get(cache_inputs)
        if cached is not None:
            self._inject_header(
                flow=flow,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                secret_name=secret_name,
                secret_spec=secret_spec,
                oauth_injector=oauth_injector,
                header_name=header_name,
                access_token=cached,
                companion_headers=companion_headers,
            )
            return

        # Cache miss — exchange via the inflight dedup. The fetch_fn
        # captures the resolved inputs by closure; the dedup machinery
        # guarantees exactly one upstream call per binding under
        # concurrent requests.
        exchange_result_holder: list[ExchangeResult] = []

        def _fetch_for_cache() -> tuple[str, float]:
            result = exchange(
                oauth_injector,
                client_id_value.reveal(),
                client_secret_value.reveal(),
                refresh_token_value.reveal(),
            )
            exchange_result_holder.append(result)
            if result.outcome != "success":
                raise OauthExchangeFailedError(result)
            assert result.access_token is not None
            assert result.expires_at is not None
            return result.access_token, result.expires_at

        try:
            access_token = token_cache.dedup_or_fetch(cache_inputs, _fetch_for_cache)
        except OauthExchangeFailedError as exc:
            result = exc.result
        else:
            # Success path. Ordering: token_exchange (the call happened) →
            # refresh_token_rotated (only when the upstream issued a new
            # refresh token) → inject_decision (G6 audit-before-action).
            #
            # ONLY the leader — the caller whose ``_fetch_for_cache``
            # actually ran — has a populated holder and owns the
            # token_exchange audit + rotation write-back. A concurrent
            # caller that waited on the leader's in-flight future receives
            # the access token with an EMPTY holder and must only inject:
            # the leader's audit already records the one real upstream
            # call. (Indexing the empty holder here used to raise
            # IndexError out of the addon hook for every follower in a
            # cold refresh-storm — pinned by
            # test_concurrent_cold_requests_all_inject.)
            if exchange_result_holder:
                result = exchange_result_holder[0]
                self._emit_token_exchange_audit(
                    audit=audit,
                    request_id=request_id,
                    secret_name=secret_name,
                    oauth_injector=oauth_injector,
                    result=result,
                )
                if result.new_refresh_token is not None:
                    self._handle_rotation(
                        client=client,
                        audit=audit,
                        request_id=request_id,
                        secret_name=secret_name,
                        oauth_injector=oauth_injector,
                        new_refresh_token=result.new_refresh_token,
                        old_refresh_token=refresh_token_value.reveal(),
                    )
            self._inject_header(
                flow=flow,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                secret_name=secret_name,
                secret_spec=secret_spec,
                oauth_injector=oauth_injector,
                header_name=header_name,
                access_token=access_token,
                companion_headers=companion_headers,
            )
            return

        # Failure path. Emit token_exchange audit with the categorised
        # outcome, then deny via inject_decision so the existing
        # downstream consumer set keeps working without a second branch.
        self._emit_token_exchange_audit(
            audit=audit,
            request_id=request_id,
            secret_name=secret_name,
            oauth_injector=oauth_injector,
            result=result,
        )
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
            503,
            OauthExchangeFailedError.client_message,
            {"Content-Type": "text/plain"},
        )

    def _emit_token_exchange_audit(
        self,
        *,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        oauth_injector: Oauth2RefreshInjector,
        result: ExchangeResult,
    ) -> None:
        """Emit the ``token_exchange`` event (ADR-0017 §7).

        Carries outcome + URL host (never the full URL — query params
        would leak) and lifetime metadata for success cases. No secret
        material in any field."""
        token_url_host = urlparse(str(oauth_injector.token_url)).hostname
        event: dict[str, object] = {
            "type": "token_exchange",
            "request_id": request_id,
            "binding_name": secret_name,
            "token_url_host": token_url_host,
            "outcome": result.outcome,
        }
        if result.outcome == "success" and result.expires_at is not None:
            event["cache_ttl_effective_seconds"] = int(result.expires_at - time.time())
            event["used_default_expiry"] = result.used_default_expiry
        if result.error_description is not None:
            event["error_description"] = result.error_description
        audit.emit(event)

    def _handle_rotation(  # noqa: C901
        self,
        *,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        oauth_injector: Oauth2RefreshInjector,
        new_refresh_token: str,
        old_refresh_token: str,
    ) -> None:
        """Persist a rotated refresh token back to the vault (ADR-0017 §11
        slice 7 + hardening series). Outcomes, each a single
        ``refresh_token_rotated`` audit event: ``pending`` is emitted
        BEFORE the backend PUT (a crash inside the write window leaves a
        pending-with-no-final pair, so the operator can distinguish
        "write attempted, outcome unknown" from "never attempted" — the
        reverse, a final event for a write that never happened, stays
        structurally impossible), then exactly one of ``success``,
        ``write_back_disabled``, ``write_back_unavailable`` (read-only
        backend), ``write_back_rate_limited`` (per-binding PUT floor,
        ``write_back_min_interval_seconds``), ``write_back_conflict``
        (vault value changed since read — operator-side rotation; we
        refuse to clobber), ``write_back_failed`` (transient), or
        ``write_back_rejected_malformed`` (Silas F1 / #2 vault-poisoning
        defense — a compromised token endpoint would otherwise PUT junk
        into BWS with no live backup).

        Best-effort semantics: on any failure, the access token is STILL
        served on THIS request (we already hold it; killing a valid-token
        request is hostile UX). The audit signal is the operator's cue.

        The audit event never carries the refresh-token VALUE (old or
        new); only the binding name, the ``refresh_token_secret``
        reference from ``bindings.yaml``, the outcome, and (on failure)
        the exception class name — never the exception message, which
        a backend could put credential material in."""
        if not is_well_formed_refresh_token(new_refresh_token):
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_rejected_malformed",
                error_type="malformed_refresh_token",
            )
            return
        if not oauth_injector.refresh_token_write_back:
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_disabled",
            )
            return
        # Per-binding PUT floor (hardening series). Checked before the
        # pending emit — a rate-limited rotation never enters the write
        # window, so it gets one event, not a pending/final pair. The
        # read-and-claim is atomic under the lock so concurrent rotations
        # of the same binding can't all slip past the floor (surface 4).
        interval = oauth_injector.write_back_min_interval_seconds
        now = time.monotonic()
        with self._write_back_lock:
            last = self._write_back_last.get(secret_name)
            rate_limited = interval > 0 and last is not None and (now - last) < interval
            if not rate_limited:
                self._write_back_last[secret_name] = now
        if rate_limited:
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_rate_limited",
            )
            return
        # Pending BEFORE the PUT (hardening series, Oracle F2): the
        # fsynced pending record closes the mid-write crash ordering gap.
        self._emit_rotated_audit(
            audit=audit,
            request_id=request_id,
            secret_name=secret_name,
            oauth_injector=oauth_injector,
            outcome="pending",
        )
        try:
            client.update_secret(
                oauth_injector.refresh_token_secret,
                new_refresh_token,
                expected_current_value=old_refresh_token,
            )
        except BackendWriteConflictError as e:
            _log.warning(
                "refresh-token write-back conflict for %s: vault value changed "
                "since read (operator-side rotation?); not overwriting",
                secret_name,
            )
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_conflict",
                error_type=type(e).__name__,
            )
            return
        except BackendNotWritableError as e:
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_unavailable",
                error_type=type(e).__name__,
            )
            return
        except (BackendUnavailableError, SecretNotFoundError) as e:
            _log.warning(
                "refresh-token write-back failed for %s (%s); next exchange will likely fail",
                secret_name,
                type(e).__name__,
            )
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_failed",
                error_type=type(e).__name__,
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception(
                "unexpected backend exception during refresh-token write-back for %s",
                secret_name,
            )
            self._emit_rotated_audit(
                audit=audit,
                request_id=request_id,
                secret_name=secret_name,
                oauth_injector=oauth_injector,
                outcome="write_back_failed",
                error_type=type(e).__name__,
            )
            return
        self._emit_rotated_audit(
            audit=audit,
            request_id=request_id,
            secret_name=secret_name,
            oauth_injector=oauth_injector,
            outcome="success",
        )

    def _emit_rotated_audit(
        self,
        *,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        oauth_injector: Oauth2RefreshInjector,
        outcome: str,
        error_type: str | None = None,
    ) -> None:
        event: dict[str, object] = {
            "type": "refresh_token_rotated",
            "request_id": request_id,
            "binding_name": secret_name,
            "refresh_token_secret": oauth_injector.refresh_token_secret,
            "outcome": outcome,
        }
        if error_type is not None:
            event["error_type"] = error_type
        audit.emit(event)

    def _inject_header(  # noqa: PLR0913
        self,
        *,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        secret_name: str,
        secret_spec: SecretSpec,
        oauth_injector: Oauth2RefreshInjector,
        header_name: str,
        access_token: str,
        companion_headers: dict[str, dict[str, str]],
    ) -> None:
        """Set the resolved access token in the request header and emit
        the standard ``inject_decision: allowed`` audit under the G6
        audit-before-bytes-leave ordering."""
        flow.request.headers[header_name] = oauth_injector.render_value(access_token=access_token)
        for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
            if companion_name not in flow.request.headers:
                flow.request.headers[companion_name] = companion_value
        # G6 ORDERING — DO NOT REORDER (see header path comment).
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                "binding_source": secret_spec.binding_source,
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )
