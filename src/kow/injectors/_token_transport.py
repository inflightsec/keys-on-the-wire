"""Shared HTTPS egress for the token-minting injectors.

``oauth2_client_credentials``, ``github_app``, and ``oauth2_refresh`` all POST
to operator-supplied token endpoints. The transport therefore owns three
security properties:

1. Fresh SSRF re-vetting on EVERY call (DNS rebinding defense).
2. Pinned connect-by-IP: resolve and vet once, then connect to a vetted member
   of that exact address set so check and connect cannot diverge (ADR-0035).
3. No redirect following: a 3xx from a token endpoint is treated as a terminal
   response and surfaced as ``HTTPError`` to the caller.

``transport_open`` remains the single patchable egress seam the tests use.
"""

from __future__ import annotations

import http.client
import io
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from kow._ssrf_guard import SsrfBlockedError, check_url_not_internal, resolve_and_vet
from kow._textguard import has_forbidden_char

_log = logging.getLogger("kow.injectors._token_transport")
_RETRY_BACKOFF_SECONDS = 1.0
_USER_AGENT = "kow/token-exchange"
_TLS_CONTEXT = ssl.create_default_context()


@dataclass(frozen=True)
class TokenResult:
    """One token-minting attempt. ``outcome`` is the audit vocabulary label;
    ``token`` + ``expires_at`` are set only on ``success``. No secret material
    other than the freshly minted ``token`` (which the resolver injects, never
    audits)."""

    outcome: str
    token: str | None = None
    expires_at: float | None = None
    error_description: str | None = None

    def __post_init__(self) -> None:
        # Every resolver writes a minted token straight into a header, past the
        # CR/LF gate the static path has, so refuse it here (C1, review of 1.2.0).
        if self.outcome == "success" and self.token is not None and has_forbidden_char(self.token):
            object.__setattr__(self, "outcome", "response_parse_failed")
            object.__setattr__(self, "token", None)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a caller-supplied vetted IP literal while
    keeping the original hostname for TLS SNI, ``Host:``, and certificate
    verification (ADR-0035).

    ``http.client`` already handles request formatting, ``Host:`` synthesis, and
    non-following of redirects. The only custom behavior here is the connect
    path: no resolver call, no ``create_connection()``, only a direct socket
    connect to the vetted address.
    """

    def __init__(
        self,
        family: int,
        ip: str,
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_family = family
        self._pinned_ip = ip
        # Keep an explicitly-typed handle on the TLS context. ``http.client``
        # stores it as the private ``self._context``; referencing our own
        # attribute keeps the type checker happy and the intent explicit.
        self._pinned_context = context

    def connect(self) -> None:
        # Dial the pre-vetted IP directly — no resolver call, no
        # ``create_connection`` (which would re-run getaddrinfo). Then TLS-wrap
        # with SNI + verification bound to the HOSTNAME (``self.host``), never
        # the IP, so pinning the transport address cannot weaken TLS identity.
        sock = socket.socket(self._pinned_family, socket.SOCK_STREAM)
        try:
            if isinstance(self.timeout, int | float):
                sock.settimeout(self.timeout)
            sock.connect((self._pinned_ip, self.port))
        except OSError:
            sock.close()
            raise
        self.sock = self._pinned_context.wrap_socket(sock, server_hostname=self.host)


class _PinnedResponse:
    """Context-manager wrapper matching the historic ``with transport_open(...)
    as resp: resp.read()`` seam while ensuring both response and connection are
    closed on exit.
    """

    def __init__(
        self,
        conn: http.client.HTTPSConnection,
        resp: http.client.HTTPResponse,
    ) -> None:
        self._conn = conn
        self._resp = resp

    def read(self) -> bytes:
        return self._resp.read()

    def __enter__(self) -> _PinnedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        try:
            self._resp.close()
        finally:
            self._conn.close()


def transport_open(req: urllib.request.Request, timeout: float) -> Any:
    """Open ``req`` through the pinned token-egress transport.

    The URL is resolved and vetted FRESH on every call. Each vetted address is
    tried in order; every candidate is already safe, so sequential failover is
    allowed. A retry in :func:`post` therefore re-runs resolution and receives a
    fresh vetted set rather than reusing a stale pin.
    """
    url = req.full_url
    parsed = urlparse(url)
    if parsed.scheme != "https":
        # Defense-in-depth: config-load enforces https on every token_url, so
        # this is unreachable today — but transport_open must never TLS-wrap a
        # plaintext endpoint if a future caller slips one through. Fail closed.
        raise SsrfBlockedError(f"token endpoint must use https, refusing scheme {parsed.scheme!r}")
    vetted = resolve_and_vet(url)
    hostname = parsed.hostname
    if hostname is None:
        raise urllib.error.URLError(f"token endpoint URL has no hostname: {url!r}")
    port = parsed.port or 443
    selector = parsed.path or "/"
    if parsed.query:
        selector = f"{selector}?{parsed.query}"
    method = req.get_method()
    body = req.data
    headers = dict(req.header_items())

    last_exc: OSError | None = None
    for family, ip in vetted:
        conn = _PinnedHTTPSConnection(
            family,
            ip,
            hostname,
            port,
            timeout=timeout,
            context=_TLS_CONTEXT,
        )
        try:
            conn.request(method, selector, body=body, headers=headers)
            resp = conn.getresponse()
        except OSError as e:
            conn.close()
            last_exc = e
            continue
        if 200 <= resp.status < 300:
            return _PinnedResponse(conn, resp)
        body_bytes = resp.read()
        conn.close()
        raise urllib.error.HTTPError(
            url,
            resp.status,
            resp.reason,
            resp.headers,
            io.BytesIO(body_bytes),
        )

    if last_exc is None:
        # Unreachable — resolve_and_vet fails closed on an empty answer, so the
        # loop always ran at least once. Explicit raise (not assert, which
        # strips under `python -O`) keeps it fail-closed regardless.
        raise urllib.error.URLError("no vetted address to connect to")
    raise urllib.error.URLError(last_exc)


def _safe_read(err: urllib.error.HTTPError) -> bytes:
    try:
        return err.read()
    except Exception:  # noqa: BLE001
        return b""


def _http_error(status: int, body: bytes) -> TokenResult:
    description: str | None = None
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            raw = payload.get("error_description") or payload.get("error") or payload.get("message")
            description = str(raw) if raw is not None else None
    except (ValueError, json.JSONDecodeError):
        description = None
    if 300 <= status < 400:
        return TokenResult(outcome=f"token_endpoint_status:{status}", error_description=description)
    return TokenResult(outcome=f"token_endpoint_error:{status}", error_description=description)


def post(
    *,
    url: str,
    data: bytes,
    headers: dict[str, str],
    on_success: Callable[[bytes], TokenResult],
    timeout: float = 10.0,
) -> TokenResult:
    """SSRF-checked POST with one retry on 5xx / transport error. On HTTP 200,
    ``on_success(body)`` parses the provider response; on any error a categorised
    :class:`TokenResult` is returned. Never raises (barring programmer error)."""
    try:
        check_url_not_internal(url)
    except SsrfBlockedError as e:
        _log.warning("token endpoint SSRF-blocked at runtime: %s", e)
        return TokenResult(outcome="ssrf_blocked")

    all_headers = {"User-Agent": _USER_AGENT, "Accept": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=all_headers, method="POST")  # noqa: S310
    for attempt in (0, 1):
        try:
            with transport_open(req, timeout=timeout) as resp:
                return on_success(resp.read())
        except SsrfBlockedError as e:
            _log.warning("token endpoint SSRF-blocked during transport resolve: %s", e)
            return TokenResult(outcome="ssrf_blocked")
        except urllib.error.HTTPError as e:
            status = e.code
            body = _safe_read(e)
            if 300 <= status < 500:
                return _http_error(status, body)
            if attempt == 0:  # 5xx — retry once
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            return _http_error(status, body)
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 0:
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            _log.info("token endpoint unreachable: %s", e)
            return TokenResult(outcome="token_endpoint_unreachable")
    return TokenResult(outcome="token_endpoint_unreachable")
