"""``kow oauth login`` — interactive OAuth authorization-code bootstrap (ADR-0042).

Mints the *first* refresh token via a one-time human browser consent and populates the
vault secret the ``oauth2_refresh`` binding (ADR-0017) reads. Two acquisition flows:

* **loopback** (RFC 8252 §7.3 + PKCE RFC 7636) — a browser opens, the operator consents,
  and a single-shot ``127.0.0.1`` listener catches the redirect. Default when a local
  browser is reachable.
* **device grant** (RFC 8628) — "visit URL, enter code"; default on headless hosts where
  no loopback browser exists (the SSH-reached fleet).

Security posture:
* The refresh token, access token, and authorization code are **never** printed, logged,
  or placed in an exception message — stdout emits only the name of the populated secret.
* PKCE ``S256`` is mandatory; ``state`` is checked with a constant-time compare; the
  redirect URI is exact-matched. The authorization / token / device endpoints come from a
  provider preset or an operator-confirmed flag (never runtime discovery), and are
  SSRF-vetted before use (ADR-0017 §5 / ADR-0035 transport pinning).
* First-mint is a **populate**, not a rotate: the target secret must already exist holding
  an empty/placeholder value; a secret already holding a live token is refused without
  ``--force`` (ADR-0042 §1). The write is preconditioned on the value we read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from kow import _paths
from kow._ssrf_guard import SsrfBlockedError, check_url_not_internal
from kow.backends import (
    BackendUnavailableError,
    BackendWriteConflictError,
    SecretNotFoundError,
    fetch_with_meta,
    update_secret,
)
from kow.injectors._token_transport import transport_open
from kow.injectors.oauth2_refresh import is_well_formed_refresh_token
from kow.oauth_providers import PROVIDER_PRESETS
from kow.placeholders import ACCEPTED_PREFIXES

_UA = "kow/oauth-login"
_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"  # noqa: S105 — grant name, not a secret
_LOOPBACK_TIMEOUT_SECONDS = 300


class OAuthFlowError(Exception):
    """Any recoverable failure in the acquisition flow. The message is
    operator-facing and MUST NOT carry token/code material."""


def _die(msg: str) -> int:
    print(f"kow oauth: {msg}", file=sys.stderr)
    return 1


# Single egress seam — tests patch THIS name (mirrors oauth2_refresh._transport_open).
def _transport_open(req: urllib.request.Request, timeout: float) -> Any:
    return transport_open(req, timeout)


def _pkce_pair() -> tuple[str, str]:
    """RFC 7636 S256: high-entropy verifier + its SHA-256 base64url challenge."""
    verifier = secrets.token_urlsafe(64)  # 86 unreserved chars, within 43-128
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _prevet(url: str) -> None:
    """https-only + SSRF guard on an endpoint we will contact or open. Defense in
    depth for the authorization endpoint (opened in a browser) and load-bearing for
    the token/device endpoints (fetched by us)."""
    if urlparse(url).scheme != "https":
        raise OAuthFlowError(f"endpoint must be https, refusing {urlparse(url).scheme!r}")
    try:
        check_url_not_internal(url)
    except SsrfBlockedError as exc:
        raise OAuthFlowError(f"endpoint blocked by SSRF guard: {exc}") from exc


def _parse_json(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (ValueError, json.JSONDecodeError) as exc:
        raise OAuthFlowError("token endpoint returned a non-JSON body") from exc
    if not isinstance(payload, dict):
        raise OAuthFlowError("token endpoint returned a non-object JSON body")
    return payload


_TERMINAL_UNSAFE = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _clean(text: str) -> str:
    """Strip control/format/line-separator chars from provider-supplied text before it is
    printed to a terminal — a hostile endpoint could otherwise inject ANSI escapes via an
    ``error`` string, ``user_code``, or ``verification_uri`` (Oracle round 2)."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in _TERMINAL_UNSAFE)


def _safe_int(value: Any, default: int) -> int:
    """Provider-controlled numeric fields (``interval`` / ``expires_in``) may be junk from a
    hostile endpoint; never let a bad cast escape as a traceback (Oracle C4)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _basic_auth_header(client_id: str, client_secret: str) -> dict[str, str]:
    """RFC 6749 §2.3.1 HTTP Basic client authentication."""
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
    return {"Authorization": f"Basic {creds}"}


def _oauth_post(
    url: str,
    params: dict[str, str],
    *,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """POST a form to an OAuth endpoint through the pinned, no-redirect, SSRF-vetted
    transport and return the parsed JSON — on BOTH success and OAuth error responses, so
    the caller sees the ``error`` code (device polling needs ``authorization_pending`` /
    ``slow_down``)."""
    _prevet(url)
    data = urlencode(params).encode("utf-8")
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "User-Agent": _UA,
        **(extra_headers or {}),
    }
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310
    try:
        with _transport_open(req, timeout=timeout) as resp:
            return _parse_json(resp.read())
    except urllib.error.HTTPError as exc:
        # OAuth error responses (RFC 6749 §5.2) carry a JSON {error, ...} body.
        try:
            return _parse_json(exc.read())
        except OAuthFlowError:
            raise OAuthFlowError(f"token endpoint HTTP {exc.code}") from exc
    except SsrfBlockedError as exc:
        raise OAuthFlowError(f"endpoint blocked by SSRF guard: {exc}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise OAuthFlowError("token endpoint unreachable") from exc


class _CallbackHandler(BaseHTTPRequestHandler):
    """Single-shot loopback redirect catcher. Writes the outcome into the shared
    ``holder`` on the ``/callback`` path only; every other path (favicon, etc.) 404s
    without disturbing the holder."""

    holder: dict[str, str]
    expected_state: str

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path != "/callback":
            self.send_error(404)
            return
        qs = parse_qs(parsed.query)
        state = (qs.get("state") or [""])[0]
        if not secrets.compare_digest(state, self.expected_state):
            # A wrong-state hit is noise or a local process trying to abort the flow.
            # IGNORE it (do not fill the holder) so it cannot DoS the real consent; the
            # genuine provider redirect always carries the matching state. (Silas L4.)
            self._say("Ignoring an unexpected callback. You may close this window.")
            return
        if "error" in qs:
            # Store only the error CODE, never the full query (which held the code).
            self.holder["error"] = (qs.get("error") or ["error"])[0][:64]
            self._say("Authorization was denied. You may close this window.")
            return
        code = (qs.get("code") or [""])[0]
        if not code:
            self.holder["error"] = "no_code"
            self._say("Authentication failed (no code). You may close this window.")
            return
        self.holder["code"] = code
        self._say("Authentication complete. You may close this window and return to the terminal.")

    def _say(self, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:  # noqa: A003 — silence; the path holds the code
        return


def _loopback_flow(
    *,
    authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str | None,
    client_auth_basic: bool,
    scopes: str | None,
    resource: str | None,
    provider: str | None,
    callback_port: int,
) -> str:
    """Run the auth-code + PKCE loopback flow; return the acquired refresh token."""
    # Vet the endpoint the human's cookie-bearing browser will actually open — https +
    # not-internal — BEFORE constructing the URL (Silas H1 / Oracle C1). Without this the one
    # endpoint we don't fetch ourselves was the only unvetted one.
    _prevet(authorization_endpoint)
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    holder: dict[str, str] = {}

    handler = type(
        "_BoundCallbackHandler",
        (_CallbackHandler,),
        {"holder": holder, "expected_state": state},
    )
    # 127.0.0.1 ONLY — never 0.0.0.0; the redirect must stay on-host.
    try:
        server = HTTPServer(("127.0.0.1", callback_port), handler)
    except OSError as exc:
        raise OAuthFlowError(
            f"cannot bind loopback callback on port {callback_port or 'ephemeral'}: "
            f"{type(exc).__name__}"
        ) from exc
    try:
        bound_port = server.server_address[1]
        redirect_uri = f"http://127.0.0.1:{bound_port}/callback"
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if scopes:
            params["scope"] = scopes
        if resource:
            params["resource"] = resource
        if provider == "google":
            # Google only returns a refresh token with these; harmless elsewhere but
            # scoped to google to avoid surprising other providers.
            params["access_type"] = "offline"
            params["prompt"] = "consent"
        auth_url = f"{authorization_endpoint}?{urlencode(params)}"

        opened = webbrowser.open(auth_url)
        if opened:
            print("kow oauth: opened your browser to consent...", file=sys.stderr)
        else:
            print(
                f"kow oauth: no browser could be opened. Visit this URL to consent:\n  {auth_url}",
                file=sys.stderr,
            )

        server.timeout = 1.0
        deadline = time.monotonic() + _LOOPBACK_TIMEOUT_SECONDS
        while not holder and time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()

    if "error" in holder:
        raise OAuthFlowError(f"loopback consent failed: {_clean(holder['error'])}")
    if "code" not in holder:
        raise OAuthFlowError("loopback consent timed out")

    return _exchange_code(
        token_endpoint=token_endpoint,
        code=holder["code"],
        code_verifier=verifier,
        redirect_uri=redirect_uri,
        client_id=client_id,
        client_secret=client_secret,
        client_auth_basic=client_auth_basic,
        resource=resource,
    )


def _client_auth(
    params: dict[str, str], client_id: str, client_secret: str | None, basic: bool
) -> dict[str, str]:
    """Apply client authentication per RFC 6749 §2.3.1: Basic header for confidential
    ``basic`` providers, else the secret in the body. Returns extra headers (empty for the
    body_post / public-client case). ``params`` is mutated to carry the body secret when used."""
    if client_secret and basic:
        return _basic_auth_header(client_id, client_secret)
    if client_secret:
        params["client_secret"] = client_secret
    return {}


def _exchange_code(
    *,
    token_endpoint: str,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str | None,
    client_auth_basic: bool,
    resource: str | None,
) -> str:
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
    }
    headers = _client_auth(params, client_id, client_secret, client_auth_basic)
    if resource:
        params["resource"] = resource
    payload = _oauth_post(token_endpoint, params, extra_headers=headers)
    return _refresh_from_payload(payload, context="token exchange")


def _refresh_from_payload(payload: dict[str, Any], *, context: str) -> str:
    if payload.get("error"):
        raise OAuthFlowError(f"{context} rejected: {_clean(str(payload['error']))[:64]}")
    refresh = payload.get("refresh_token")
    if not isinstance(refresh, str) or not refresh:
        raise OAuthFlowError(
            f"{context} returned no refresh_token — the provider may need an offline scope "
            "(e.g. offline_access) or a forced re-consent"
        )
    return refresh


def _device_flow(  # noqa: C901 — RFC 8628 poll states (pending/slow_down/denied/expired) are inherent
    *,
    device_authorization_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str | None,
    client_auth_basic: bool,
    scopes: str | None,
    resource: str | None,
) -> str:
    """Run the RFC 8628 device grant; return the acquired refresh token."""
    start_params = {"client_id": client_id}
    if scopes:
        start_params["scope"] = scopes
    if resource:
        # RFC 8707: bind the audience at the authorization step, not only at polling (Oracle C6).
        start_params["resource"] = resource
    start = _oauth_post(device_authorization_endpoint, start_params)
    device_code = start.get("device_code")
    user_code = start.get("user_code")
    verification_uri = start.get("verification_uri") or start.get("verification_url")
    if not (
        isinstance(device_code, str)
        and isinstance(user_code, str)
        and isinstance(verification_uri, str)
    ):
        raise OAuthFlowError("device authorization response missing required fields")
    # The human is told to visit this URL — refuse a non-https one (phishing / downgrade).
    if urlparse(verification_uri).scheme != "https":
        raise OAuthFlowError("device verification_uri is not https; refusing to display it")
    # Provider-controlled numerics: safe-cast + clamp so a hostile endpoint can neither crash
    # the cast nor turn the poll into an unbounded hammer (Silas M3 / Oracle C4).
    interval = min(max(_safe_int(start.get("interval"), 5), 1), 60)
    expires_in = min(max(_safe_int(start.get("expires_in"), 900), 1), 1800)
    complete = start.get("verification_uri_complete")

    print(
        f"kow oauth: on any device, visit {_clean(verification_uri)} "
        f"and enter code: {_clean(user_code)}",
        file=sys.stderr,
    )
    if isinstance(complete, str) and urlparse(complete).scheme == "https":
        print(f"kow oauth: or open directly: {_clean(complete)}", file=sys.stderr)

    poll = {"grant_type": _DEVICE_GRANT, "device_code": device_code, "client_id": client_id}
    poll_headers = _client_auth(poll, client_id, client_secret, client_auth_basic)
    if resource:
        poll["resource"] = resource

    deadline = time.monotonic() + expires_in
    while time.monotonic() < deadline:
        time.sleep(interval)
        payload = _oauth_post(token_endpoint, poll, extra_headers=poll_headers)
        error = payload.get("error")
        if error is None:
            return _refresh_from_payload(payload, context="device grant")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = min(interval + 5, 60)
            continue
        raise OAuthFlowError(f"device grant failed: {_clean(str(error))[:64]}")
    raise OAuthFlowError("device grant timed out before the code was entered")


def _looks_live(value: str) -> bool:
    """True if the secret already holds SOMETHING real — any non-empty value that isn't an kow
    placeholder. Deliberately NOT shape-gated: an opaque or non-conforming existing token must
    still block a silent overwrite (Oracle C3 / Silas L6). ``--force`` is the explicit override."""
    return bool(value) and not value.startswith(ACCEPTED_PREFIXES)


def _populate_secret(backend: Any, name: str, refresh_token: str, *, force: bool) -> int:
    """Populate the (pre-existing) refresh_token secret via the preconditioned write path.
    Never prints the token value; on backend errors, surfaces the exception TYPE only."""
    try:
        current, _note = fetch_with_meta(backend, name)
    except SecretNotFoundError:
        return _die(
            f"vault secret {name!r} does not exist — create it (empty/placeholder) as part "
            "of the oauth2_refresh binding, then re-run"
        )
    except BackendUnavailableError as exc:
        return _die(f"backend unavailable reading {name!r}: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 — any backend error; never echo its message
        return _die(f"backend error reading {name!r}: {type(exc).__name__}")

    # Plaintext boundary: the preconditioned write and the live-token guard
    # both need the bytes. Nothing above this line does.
    current_value = current.reveal() if current is not None else ""
    if _looks_live(current_value) and not force:
        return _die(
            f"vault secret {name!r} already holds a live token; pass --force to overwrite "
            "(this re-consents and invalidates the previous grant)"
        )

    try:
        update_secret(backend, name, refresh_token, expected_current_value=current_value)
    except BackendWriteConflictError:
        return _die(f"vault secret {name!r} changed since it was read; re-run `kow oauth login`")
    except (BackendUnavailableError, SecretNotFoundError) as exc:
        return _die(f"could not write {name!r}: {type(exc).__name__}")
    except Exception as exc:  # noqa: BLE001 — never echo a backend message (may carry value)
        return _die(f"could not write {name!r}: {type(exc).__name__}")

    print(name)  # stdout: the populated secret name only, never the value
    print(
        f"kow oauth: populated vault secret {name!r} with a fresh refresh token.", file=sys.stderr
    )
    print(
        "kow oauth: bootstrap this refresh secret on ONE host only — sharing it across "
        "hosts strands the others on rotation (ADR-0042 §6).",
        file=sys.stderr,
    )
    return 0


def _is_headless() -> bool:
    """No reachable local browser: an SSH session, or a Linux box with no display server."""
    import os

    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return True
    if sys.platform.startswith("linux"):
        return not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return False


def _resolve_endpoints(args: argparse.Namespace) -> tuple[str | None, str | None, str | None]:
    """Return (authorization_endpoint, token_endpoint, device_authorization_endpoint) from
    the provider preset, overlaid by explicit flags. Explicit flags win so an operator can
    correct a preset or drive an uncatalogued provider."""
    preset = PROVIDER_PRESETS.get(args.provider) if args.provider else None
    auth_ep = args.authorization_endpoint or (preset.authorization_endpoint if preset else None)
    token_ep = args.token_endpoint or (preset.token_url if preset else None)
    device_ep = args.device_authorization_endpoint or (
        preset.device_authorization_endpoint if preset else None
    )
    return auth_ep, token_ep, device_ep


def run_oauth(args: argparse.Namespace) -> int:  # noqa: C901 — flow-select + backend + creds + acquire
    if getattr(args, "oauth_cmd", None) != "login":
        return _die("unknown subcommand; use `avp oauth login <binding> ...`.")

    from kow.config import build_backend, load_config

    # Endpoint-confusion guard (Silas M2): a preset pins all endpoints to ONE issuer. Allowing
    # `--provider google --token-endpoint https://evil/…` would consent at Google but redeem the
    # code+verifier at the attacker. Preset OR explicit endpoints, never mixed.
    explicit_eps = (
        args.authorization_endpoint,
        args.token_endpoint,
        args.device_authorization_endpoint,
    )
    if args.provider and any(explicit_eps):
        return _die(
            "do not combine --provider with explicit --*-endpoint flags — a preset pins every "
            "endpoint to one issuer; mixing them enables endpoint confusion. Use --provider OR "
            "the explicit endpoints, not both."
        )
    if not (0 <= args.callback_port <= 65535):
        return _die("--callback-port must be between 0 and 65535")

    print(f"kow oauth: bootstrapping binding {args.binding!r}...", file=sys.stderr)

    preset = PROVIDER_PRESETS.get(args.provider) if args.provider else None
    client_auth_basic = bool(preset and preset.client_auth_method == "basic")
    auth_ep, token_ep, device_ep = _resolve_endpoints(args)
    scopes = args.scopes or (preset.default_scopes if preset else None)

    use_device = args.device or (not args.loopback and _is_headless())
    if use_device and not device_ep:
        return _die(
            "device flow selected but no device_authorization_endpoint "
            "(set --provider with device support, or --device-authorization-endpoint)"
        )
    if not use_device and not auth_ep:
        return _die(
            "loopback flow selected but no authorization_endpoint "
            "(set --provider, or --authorization-endpoint, or use --device)"
        )
    if not token_ep:
        return _die("no token endpoint (set --provider or --token-endpoint)")

    try:
        config = load_config(args.config)
    except Exception as exc:  # noqa: BLE001 — operator-facing CLI surface
        return _die(f"cannot load config {args.config}: {type(exc).__name__}")
    try:
        backend, _ = build_backend(config)
    except Exception as exc:  # noqa: BLE001 — operator-facing CLI surface
        return _die(f"cannot build backend: {type(exc).__name__}")

    try:
        client_id = backend.fetch(args.client_id_secret)
    except Exception as exc:  # noqa: BLE001 — never echo a backend message
        return _die(f"cannot read client id secret {args.client_id_secret!r}: {type(exc).__name__}")
    if not client_id:
        return _die(f"client id secret {args.client_id_secret!r} is empty")
    client_secret: str | None = None
    if args.client_secret_secret:
        try:
            client_secret = backend.fetch(args.client_secret_secret) or None
        except Exception as exc:  # noqa: BLE001
            return _die(
                f"cannot read client secret {args.client_secret_secret!r}: {type(exc).__name__}"
            )

    # Refuse the secret-less (public-client) path BEFORE consent. The runtime oauth2_refresh
    # injector requires a client secret (config_models: client_secret_secret is mandatory, and
    # exchange() always transmits it), so a secret-less token would be minted, vaulted, and then
    # unusable — burning a one-shot authorization the provider may not re-issue. Fail closed until
    # runtime public-client support lands (ADR-0042 §7). (Silas H1.)
    if client_secret is None:
        return _die(
            "the oauth2_refresh runtime requires a client secret — pass --client-secret-secret "
            "with a vault secret holding it. Secret-less public clients are not yet consumable at "
            "runtime (ADR-0042 §7); refusing before consent so a one-time authorization is not "
            "spent on an unusable token."
        )

    try:
        if use_device:
            assert device_ep is not None
            refresh_token = _device_flow(
                device_authorization_endpoint=device_ep,
                token_endpoint=token_ep,
                client_id=client_id,
                client_secret=client_secret,
                client_auth_basic=client_auth_basic,
                scopes=scopes,
                resource=args.resource,
            )
        else:
            assert auth_ep is not None
            refresh_token = _loopback_flow(
                authorization_endpoint=auth_ep,
                token_endpoint=token_ep,
                client_id=client_id,
                client_secret=client_secret,
                client_auth_basic=client_auth_basic,
                scopes=scopes,
                resource=args.resource,
                provider=args.provider,
                callback_port=args.callback_port,
            )
    except OAuthFlowError as exc:
        return _die(str(exc))

    if not is_well_formed_refresh_token(refresh_token):
        return _die("provider returned a malformed refresh token; refusing to store it")

    return _populate_secret(backend, args.refresh_token_secret, refresh_token, force=args.force)


def register_oauth_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    oauth_p = parent_subparsers.add_parser(
        "oauth",
        help="Interactive OAuth bootstrap: mint the first refresh token into the vault (ADR-0042).",
        description=(
            "Run a one-time OAuth authorization-code + PKCE consent (loopback) or an "
            "RFC 8628 device grant on a headless host, and populate the vault's "
            "refresh_token secret. The token value is never printed or logged."
        ),
    )
    oauth_sub = oauth_p.add_subparsers(dest="oauth_cmd")
    login_p = oauth_sub.add_parser(
        "login",
        help="Consent once and store the refresh token in the vault.",
        description=(
            "Acquire a refresh token via browser (loopback) or device code and write it "
            "to the named vault secret, which the oauth2_refresh binding then reads."
        ),
    )
    login_p.add_argument(
        "binding", help="Binding label (for messages; the secret is --refresh-token-secret)."
    )
    login_p.add_argument(
        "--provider",
        choices=sorted(PROVIDER_PRESETS),
        default=None,
        help="Provider preset supplying the authorization/token/device endpoints.",
    )
    login_p.add_argument(
        "--client-id-secret",
        dest="client_id_secret",
        required=True,
        help="Vault secret name holding the OAuth client id.",
    )
    login_p.add_argument(
        "--client-secret-secret",
        dest="client_secret_secret",
        default=None,
        help="Vault secret name holding the client secret (confidential clients only; "
        "loopback/device are public clients and omit it).",
    )
    login_p.add_argument(
        "--refresh-token-secret",
        dest="refresh_token_secret",
        required=True,
        help="Vault secret to populate (must already exist, empty/placeholder).",
    )
    login_p.add_argument("--scopes", default=None, help="Space-separated OAuth scopes.")
    login_p.add_argument("--resource", default=None, help="RFC 8707 resource indicator (audience).")
    # Explicit endpoints are the uncatalogued-provider path — mutually exclusive with
    # --provider (a preset pins all endpoints to one issuer; mixing enables endpoint confusion).
    login_p.add_argument(
        "--authorization-endpoint",
        dest="authorization_endpoint",
        default=None,
        help="Authorization endpoint (uncatalogued provider; do not combine with --provider).",
    )
    login_p.add_argument(
        "--token-endpoint",
        dest="token_endpoint",
        default=None,
        help="Token endpoint (uncatalogued provider; do not combine with --provider).",
    )
    login_p.add_argument(
        "--device-authorization-endpoint",
        dest="device_authorization_endpoint",
        default=None,
        help="Device authorization endpoint (uncatalogued provider; not with --provider).",
    )
    flow = login_p.add_mutually_exclusive_group()
    flow.add_argument("--loopback", action="store_true", help="Force the loopback browser flow.")
    flow.add_argument(
        "--device", action="store_true", help="Force the device-code flow (headless)."
    )
    login_p.add_argument(
        "--callback-port",
        dest="callback_port",
        type=int,
        default=0,
        help="Loopback callback port (default: ephemeral).",
    )
    login_p.add_argument(
        "--config",
        default=str(_paths.resolve(_paths.LINUX_CONFDIR / "bindings.yaml")),
        help="Path to bindings.yaml (for the backend).",
    )
    login_p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite a refresh secret that already holds a live token (re-consent).",
    )
