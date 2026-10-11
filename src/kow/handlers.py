"""Request-path handlers split out of :class:`AgentVaultProxyAddon`.

The addon owns the mitmproxy lifecycle and per-request state snapshot; these
handlers own the execution of each verdict. They receive the per-request
snapshot (client, audit, request_id, target_host, flow) as call arguments so
the addon's tearing-prevention capture model is preserved verbatim.

Logging uses the ``kow.addon`` channel so operator log filters
and caplog assertions keyed on that name keep working after the split.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from mitmproxy import http

from kow._fail_closed import emit_denial_and_503
from kow._textguard import has_forbidden_char
from kow.audit import REASON_HOST_NOT_IN_ALLOWLIST, AuditWriter
from kow.backends import (
    BackendCannotListError,
    BackendUnavailableError,
    SecretNotFoundError,
)
from kow.caching import CachingSecretsClient
from kow.config import (
    BodyInjector,
    Config,
    SecretSpec,
    iter_leaf_injectors,
)
from kow.denials import (
    AmbiguousPlaceholderError,
    CompositeFetchFailedError,
    CompositeRenderFailedError,
    CompositeUnavailableError,
    HeaderControlCharactersError,
    SecretFetchFailedError,
    SecretUnavailableError,
)
from kow.injectors.body import _build_body_replacer
from kow.injectors.gcp_service_account import GcpServiceAccountResolver
from kow.injectors.github_app import GithubAppResolver
from kow.injectors.oauth2_client_credentials import Oauth2CcResolver
from kow.injectors.oauth2_refresh import OauthResolver
from kow.matching import host_matches_pattern
from kow.policy import matched_binding
from kow.secret import Secret
from kow.template import TemplateRenderError

if TYPE_CHECKING:
    from kow._derived_token_cache import DerivedTokenCache
    from kow.policy import Decision

_log = logging.getLogger("kow.addon")


class CompositeResolver:
    """Composite-binding fetch + render, with per-binding same-UUID warnings.

    Owns the once-per-binding warning state; :meth:`reset_warnings` is called
    on every config reload so a corrected binding can re-warn.
    """

    def __init__(self) -> None:
        import threading

        self._same_uuid_warned: set[str] = set()
        self._warned_lock = threading.Lock()

    def reset_warnings(self) -> None:
        with self._warned_lock:
            self._same_uuid_warned.clear()

    def fetch_and_render(
        self,
        *,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        flow: http.HTTPFlow,
        secret_name: str,
        secret_spec: SecretSpec,
    ) -> str | None:
        """Composite-binding fetch + render path. Returns the rendered header
        value on success, or None after writing a 503 response + audit entry
        on failure. Failure-path audit includes the compose: list so an
        operator can correlate flush events with affected composites."""
        assert secret_spec.compose is not None
        assert secret_spec.compiled_template is not None

        try:
            values = client.composite_fetch(secret_spec.compose)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            # Failure audit shape: include compose: list so operators can
            # correlate flush events with affected composites.
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"composite_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=CompositeUnavailableError.client_message,
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
            )
            return None
        except Exception as e:  # noqa: BLE001
            # G6 fail-closed mirror of the single-secret path: any uncaught
            # backend exception during composite fetch must result in a 503,
            # not a forwarded placeholder.
            _log.exception(
                "unexpected backend exception fetching composite %s: %s",
                secret_name,
                type(e).__name__,
            )
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"composite_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=CompositeFetchFailedError.client_message,
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
            )
            return None

        # Warn once per binding when two compose entries resolve to equal
        # values (likely operator typo pointing both at the same BWS UUID).
        # Values themselves are NEVER logged — only the binding name.
        self._maybe_warn_same_uuid(secret_name, values)

        try:
            # Single plaintext boundary for the composite path: the template
            # needs the bytes, nothing upstream of here does.
            rendered = secret_spec.compiled_template.render(
                {k: v.reveal() for k, v in values.items()}
            )
        except TemplateRenderError as exc:
            # Audit reason stays generic ("render_failed") so the agent
            # boundary can't infer compose-internal details.
            #
            # Default WARNING line carries only the EXCEPTION CLASS NAME —
            # not the exception message. Template helpers (e.g. ``b64decode``,
            # ``totp``) raise exceptions whose ``str()`` legitimately includes
            # operator-provided fragments (a base32 input that fails to decode,
            # a Unicode position from ``encode("ascii")``). Those fragments can
            # be substrings or shape-leaks of the secret value the template
            # was given. Stderr is root-readable but commonly shipped to log
            # aggregators, so we keep secrets out of it by default. The full
            # message is available at DEBUG when an operator opts in.
            _log.warning(
                "composite render failed for binding %s: %s",
                secret_name,
                type(exc).__name__,
            )
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug(
                    "composite render failure detail for binding %s: %s",
                    secret_name,
                    exc,
                )
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason="render_failed",
                secret_name=secret_name,
                message=CompositeRenderFailedError.client_message,
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
            )
            return None

        return rendered

    def _maybe_warn_same_uuid(
        self,
        secret_name: str,
        values: dict[str, Secret],
    ) -> None:
        """One-shot warning if two compose entries resolve to the same
        value. Suggests an operator typo (two names pointing at one BWS
        UUID); does NOT fail — legitimate edge cases exist (e.g. service
        account where username == password)."""
        if len(values) < 2:
            return
        with self._warned_lock:
            if secret_name in self._same_uuid_warned:
                return
        # O(n²) is fine for n ≤ 4 per the cap.
        names = list(values.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                if values[names[i]] == values[names[j]]:
                    with self._warned_lock:
                        self._same_uuid_warned.add(secret_name)
                    _log.warning(
                        "composite binding %s: distinct compose entries "
                        "%s and %s resolved to the same value — likely an "
                        "operator typo pointing both at one BWS secret. "
                        "Composite is degraded.",
                        secret_name,
                        names[i],
                        names[j],
                    )
                    return


class _ExchangeResolver(Protocol):
    """Structural type of the token-minting resolvers dispatched at
    requestheaders. They share one signature by construction; this pins it so a
    new minting injector cannot drift from the seam."""

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
    ) -> None: ...


class HeaderInjectionHandler:
    """Executes the header verdict from :func:`kow.policy.decide`."""

    def __init__(
        self,
        *,
        composite: CompositeResolver,
        oauth_resolver: OauthResolver,
        oauth_cc_resolver: Oauth2CcResolver,
        github_app_resolver: GithubAppResolver,
        gcp_sa_resolver: GcpServiceAccountResolver,
    ) -> None:
        # ADR-0024: name -> hosts the file-side allowlist REMOVED from that
        # secret's notes binding (partial rejection — siblings stayed live).
        # Swapped atomically by the addon on every configure(); consulted in
        # _audit_deny so a request to a removed host attributes precisely as
        # host_not_in_allowlist instead of a generic unbound-destination.
        self.allowlist_rejected_hosts: dict[str, set[str]] = {}
        self._composite = composite
        self._oauth_resolver = oauth_resolver
        self._oauth_cc_resolver = oauth_cc_resolver
        self._github_app_resolver = github_app_resolver
        self._gcp_sa_resolver = gcp_sa_resolver

    def _exchange_resolver(self, decision: Decision) -> _ExchangeResolver | None:
        """The resolver for a token-minting verdict, or None for the inline and
        request-hook paths. ADR-0030 accepted four copy-pasted dispatch blocks;
        ADR-0050 would have made it five, so the branch lives here once."""
        if decision.oauth2_injector is not None:
            return self._oauth_resolver
        if decision.oauth2_cc_injector is not None:
            return self._oauth_cc_resolver
        if decision.github_app_injector is not None:
            return self._github_app_resolver
        if decision.gcp_sa_injector is not None:
            return self._gcp_sa_resolver
        return None

    def execute(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        companion_headers: dict[str, dict[str, str]],
        token_cache: DerivedTokenCache | None,
    ) -> None:
        """Execute the header verdict from :func:`decide`.

        decide() chose the branch (pure); this method performs the side
        effects: audit emission, secret fetch/render, header mutation. The
        allowed path keeps the G6 audit-before-write ordering verbatim — do
        not reorder. ``return`` ends the header path only; the caller runs
        body streaming unless this set ``flow.response``.
        """
        if decision.decision == "forward_unmodified":
            return

        if self._audit_deny(
            flow=flow,
            decision=decision,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        ):
            return

        # Allowed — execute with the handles decide() resolved.
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_injector = decision.header_injector
        header_name = decision.header_name
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        # Token-minting injectors (oauth2_refresh ADR-0017, oauth2_cc +
        # github_app ADR-0030, gcp_service_account ADR-0050) all resolve at
        # THIS seam: resolution slots in between the deny gates (handled above)
        # and header injection. Each resolver sets ``flow.response`` on its deny
        # paths and otherwise injects the minted credential through the standard
        # header mutation + audit-before-bytes-leave ordering. decide() sets
        # exactly one handle, so the first match is the only match.
        resolver = self._exchange_resolver(decision)
        if resolver is not None:
            assert token_cache is not None
            resolver.resolve(
                flow=flow,
                decision=decision,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                companion_headers=companion_headers,
                token_cache=token_cache,
            )
            return

        # Computed signing injectors (sigv4/hmac/jwt_bearer, ADR-0027/0028)
        # resolve in the addon `request` hook: sigv4 and hmac hash the request
        # BODY (unavailable here); jwt rides the same seam. Stash the verdict.
        # Streaming stays OFF for a body-signing host (sigv4/hmac + body-injector
        # on one host is rejected at config-load), so the body is intact there.
        if (
            decision.sigv4_injector is not None
            or decision.hmac_injector is not None
            or decision.jwt_injector is not None
        ):
            flow.metadata["avp_signing"] = (decision, request_id, target_host)
            return

        new_header_value = self._resolve_header_value(
            flow=flow,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            secret_name=secret_name,
            secret_spec=secret_spec,
            header_injector=header_injector,
        )
        if new_header_value is None:
            return  # response already set + audit emitted

        # Last gate before the value becomes header bytes. The config layer
        # already refuses control characters in `header`/`format`, so this
        # catches what config cannot see: a SECRET VALUE that itself carries a
        # break character (backends round-trip values verbatim). Fail closed —
        # a split request would carry the real credential past policy scoping.
        if has_forbidden_char(new_header_value) or has_forbidden_char(header_name):
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason="header_control_characters",
                secret_name=secret_name,
                message=HeaderControlCharactersError.client_message,
                target_host=target_host,
            )
            return

        flow.request.headers[header_name] = new_header_value
        # Companion headers (e.g. anthropic-version) are DEFAULTS, not
        # overrides: set them only when the client didn't already send one.
        for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
            if companion_name not in flow.request.headers:
                flow.request.headers[companion_name] = companion_value

        # G6 ORDERING — DO NOT REORDER. mitmproxy does not write the request to
        # the upstream socket until requestheaders() returns. The header
        # mutation above is an in-memory update on flow.request only; no bytes
        # leave the proxy until this function returns. audit.emit() below does a
        # synchronous fsync (see audit.py), so the inject_decision event is
        # durable before any upstream write. Do NOT move audit.emit() to a
        # thread/queue, do NOT defer it past return, and do NOT add a return
        # between the mutation and the emit — any of those breaks G6 invisibly.
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                # ADR-0011 item 6: binding source ("file" | "bws_notes").
                "binding_source": secret_spec.binding_source,
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    def _audit_deny(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> bool:
        """Emit the deny audit for a non-allowed header verdict. Returns True if
        the verdict was a deny (caller must stop); False if it is the allowed
        path. Only ambiguous_placeholder_match sets a response (400); the
        other two forward the placeholder verbatim after auditing."""
        if decision.reason == "ambiguous_placeholder_match":
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "ambiguous_placeholder_match",
                    "matched_secret_names": decision.extra["matched_secret_names"],
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                400,
                AmbiguousPlaceholderError.client_message,
                {"Content-Type": "text/plain"},
            )
            return True

        if decision.reason == "destination_not_in_binding":
            # ADR-0024: if this exact host was stripped from the secret's
            # notes binding by the file-side allowlist, say so precisely —
            # "someone tried to route this secret somewhere un-approved" is
            # a different operator signal than an ordinary unbound
            # destination. The destination field names the host either way.
            reason = "destination_not_in_binding"
            name = decision.secret_name
            if name is not None and target_host in self.allowlist_rejected_hosts.get(name, ()):
                reason = REASON_HOST_NOT_IN_ALLOWLIST
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": reason,
                    "secret_name": decision.secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            return True

        if decision.reason == "binding_scope_violation":
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "binding_scope_violation",
                    "secret_name": decision.secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                    "method": decision.extra["method"],
                    "path": decision.extra["path"],
                }
            )
            return True

        return False

    def _resolve_header_value(
        self,
        *,
        flow: http.HTTPFlow,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        secret_name: str,
        secret_spec: SecretSpec,
        header_injector: object,
    ) -> str | None:
        """Resolve the header value for an allowed verdict. Returns the rendered
        value, or None after a fail-closed 503 + audit. Branches on composite
        vs single-secret — config-load guarantees exactly one applies
        (inject.format XOR inject.template)."""
        if secret_spec.compose is not None:
            return self._composite.fetch_and_render(
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                flow=flow,
                secret_name=secret_name,
                secret_spec=secret_spec,
            )

        from kow.config import HeaderInjector

        assert isinstance(header_injector, HeaderInjector)
        assert header_injector.format is not None
        try:
            real_secret = client.get(secret_name)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=SecretUnavailableError.client_message,
                target_host=target_host,
            )
            return None
        except Exception as e:  # noqa: BLE001
            # G6 fail-closed: any uncaught backend exception MUST NOT result
            # in the placeholder being forwarded verbatim. Without this the
            # exception bubbles to mitmproxy, which logs it and forwards the
            # unmodified request — silently leaking the placeholder. Audit
            # reason is distinct from secret_unavailable: so operators can
            # grep the "unexpected backend bug" class separately.
            _log.exception(
                "unexpected backend exception fetching %s: %s",
                secret_name,
                type(e).__name__,
            )
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=SecretFetchFailedError.client_message,
                target_host=target_host,
            )
            return None
        # HeaderInjector.render_value() owns the substitution rule (named
        # form {<SECRET_NAME>} replaced with the resolved bytes via
        # .replace(), not .format() — no attribute-access traversal).
        return header_injector.render_value(
            real_secret=real_secret.reveal(),
            secret_name=secret_name,
        )


class BodyInjectionHandler:
    """Attaches a streaming body replacer for hosts with body bindings."""

    def __init__(self, *, composite: CompositeResolver) -> None:
        self._composite = composite

    def setup(
        self,
        *,
        flow: http.HTTPFlow,
        config: Config,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        """Body-injection setup — P0.6 of the v0.5.0 injector port.

        For each body-injector secret bound to ``target_host``, attach a
        streaming replacer to ``flow.request.stream`` so the body is
        rewritten chunk-by-chunk without ever buffering in proxy memory.
        A Transformer-style chain emits modified bytes as the body
        arrives, with chunked transfer encoding ensuring the upstream
        sees the new framing.

        Three control-flow shapes here:

        1. **No body candidates for this host** — return without touching
           ``flow.request.stream`` (mitmproxy default: stream=False,
           body buffered for header path, no streaming overhead).
        2. **Candidates exist but all filtered out by ``content_type``** —
           pass through without modification but in streaming mode
           (constant memory regardless of body size).
        3. **At least one candidate eligible** — attach the replacer
           closure built by :func:`_build_body_replacer`. The closure
           lazy-fetches secrets on first placeholder match and uses the
           same fail-closed audit shape as the header path.
        """
        candidates = self._collect_candidates(
            flow=flow,
            config=config,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        )
        if not candidates:
            return

        # Content-Type gate: filter candidates whose declared content_type
        # doesn't match the request's. Content-Type may include parameters
        # (``application/json; charset=utf-8``) — strip them and casefold
        # before comparing. Spec values were normalised at config load.
        raw_ct = flow.request.headers.get("Content-Type", "") or ""
        actual_ct = raw_ct.split(";", 1)[0].strip().lower()
        eligible: list[tuple[str, SecretSpec, BodyInjector]] = []
        for secret_name, spec, inject in candidates:
            if inject.content_type is not None and inject.content_type != actual_ct:
                continue
            eligible.append((secret_name, spec, inject))

        if not eligible:
            # Candidates existed but were all filtered out by Content-Type.
            # Stream the body through unchanged (constant-memory passthrough)
            # rather than buffering. No audit event — content_type is a
            # filter, not a deny gate.
            flow.request.stream = True
            return

        # Composite resolver closure: delegates to the shared CompositeResolver
        # (which owns the per-binding same-UUID warning state). Returns the
        # rendered composite value on success, or None after the resolver has
        # already set ``flow.response = 503`` and emitted the failure audit.
        def _composite_resolver(secret_name: str, secret_spec: SecretSpec) -> str | None:
            return self._composite.fetch_and_render(
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                flow=flow,
                secret_name=secret_name,
                secret_spec=secret_spec,
            )

        replacer = _build_body_replacer(
            eligible=eligible,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            flow=flow,
            composite_resolver=_composite_resolver,
        )
        flow.request.stream = replacer
        # Chunked transfer encoding. The replacement length is not
        # knowable until the body is fully streamed (each placeholder
        # occurrence changes the byte count by
        # len(rendered) - len(placeholder)), so we cannot preserve the
        # original Content-Length. Drop it and let HTTP/1.1's chunked
        # framing handle the unknown-length body.
        flow.request.headers.pop("Content-Length", None)
        flow.request.headers["Transfer-Encoding"] = "chunked"

    def _collect_candidates(
        self,
        *,
        flow: http.HTTPFlow,
        config: Config,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> list[tuple[str, SecretSpec, BodyInjector]]:
        """Collect in-scope body-injector candidates for this host. Emits a
        scope-violation deny audit (forward-unmodified default) for any body
        binding whose method/path scope excludes this request."""
        candidates: list[tuple[str, SecretSpec, BodyInjector]] = []
        for secret_name, spec in config.secrets_for_host(target_host):
            for child in iter_leaf_injectors(spec.inject):
                if not isinstance(child, BodyInjector):
                    continue
                # Per-binding scope check (method/path) — the placeholder may
                # appear in any body, but the binding gates whether THIS
                # request is in scope. Same semantics as the header path.
                binding = matched_binding(target_host, spec)
                if binding is None:
                    continue
                request_method = flow.request.method.upper()
                request_path = flow.request.path.split("?", 1)[0]
                if not binding.matches_scope(request_method, request_path):
                    # Audit a deny so operators see scope violations on body
                    # injectors too. The request still proceeds with the
                    # placeholder verbatim (forward-unmodified default); the
                    # caller (e.g. an egress firewall) is responsible for
                    # actually blocking traffic if that's the policy.
                    audit.emit(
                        {
                            "type": "inject_decision",
                            "request_id": request_id,
                            "decision": "denied",
                            "reason": "binding_scope_violation",
                            "secret_name": secret_name,
                            "destination": {"host": target_host, "port": flow.request.port},
                            "method": request_method,
                            "path": request_path,
                        }
                    )
                    continue
                candidates.append((secret_name, spec, child))
        return candidates


def _host_in_allowlist(host: str, allow: list[str]) -> bool:
    """ADR-0024 membership: exact entry match, or a `*.suffix` entry (only
    present when ``allow_wildcard_hosts`` passed config-load) matching via
    the same one-label matcher the request path uses. A wildcard NOTE host
    matches only an identical wildcard ENTRY — the note side can never
    broaden an exact allowlist entry."""
    for entry in allow:
        if host == entry:
            return True
        if (
            entry.startswith("*.")
            and not host.startswith("*.")
            and host_matches_pattern(host, entry)
        ):
            return True
    return False


def _apply_notes_host_allowlist(
    *,
    allow: list[str],
    notes_names: list[str],
    merged: dict[str, SecretSpec],
    file_specs: dict[str, SecretSpec],
    out_placeholder_to_name: dict[str, str],
    out_allowlist_rejected: set[str] | None,
    out_allowlist_rejected_hosts: dict[str, set[str]] | None,
) -> None:
    """Enforce the file-side host allowlist over NOTES-sourced specs (ADR-0024).

    Annotations/notes may only NARROW scope — they can never route a secret to a
    host the file didn't pre-approve (the GSM confused-deputy fix:
    ``secretmanager.secrets.update`` and ``versions.access`` are independently
    grantable, so an annotation-only writer must not control egress). Only names
    that came from notes (``notes_names``) are checked; file ``secrets:`` entries
    are the trusted tier. A host the file already binds for the same secret is
    exempt (covers ``both``-mode unions). Per the ADR-0021 fan-out, hosts are
    judged individually: a disallowed host drops only its own binding entry
    (recorded in ``out_allowlist_rejected_hosts`` for precise request-time
    attribution); a spec left with NO allowed host is dropped whole and its name
    added to ``out_allowlist_rejected``. Mutates ``merged`` in place."""
    for name in notes_names:
        spec = merged.get(name)
        if spec is None:
            continue
        file_spec = file_specs.get(name)
        file_hosts = {b.host for b in file_spec.bindings} if file_spec is not None else set()

        def _ok(host: str, _fh: set[str] = file_hosts) -> bool:
            return host in _fh or _host_in_allowlist(host, allow)

        kept = [b for b in spec.bindings if _ok(b.host)]
        rejected = sorted(b.host for b in spec.bindings if not _ok(b.host))
        if not rejected:
            continue
        if kept:
            merged[name] = spec.model_copy(update={"bindings": kept})
            if out_allowlist_rejected_hosts is not None:
                out_allowlist_rejected_hosts[name] = set(rejected)
            _log.warning(
                "notes binding %r: host(s) %s not in notes_host_allowlist; dropping those "
                "fan-out entries (fail closed), keeping %d allowed host(s).",
                name,
                rejected,
                len(kept),
            )
        else:
            dropped = merged.pop(name)
            if out_allowlist_rejected is not None:
                out_allowlist_rejected.add(name)
            out_placeholder_to_name[dropped.placeholder] = name
            _log.warning(
                "notes binding %r: no host in notes_host_allowlist (%s rejected); dropping "
                "the binding entirely (fail closed).",
                name,
                rejected,
            )


def _preserve_file_flags(spec: SecretSpec, file_spec: SecretSpec | None) -> SecretSpec:
    """Carry operator-only file flags onto a notes-derived spec that replaces
    it. A `honeytoken: true` file secret must stay armed even when a note/
    annotation supplies its binding — a note cannot express the flag, so the
    wholesale replace would otherwise silently disarm the tripwire (ADR-0019)."""
    if file_spec is not None and file_spec.honeytoken and not spec.honeytoken:
        return spec.model_copy(update={"honeytoken": True})
    return spec


def _warn_note_shadows_file(name: str, spec: SecretSpec, file_spec: SecretSpec | None) -> None:
    """Say so, loudly, when a note replaces a file binding for the same secret.

    `binding_source: both` makes notes win, which is intended and documented.
    What was NOT survivable is that it happened in silence: the operator writes
    a file-source injector, forgets to delete the old note, and the note wins.
    kow is fail-closed, so the symptom is "auth just didn't happen" with nothing
    naming the stale note. That cost a real debugging session (Verda, 2026-09-20,
    where a leftover Basic note shadowed an `oauth2_client_credentials` injector).

    Two severities, because they are not equally alarming:

    * Same injector type — the note is narrowing or re-pointing a like-for-like
      binding. Worth naming, rarely a mistake.
    * DIFFERENT injector type — a note can only ever express `header`, so this
      is a richer injector (oauth2, sigv4, hmac, jwt_bearer, body, multi) being
      silently downgraded to static header substitution. The capability the
      operator configured is gone. This is the Verda shape.
    """
    if file_spec is None:
        return
    note_type = getattr(spec.inject, "type", "header")
    file_type = getattr(file_spec.inject, "type", "header")
    # Oracle review 2026-09-24: the advice that follows this warning is "delete
    # the note". That is only safe if the file binding is at least as narrow.
    # A note routinely narrows scope (ADR-0024 is built on it), so deleting one
    # can silently BROADEN what the credential reaches. Name it when it would.
    note_hosts = {b.host for b in spec.bindings}
    file_hosts = {b.host for b in file_spec.bindings}
    if note_hosts < file_hosts:
        _log.warning(
            "secret %r: the overriding note is also NARROWER than the file binding "
            "(note hosts %s vs file hosts %s). Deleting the note would widen this "
            "credential to the file's full host set — narrow the file binding first.",
            name,
            sorted(note_hosts),
            sorted(file_hosts),
        )
    if note_type != file_type:
        _log.warning(
            "secret %r: a vault NOTE is overriding the file binding, and the two are "
            "DIFFERENT injector types (file=%r -> note=%r). A note can only express "
            "static header injection, so the %r injector you configured is NOT active. "
            "If the file binding is the one you want, DELETE the note — under "
            "binding_source: both the note always wins.",
            name,
            file_type,
            note_type,
            file_type,
        )
    else:
        _log.warning(
            "secret %r: a vault NOTE is overriding the file binding (both are %r). "
            "Intended under binding_source: both; delete the note if the file "
            "binding is the one you want.",
            name,
            file_type,
        )


class NotesActivator:
    """Resolves BWS-notes bindings and merges them into a fresh Config at load.

    Config-build helper only — no request-path state. Degrades to file-only
    (`both`) or no bindings (`bws_notes`) when the install salt or backend
    listing is unusable, rather than serving guessed state.
    """

    # ADR-0032: set by degrade() to the degrade reason (else None) so a caller
    # that must NOT tolerate a degraded resolution — the background notes-refresh
    # — can keep its previous snapshot instead of publishing emptied bindings.
    last_degraded_reason: str | None = None

    def activate(  # noqa: C901 — config-build orchestrator; heavy branches extracted to module helpers
        self,
        *,
        new_config: Config,
        backend: object,
        config_path: Path,
        out_placeholder_to_name: dict[str, str],
        out_no_binding: set[str],
        out_invalid: set[str],
        out_companion_headers: dict[str, dict[str, str]],
        out_allowlist_rejected: set[str] | None = None,
        out_allowlist_rejected_hosts: dict[str, set[str]] | None = None,
    ) -> None:
        """Resolve BWS-notes bindings and merge them into ``new_config``.

        Mutates ``new_config.secrets`` (notes specs win over file specs for
        the same name) and rebuilds the host index. Populates the three
        ``out_*`` collections so the request path can attribute and fail
        closed on no-binding / invalid placeholders.

        Collision / config errors remain hard failures. Salt-path/salt-file
        failures and backends that cannot list secrets degrade to file-only
        (`both`) or no bindings (`bws_notes`) so the daemon keeps serving
        without guessing or using insecure state.
        """
        # ADR-0032: fresh per run; degrade() flips it so the notes-refresh caller
        # can tell a degraded resolution from a legitimately empty one.
        self.last_degraded_reason = None
        from kow.placeholders import (
            load_or_create_install_salt,
            resolve_install_salt_path,
        )
        from kow.runtime_bindings import resolve_runtime_bindings

        try:
            salt_path = resolve_install_salt_path(new_config.install_salt_path)
            install_salt = load_or_create_install_salt(salt_path)
        except (OSError, RuntimeError, ValueError) as e:
            self.degrade(
                new_config=new_config,
                reason=(
                    f"cannot use install salt at {new_config.install_salt_path or '<default>'}: "
                    f"{type(e).__name__}: {e}"
                ),
            )
            return

        try:
            resolved = resolve_runtime_bindings(
                backend=backend,
                binding_source=new_config.binding_source,
                install_salt=install_salt,
                file_config=new_config if new_config.binding_source == "both" else None,
            )
        except BackendCannotListError as e:
            self.degrade(
                new_config=new_config,
                reason=f"backend cannot list secrets: {type(e).__name__}: {e}",
            )
            return

        file_specs = dict(new_config.secrets)

        # Merge resolved specs over the file-loaded secrets. The resolver has
        # ALREADY applied notes-over-file precedence within its own sources;
        # here we additionally let any resolved spec replace the matching
        # file entry in the live config (so the request path's single
        # config.secrets iteration sees the effective binding).
        if new_config.binding_source == "both":
            merged: dict[str, SecretSpec] = {
                name: spec for name, spec in file_specs.items() if name not in resolved.invalid
            }
        else:
            merged = {}
        for name, (spec, source, companion) in resolved.specs.items():
            # Notes specs replace the file spec wholesale; keep operator-only
            # file flags (honeytoken) so the tripwire can't silently disarm.
            file_spec = file_specs.get(name)
            # In `both` mode the resolver ALSO yields the file specs (tagged
            # "file"), so a file-only secret arrives here with itself as its
            # own "file_spec". Only a genuinely notes-derived spec can shadow
            # anything — warning on the rest would make this background hum
            # and stop it being read, which a control test pins.
            if source != "file":
                _warn_note_shadows_file(name, spec, file_spec)
            merged[name] = _preserve_file_flags(spec, file_spec)
            if companion:
                out_companion_headers[name] = dict(companion)
        # Notes-derived specs bypass Config.enforce_wildcard_opt_in — that
        # model_validator ran at load, BEFORE notes were merged in. Re-enforce
        # the wildcard opt-in here so an `avp-binding` annotation (or a BWS
        # note) cannot widen a credential's blast radius to `*.suffix` past
        # `allow_wildcard_hosts: false`. Fail closed: drop the offending spec
        # and attribute its placeholder as invalid_binding_metadata. (File
        # specs already passed the load-time gate, so only notes specs match.)
        if not new_config.allow_wildcard_hosts:
            wildcarded = [
                name
                for name, spec in merged.items()
                if any(b.host.startswith("*.") for b in spec.bindings)
            ]
            for name in wildcarded:
                spec = merged.pop(name)
                out_invalid.add(name)
                out_placeholder_to_name[spec.placeholder] = name
                _log.warning(
                    "notes binding %r uses a wildcard host but allow_wildcard_hosts is "
                    "false; rejecting (fail closed).",
                    name,
                )
        # File-side host allowlist over NOTES-sourced specs (ADR-0024).
        if new_config.notes_host_allowlist is not None:
            _apply_notes_host_allowlist(
                allow=new_config.notes_host_allowlist,
                notes_names=list(resolved.specs.keys()),
                merged=merged,
                file_specs=file_specs,
                out_placeholder_to_name=out_placeholder_to_name,
                out_allowlist_rejected=out_allowlist_rejected,
                out_allowlist_rejected_hosts=out_allowlist_rejected_hosts,
            )
        new_config.secrets = merged
        # Re-assert the placeholder invariants over the MERGED set. config-load
        # validated only the file secrets; in `both` mode a derived placeholder
        # could in principle collide with / be a substring of a file one, which
        # would make the addon's `in` matching ambiguous. Fail closed at
        # configure() before serving rather than risk routing the wrong secret.
        from kow.config import validate_placeholder_invariants

        validate_placeholder_invariants({name: spec.placeholder for name, spec in merged.items()})
        # Rebuild the host-keyed indices for the merged secret set — the
        # request path's destination matching reads these indices.
        new_config.rebuild_host_index()

        out_placeholder_to_name.update(resolved.placeholder_to_name)
        for name in resolved.invalid:
            file_spec = file_specs.get(name)
            if file_spec is not None:
                out_placeholder_to_name[file_spec.placeholder] = name
        out_no_binding.update(resolved.no_binding)
        out_invalid.update(resolved.invalid)

    def degrade(self, *, new_config: Config, reason: str) -> None:
        """Fall back from notes activation without serving guessed state.

        An unusable salt is a security failure, not something we should work
        around by continuing to derive placeholders from it. Degrading to
        file-only (`both`) or no bindings (`bws_notes`) keeps startup alive
        while staying fail closed for notes-derived bindings.
        """
        self.last_degraded_reason = reason
        degraded_to = "file bindings only" if new_config.binding_source == "both" else "no bindings"
        _log.warning(
            "BWS-notes activation degraded in %s mode: %s; serving %s",
            new_config.binding_source,
            reason,
            degraded_to,
        )
        if new_config.binding_source == "notes":
            new_config.secrets = {}
        new_config.rebuild_host_index()
