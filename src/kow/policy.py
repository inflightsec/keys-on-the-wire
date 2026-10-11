"""Pure policy core — ADR-0013's ``decide()`` single source of truth.

``decide()`` answers *whether* a request gets a credential and *which* one,
with no I/O and no flow mutation. It returns a :class:`Decision` the addon
then EXECUTES (fetch the secret, render, mutate the header, fsync the audit
under the G6 ordering). Splitting the verdict from the execution is what
makes the decision logic unit-testable against the policy fixtures without
a live backend or the mitmproxy transport.

What stays OUT of here (because it is I/O or ordering-sensitive, not policy):
  * secret fetch + render (and the ``secret_unavailable`` / ``secret_fetch_error``
    / ``composite_*`` denials that only a failed fetch can produce);
  * ``audit.emit`` and its synchronous fsync (G6);
  * the BWS-notes no-binding/invalid attribution audit (an addon pre-step).

The verdict ``forward_unmodified`` means "no inject_decision event from the
header path" — the placeholder is forwarded verbatim (G5 enforcement by
omission).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from kow.config import (
    BindingSpec,
    Config,
    GcpServiceAccountInjector,
    GithubAppInjector,
    HeaderInjector,
    HmacInjector,
    JwtBearerInjector,
    Oauth2ClientCredentialsInjector,
    Oauth2RefreshInjector,
    SecretSpec,
    Sigv4Injector,
    iter_leaf_injectors,
)
from kow.config_models import _PLACEHOLDER_MARKER
from kow.denials import (
    AmbiguousPlaceholderError,
    DestinationNotBoundError,
    SniHostMismatchError,
)

# Injectors whose target is a request header (all expose ``.header``); the body
# injector is the only leaf that is not header-targeting. Used for placeholder
# detection and as the matched-injector type. A ``types.UnionType`` at runtime,
# so it works in both type hints and ``isinstance``.
_HeaderTargetInjector = (
    HeaderInjector
    | Oauth2RefreshInjector
    | Oauth2ClientCredentialsInjector
    | GithubAppInjector
    | GcpServiceAccountInjector
    | Sigv4Injector
    | HmacInjector
    | JwtBearerInjector
)

Verdict = Literal["allowed", "denied", "forward_unmodified"]


@dataclass(frozen=True)
class Decision:
    """The verdict for one request's header path.

    ``decision``/``reason``/``secret_name`` are the audited triple (the
    policy fixtures assert exactly these). ``response_status`` is the HTTP
    status the addon should synthesise on a hard deny (403/400); ``None``
    means "do not set a response" — for ``allowed`` and for the
    forward-verbatim denials (``destination_not_in_binding`` /
    ``binding_scope_violation``, which preserve G5 by omission).

    The remaining fields are EXECUTION handles, populated only for
    ``allowed``: the addon uses them to fetch + render + inject. ``extra``
    carries branch-specific audit fields (e.g. ``matched_secret_names`` for
    ambiguity, ``method``/``path`` for a scope violation).
    """

    decision: Verdict
    reason: str | None = None
    secret_name: str | None = None
    response_status: int | None = None
    response_body: bytes | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # Execution handles (allowed only). For a single allowed verdict,
    # exactly ONE of ``header_injector`` / ``oauth2_injector`` is set —
    # the dispatch is keyed on the populated field rather than a tagged
    # union so the existing HeaderInjector code path stays untouched
    # by ADR-0017.
    secret_spec: SecretSpec | None = None
    header_injector: HeaderInjector | None = None
    oauth2_injector: Oauth2RefreshInjector | None = None
    # oauth2 client-credentials + github_app — network exchanges resolved at
    # requestheaders like oauth2_refresh (not the signing request-hook seam).
    oauth2_cc_injector: Oauth2ClientCredentialsInjector | None = None
    github_app_injector: GithubAppInjector | None = None
    # ADR-0050: Google service-account minting (self-signed JWT, RFC 7523
    # exchange, or IAM impersonation) — same requestheaders exchange seam.
    gcp_sa_injector: GcpServiceAccountInjector | None = None
    # Computed signing injectors — the addon defers execution to the ``request``
    # hook (sigv4/hmac hash the request BODY; jwt rides the same seam). Exactly
    # one is set on an allowed verdict.
    sigv4_injector: Sigv4Injector | None = None
    hmac_injector: HmacInjector | None = None
    jwt_injector: JwtBearerInjector | None = None
    header_name: str | None = None
    matched_binding: BindingSpec | None = None


# --- relocated pure matching helpers (were private in addon.py) -------------


def destination_in_any_binding(config: Config, host: str) -> bool:
    """True if any secret has a binding whose host matches ``host``.

    Uses the config-load host index rather than a per-request linear scan.
    """
    return bool(config.secrets_for_host(host))


def matched_binding(host: str, spec: SecretSpec) -> BindingSpec | None:
    """The first of ``spec``'s bindings whose host gate matches ``host``.

    Uses :meth:`BindingSpec.matches_host` so a wildcard binding's
    ``subdomains:`` discriminator is honoured — a `*.jfrog.io` binding scoped
    to ``subdomains: [mycompany]`` does not match ``evil.jfrog.io`` (returns
    None → G5 forward-verbatim, no injection).
    """
    for b in spec.bindings:
        if b.matches_host(host):
            return b
    return None


HeaderIndex = dict[str, tuple[tuple[int, str, SecretSpec, _HeaderTargetInjector], ...]]


def build_header_index(config: Config) -> HeaderIndex:
    """``{header_name: ((order, secret_name, spec, injector), ...)}``.

    The injector tree is static between config reloads, so walking it per
    request is pure waste. Built once per config snapshot (see
    ``addon._ResolvedSnapshot``) and consulted per request. ``order`` preserves
    config declaration order across the header buckets.
    """
    index: dict[str, list[tuple[int, str, SecretSpec, _HeaderTargetInjector]]] = {}
    order = 0
    for secret_name, spec in config.secrets.items():
        for child in iter_leaf_injectors(spec.inject):
            # Body leaves are handled by the streaming body path.
            if isinstance(child, _HeaderTargetInjector):
                index.setdefault(child.header, []).append((order, secret_name, spec, child))
                order += 1
    return {header: tuple(entries) for header, entries in index.items()}


def find_header_placeholder_matches(
    config: Config,
    header_get: Callable[[str], str | None],
    *,
    header_index: HeaderIndex | None = None,
) -> list[tuple[str, SecretSpec, _HeaderTargetInjector, str, str]]:
    """Every ``(secret_name, spec, injector, header_name, value)`` where
    the secret's placeholder appears inside its configured target header.

    Multiple matches => the request is ambiguous (the caller refuses to
    guess). Header-target injectors only — body leaves are handled by
    the streaming body path. The matched ``injector`` is either a
    :class:`HeaderInjector` (vault-secret substitution) or an
    :class:`Oauth2RefreshInjector` (exchange-then-substitute). Both
    share the placeholder-in-header detection shape; what differs is
    the resolution path the addon takes after this returns.
    ``header_get`` is the request's header accessor (case-insensitive,
    mitmproxy semantics) so this stays free of the flow object.
    """
    index = header_index if header_index is not None else build_header_index(config)
    matches: list[tuple[int, str, SecretSpec, _HeaderTargetInjector, str, str]] = []
    for header_name, entries in index.items():
        value = header_get(header_name)
        # Fast reject: every placeholder must carry the marker
        # (validate_placeholder_invariants), so a header without it cannot
        # match any secret. This is the common case — most requests carry no
        # placeholder at all — and it costs one scan per header instead of one
        # per secret.
        if not value or _PLACEHOLDER_MARKER not in value:
            continue
        for order, secret_name, spec, child in entries:
            if spec.placeholder in value:
                matches.append((order, secret_name, spec, child, header_name, value))
    # Restore config declaration order so the result is identical to the
    # pre-index scan (ambiguity is refused, but order must not drift).
    matches.sort(key=lambda m: m[0])
    return [m[1:] for m in matches]


# --- the decision -----------------------------------------------------------

_FORWARD = Decision(decision="forward_unmodified")


def decide(
    *,
    config: Config,
    host: str,
    port: int,
    method: str,
    path: str,
    connect_host: str | None,
    header_get: Callable[[str], str | None],
    header_index: HeaderIndex | None = None,
) -> Decision:
    """Compute the header-path verdict for one request. Pure.

    ``method`` should be upper-cased and ``path`` query-stripped by the
    caller (mirrors what the addon already extracts). ``header_get`` looks
    up a request header by name. The order of checks mirrors ``addon``'s
    ``requestheaders`` -> ``_run_header_injection_pipeline`` exactly:
    SNI consistency, destination allow-list, placeholder match, ambiguity,
    destination binding, scope, then allow.
    """
    # 1. SNI/Host consistency (G3): a CONNECT to one host then an inner
    #    request claiming another is a TLS-proxy laundering attempt.
    if connect_host and connect_host != host:
        return Decision(
            decision="denied",
            reason="sni_host_mismatch",
            response_status=403,
            response_body=SniHostMismatchError.client_message,
            extra={"destination": {"connect_host": connect_host, "request_host": host}},
        )

    # 2. Destination allow-list — enforced here (not only at CONNECT) so plain
    #    HTTP can't relay to hosts outside the binding set.
    if config.unmatched_destination_policy == "deny" and not destination_in_any_binding(
        config, host
    ):
        return Decision(
            decision="denied",
            reason="unmatched_destination",
            response_status=403,
            response_body=DestinationNotBoundError.client_message,
            extra={"destination": {"host": host, "port": port}},
        )

    # 3. Placeholder match in the configured target header(s).
    matches = find_header_placeholder_matches(config, header_get, header_index=header_index)
    if not matches:
        return _FORWARD
    if len(matches) > 1:
        # Two distinct configured placeholders in the request headers. Config
        # load forbids substring overlap, but an adversarial/accidental request
        # can still embed two — refuse to guess which secret to inject.
        return Decision(
            decision="denied",
            reason="ambiguous_placeholder_match",
            response_status=400,
            response_body=AmbiguousPlaceholderError.client_message,
            extra={"matched_secret_names": sorted({m[0] for m in matches})},
        )
    secret_name, secret_spec, matched_injector, header_name, _value = matches[0]

    # 4. The matched secret must be bound to this destination (else G5: forward
    #    the placeholder verbatim, audit the omission, no response).
    binding = matched_binding(host, secret_spec)
    if binding is None:
        return Decision(
            decision="denied",
            reason="destination_not_in_binding",
            secret_name=secret_name,
        )

    # 5. The binding's method/path scope must permit this request (else G5).
    if not binding.matches_scope(method, path):
        return Decision(
            decision="denied",
            reason="binding_scope_violation",
            secret_name=secret_name,
            extra={"method": method, "path": path},
        )

    # 6. Allowed. The addon fetches + renders + injects (and only then can an
    #    I/O failure produce secret_unavailable / secret_fetch_error / the
    #    composite_* denials — those are execution-layer, not policy).
    # For oauth2_refresh, the addon also runs the token-exchange step
    # between fetch and inject; ``token_endpoint_*`` outcomes are
    # execution-layer too.
    # Allowed. Routing the matched injector to its Decision execution handle is
    # extracted to keep decide() under the complexity gate.
    return _build_allowed_decision(
        secret_name=secret_name,
        secret_spec=secret_spec,
        matched_injector=matched_injector,
        header_name=header_name,
        binding=binding,
    )


def _build_allowed_decision(
    *,
    secret_name: str,
    secret_spec: SecretSpec,
    matched_injector: _HeaderTargetInjector,
    header_name: str,
    binding: BindingSpec,
) -> Decision:
    """Map an allowed match to a :class:`Decision` carrying exactly one execution
    handle for the matched injector type. Computed signers (sigv4/hmac/jwt)
    resolve in the addon ``request`` hook; oauth2 at requestheaders; header inline."""
    common = {
        "decision": "allowed",
        "reason": "binding_matched",
        "secret_name": secret_name,
        "secret_spec": secret_spec,
        "header_name": header_name,
        "matched_binding": binding,
    }
    if isinstance(matched_injector, Sigv4Injector):
        return Decision(sigv4_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, HmacInjector):
        return Decision(hmac_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, JwtBearerInjector):
        return Decision(jwt_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, Oauth2RefreshInjector):
        return Decision(oauth2_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, Oauth2ClientCredentialsInjector):
        return Decision(oauth2_cc_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, GithubAppInjector):
        return Decision(github_app_injector=matched_injector, **common)  # type: ignore[arg-type]
    if isinstance(matched_injector, GcpServiceAccountInjector):
        return Decision(gcp_sa_injector=matched_injector, **common)  # type: ignore[arg-type]
    return Decision(header_injector=matched_injector, **common)  # type: ignore[arg-type]
