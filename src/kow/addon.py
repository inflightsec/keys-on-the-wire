from __future__ import annotations

import asyncio
import logging
import sys
import types
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from mitmproxy import http, tls
from mitmproxy.addonmanager import Loader

from kow import _paths
from kow._derived_token_cache import DerivedTokenCache
from kow._healthz import healthz_response, is_healthz_request
from kow.audit import (
    REASON_HOST_NOT_IN_ALLOWLIST,
    REASON_INVALID_BINDING_METADATA,
    REASON_NO_BINDING_IN_NOTES,
    AuditWriter,
)
from kow.caching import CachingSecretsClient
from kow.config import (
    Config,
    build_backend,
    load_config,
    resolve_endpoint,
)
from kow.credential_endpoint import CredentialEndpoint
from kow.denials import (
    DestinationNotBoundError,
    SigningStateUnavailableError,
    UnrecognizedSigningInjectorError,
)
from kow.handlers import (
    BodyInjectionHandler,
    CompositeResolver,
    HeaderInjectionHandler,
    NotesActivator,
)
from kow.injectors.gcp_service_account import GcpServiceAccountResolver
from kow.injectors.github_app import GithubAppResolver
from kow.injectors.hmac_signer import HmacResolver
from kow.injectors.jwt_bearer import JwtResolver
from kow.injectors.oauth2_client_credentials import Oauth2CcResolver
from kow.injectors.oauth2_refresh import OauthResolver
from kow.injectors.sigv4 import Sigv4Resolver
from kow.matching import git_smart_http_effective_path
from kow.policy import (
    Decision,
    HeaderIndex,
    build_header_index,
    decide,
    destination_in_any_binding,
)
from kow.sshagent.server import SshAgentServer

_log = logging.getLogger("kow.addon")


def _emit_advisory(audit: AuditWriter, event: dict[str, object]) -> bool:
    """Emit a non-terminal policy advisory. True if it was written.

    Swallows write failures on purpose: an advisory carries no verdict, so a
    full disk or an unwritable audit must not convert an otherwise-allowed
    request into a failure. Terminal verdicts keep the strict G6 path in
    _fail_closed and are unaffected.
    """
    try:
        audit.emit(event)
    except Exception:  # noqa: BLE001 - advisory is best-effort by contract
        _log.warning("advisory audit write failed; request unaffected", exc_info=True)
        return False
    return True


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# mitmproxy loads this addon via SourceFileLoader.exec_module() without registering
# the module in sys.modules. On Python 3.13 that makes @dataclass's KW_ONLY detection
# deref None (dataclasses._is_type -> sys.modules.get(cls.__module__).__dict__), raising
# "AttributeError: 'NoneType' object has no attribute '__dict__'" at import and crash-
# looping the daemon. Registering a stand-in module under our own name gives dataclasses
# a namespace to resolve annotations against. Must run before the first @dataclass below.
if sys.modules.get(__name__) is None:
    sys.modules[__name__] = types.ModuleType(__name__)


@dataclass
class _ResolvedSnapshot:
    """Config + resolved vault-notes bindings as one snapshot. Shared by the cold
    load (configure_from_path) and the ADR-0032 background notes-refresh, so both
    resolve through exactly one path. The `out_*` maps are populated in place by
    NotesActivator.activate()."""

    config: Config
    backend: object
    placeholder_to_name: dict[str, str] = field(default_factory=dict)
    no_binding: set[str] = field(default_factory=set)
    invalid: set[str] = field(default_factory=set)
    allowlist_rejected: set[str] = field(default_factory=set)
    allowlist_rejected_hosts: dict[str, set[str]] = field(default_factory=dict)
    companion_headers: dict[str, dict[str, str]] = field(default_factory=dict)
    # Per-request header matcher index. Derived from `config`; rebuilt
    # wherever the snapshot is (cold load AND the ADR-0032 notes refresh).
    header_index: HeaderIndex = field(default_factory=dict)


def _honeytoken_names(config: Config) -> frozenset[str]:
    return frozenset(name for name, spec in config.secrets.items() if spec.honeytoken)


class AgentVaultProxyAddon:
    def __init__(self) -> None:
        self.config: Config | None = None
        # CachingSecretsClient wrapping whichever backend bindings.yaml selected.
        # Kept generic so future backends (1Password, Vault, etc.) plug in here.
        self.client: CachingSecretsClient | None = None
        self.audit: AuditWriter | None = None
        # BWS-notes activation state (ADR-0011). Populated in bws_notes/both
        # mode by configure(); empty/None in file mode. The request path
        # consults these to fail closed on a placeholder whose secret has no
        # binding (no spec) with the right audit reason.
        #   _placeholder_to_name: derived placeholder -> secret_name for EVERY
        #     listed BWS secret (bound, no-binding, or invalid).
        #   _no_binding_names / _invalid_names: the audit-reason split.
        self._placeholder_to_name: dict[str, str] = {}
        self._no_binding_names: set[str] = set()
        self._invalid_names: set[str] = set()
        # ADR-0024: names whose notes binding was dropped WHOLE by the
        # file-side notes_host_allowlist (no approved host remained) — the
        # pre-step attributes their placeholders as host_not_in_allowlist.
        # Partial rejections live on the header handler's
        # allowlist_rejected_hosts map instead (spec stays live).
        self._allowlist_rejected_names: set[str] = set()
        self._companion_headers: dict[str, dict[str, str]] = {}
        # Derived per-request header matcher index (see policy.build_header_index).
        # Keyed to the Config it was built from so it self-heals: any writer that
        # sets self.config without going through _publish_bindings still gets a
        # correct index rather than an empty one (which would match nothing).
        self._header_index: HeaderIndex = {}
        self._header_index_config: Config | None = None
        # Derived-token cache for the oauth2_refresh resolution step
        # (ADR-0017 §3 / §11). Sibling of ``self.client`` — vault secrets
        # and exchanged access tokens have incompatible flush/list/audit
        # semantics, so they live in separate caches. One instance per
        # addon, rebuilt on every ``configure_from_path`` so a config
        # reload starts with a cold derived-token cache.
        self._token_cache: DerivedTokenCache | None = None
        # Request-path handlers (see handlers.py). The composite resolver is
        # shared header+body so the same-UUID warning fires once per binding
        # across both paths; its warning set is reset on every reload.
        self._composite = CompositeResolver()
        self._header_handler = HeaderInjectionHandler(
            composite=self._composite,
            oauth_resolver=OauthResolver(),
            oauth_cc_resolver=Oauth2CcResolver(),
            github_app_resolver=GithubAppResolver(),
            gcp_sa_resolver=GcpServiceAccountResolver(),
        )
        self._body_handler = BodyInjectionHandler(composite=self._composite)
        # ADR-0027/0028: the computed signing injectors resolve in the `request`
        # hook (sigv4/hmac need the buffered body), so their resolvers live on
        # the addon; the header handler only stashes the verdict at
        # requestheaders.
        self._sigv4_resolver = Sigv4Resolver()
        self._hmac_resolver = HmacResolver()
        self._jwt_resolver = JwtResolver()
        # (secret, host, verb) triples already advised about an unscoped
        # binding — keeps the ADR-0047 advisory to one line per config smell.
        self._unscoped_advised: set[tuple[str, str, str]] = set()
        self._unscoped_advised_lock = Lock()
        self._notes_activator = NotesActivator()
        # ADR-0032: config path (so the background notes-refresh can re-read it)
        # and the background refresh task handle.
        self._config_path: Path | None = None
        self._refresh_task: asyncio.Task[None] | None = None
        # ADR-0050: the opt-in ADC credential endpoint. Restarted on every
        # config load so a changed placeholder or port takes effect.
        self._credential_endpoint: CredentialEndpoint | None = None
        # ADR-0053: the opt-in ssh-agent signing oracle. Same lifecycle as
        # the credential endpoint: restarted on every config load.
        self._ssh_agent: SshAgentServer | None = None

    def load(self, loader: Loader) -> None:
        default = str(_paths.resolve(_paths.LINUX_CONFDIR / "bindings.yaml"))
        loader.add_option(
            name="kow_config",
            typespec=str,
            default=default,
            help="Path to keys-on-the-wire bindings.yaml",
        )
        # Pre-rename option name (ADR-0045). A unit file or compose CMD still
        # passing --set avp_config= keeps working; drops in 2.0.0. Empty default
        # means "not set" — kow_config wins unless the operator set this one.
        loader.add_option(
            name="avp_config",
            typespec=str,
            default="",
            help="DEPRECATED alias for kow_config; set kow_config instead.",
        )

    def configure(self, updated: set[str]) -> None:
        if not {"kow_config", "avp_config"} & updated and self.config is not None:
            return
        from mitmproxy.ctx import options

        legacy = getattr(options, "avp_config", "") or ""
        if legacy:
            _log.warning(
                "avp_config is deprecated and will be removed in the next major "
                "release; set kow_config instead."
            )
        self.configure_from_path(legacy or options.kow_config)

    def configure_from_path(
        self,
        config_path: str | Path,
        *,
        backend_override: object | None = None,
    ) -> None:
        """Load config + (re)build the live state.

        Split out from :meth:`configure` so it can be driven directly in
        tests (and any non-mitmproxy harness) without the ctx.options shim.
        ``backend_override`` substitutes a backend instance for the one
        ``build_backend`` would construct — used by tests to inject a fake
        BWS backend; production passes None.
        """
        snap = self._resolve(config_path, backend_override)
        self._config_path = Path(config_path)
        new_client = CachingSecretsClient(
            backend=snap.backend,  # type: ignore[arg-type]
            ttl_seconds=snap.config.cache.ttl_seconds,
            jitter_seconds=snap.config.cache.jitter_seconds,
            max_entries=snap.config.cache.max_entries,
        )
        new_audit = AuditWriter(
            path=snap.config.audit.path,
            fail_on_unwritable=snap.config.audit.fail_on_unwritable,
            # ADR-0019 §5: honeytoken names so the writer auto-emits the tripwire.
            honeytoken_names=_honeytoken_names(snap.config),
        )
        # Reset the same-UUID warning set on a full reload — the operator may
        # have corrected the misconfigured binding; let the warning re-fire if
        # the new config still has the issue.
        self._composite.reset_warnings()
        # Publish. Maps BEFORE config (config is the last write) so a handler
        # that sees the new config also sees the matching attribution maps; each
        # STORE_ATTR is atomic and _capture_state freezes the tuple per request.
        self._publish_bindings(snap)
        self.client = new_client
        self.audit = new_audit
        self.config = snap.config
        # Fresh derived-token cache on every full (re)load — stale access tokens
        # from a prior config must not outlive the binding shape that minted them.
        self._token_cache = DerivedTokenCache()
        self._restart_credential_endpoint(snap.config)
        self._restart_ssh_agent(snap.config, new_client, new_audit)

    def _restart_ssh_agent(
        self, config: Config, client: CachingSecretsClient, audit: AuditWriter
    ) -> None:
        """Bring the ssh-agent listener (ADR-0053) in line with the loaded
        config. Always stops the old listener first — it holds the previous
        config's bindings and caches, and a stale oracle is worse than a
        brief connection refusal during reload."""
        if self._ssh_agent is not None:
            self._ssh_agent.stop()
            self._ssh_agent = None
        spec = config.ssh
        if spec is None or not spec.enabled:
            return
        server = SshAgentServer(spec, client, audit)
        server.start()
        self._ssh_agent = server

    def _restart_credential_endpoint(self, config: Config) -> None:
        """Bring the ADC credential endpoint in line with the loaded config.
        Always stops the old listener first: a stale one would keep serving the
        previous placeholder, which the new config may no longer substitute."""
        if self._credential_endpoint is not None:
            self._credential_endpoint.stop()
            self._credential_endpoint = None
        # Re-resolve against the EFFECTIVE config: notes activation runs after
        # Config validation and can replace the SecretSpec the endpoint was
        # bound to, which would leave it serving a placeholder the live binding
        # no longer recognises (Oracle review, 2026-09-11).
        try:
            spec = resolve_endpoint(config)
        except ValueError:
            _log.exception("credential endpoint could not be bound; not serving")
            raise
        if spec is None or not spec.enabled:
            return
        endpoint = CredentialEndpoint(spec)
        endpoint.start()
        self._credential_endpoint = endpoint

    def _resolve(
        self, config_path: str | Path, backend_override: object | None
    ) -> _ResolvedSnapshot:
        """Load config + resolve vault-notes bindings into a snapshot. Used by
        both the cold load and the ADR-0032 background refresh (which passes the
        LIVE backend so no new backend/client is built). Raises on any resolution
        failure — the refresh loop relies on that to keep the previous snapshot.

        BWS-notes activation (ADR-0011 item 3): in notes/both mode, bindings are
        resolved from the backend's per-secret notes and MERGED into the config's
        secrets map (notes win). file mode is left untouched — no listing.
        """
        config_path = Path(config_path)
        new_config = load_config(config_path)
        if backend_override is not None:
            backend: object = backend_override
        else:
            backend, _ = build_backend(new_config)
        snap = _ResolvedSnapshot(config=new_config, backend=backend)
        if new_config.binding_source != "file":
            self._notes_activator.activate(
                new_config=new_config,
                backend=backend,
                config_path=config_path,
                out_placeholder_to_name=snap.placeholder_to_name,
                out_no_binding=snap.no_binding,
                out_invalid=snap.invalid,
                out_companion_headers=snap.companion_headers,
                out_allowlist_rejected=snap.allowlist_rejected,
                out_allowlist_rejected_hosts=snap.allowlist_rejected_hosts,
            )
        return snap

    def _publish_bindings(self, snap: _ResolvedSnapshot) -> None:
        """Atomic-swap the binding attribution maps. Maps ONLY — the caller
        publishes self.config LAST (the tear-free ordering). The partial-rejection
        map rides on the header handler, consulted at the deny site."""
        self._placeholder_to_name = snap.placeholder_to_name
        self._no_binding_names = snap.no_binding
        self._invalid_names = snap.invalid
        self._allowlist_rejected_names = snap.allowlist_rejected
        self._header_handler.allowlist_rejected_hosts = snap.allowlist_rejected_hosts
        self._companion_headers = snap.companion_headers
        # Built HERE, not at snapshot creation: notes activation adds
        # secrets to config afterwards, and it mutates the same Config
        # object, so an index built earlier would be silently stale.
        snap.header_index = build_header_index(snap.config)
        self._header_index = snap.header_index
        self._header_index_config = snap.config

        # Startup/reload visibility (2026-07-23): one INFO line so an operator can
        # confirm at a glance which secrets are injectable vs dropped, without
        # reading the request path — the "is my binding live?" question the logs
        # previously couldn't answer. Names only (never values); DEBUG lists them.
        all_names = set(snap.placeholder_to_name.values())
        inactive = snap.no_binding | snap.invalid | snap.allowlist_rejected
        active = sorted(all_names - inactive)
        _log.info(
            "bindings published: %d injectable, %d no-binding, %d invalid, "
            "%d allowlist-rejected (%d secrets listed)",
            len(active),
            len(snap.no_binding),
            len(snap.invalid),
            len(snap.allowlist_rejected),
            len(all_names),
        )
        if active and _log.isEnabledFor(logging.DEBUG):
            _log.debug("injectable secrets: %s", ", ".join(active))

    def refresh_notes(self) -> None:
        """ADR-0032: re-resolve vault bindings and atomic-swap the snapshot,
        KEEPING the warm value + derived-token caches (a full reconfigure would
        drop them and force OAuth re-exchange every interval). Blocking (vault
        listing), so the loop calls it via ``asyncio.to_thread``. Raises on
        resolution failure BEFORE publishing anything, so the caller keeps the
        previous snapshot."""
        config = self.config
        client = self.client
        if config is None or client is None or self._config_path is None:
            return
        if config.binding_source == "file":
            return
        backend = getattr(client, "_backend", None)
        if backend is None:
            return
        # Fresh listing so a newly-added secret's note is seen (backends cache
        # their name/note map).
        flush = getattr(backend, "flush_name_map", None)
        if callable(flush):
            flush()
        old_names = frozenset(config.secrets)
        snap = self._resolve(self._config_path, backend)
        # Fail-safe: activate() DEGRADES to empty on a transient listing/salt
        # failure rather than raising. A refresh must NOT publish a degraded
        # (emptied) snapshot — that would drop every live binding on a vault blip.
        # Keep the previous snapshot and retry next interval.
        if self._notes_activator.last_degraded_reason is not None:
            _log.warning(
                "notes refresh degraded (%s); keeping previous bindings",
                self._notes_activator.last_degraded_reason,
            )
            return
        # Publish: maps first, config last (tear-free); client/audit/token cache
        # are deliberately kept warm.
        self._publish_bindings(snap)
        audit = self.audit
        if audit is not None:
            audit.set_honeytoken_names(_honeytoken_names(snap.config))
        self.config = snap.config
        # The refreshed snapshot can carry a different placeholder or a replaced
        # SecretSpec for the endpoint's binding; a listener left on the old one
        # would hand clients a string this config no longer substitutes. A bind
        # failure here must not take the refresh down — the bindings are already
        # published and correct (Oracle review, 2026-09-11).
        try:
            self._restart_credential_endpoint(snap.config)
        except Exception:  # noqa: BLE001
            _log.exception("credential endpoint not restarted after notes refresh")
        new_names = frozenset(snap.config.secrets)
        if audit is not None and new_names != old_names:
            audit.emit(
                {
                    "type": "notes_refreshed",
                    "added": sorted(new_names - old_names),
                    "removed": sorted(old_names - new_names),
                }
            )

    def _index_for(self, config: Config) -> HeaderIndex:
        """The header index for ``config``, rebuilt if it was never published
        or belongs to a previous config."""
        if self._header_index_config is not config:
            self._header_index = build_header_index(config)
            self._header_index_config = config
        return self._header_index

    def _capture_state(
        self,
    ) -> tuple[
        Config | None,
        CachingSecretsClient | None,
        AuditWriter | None,
        dict[str, dict[str, str]],
    ]:
        """Snapshot (config, client, audit) at handler entry. Each individual
        attribute read is atomic; the per-handler snapshot prevents using
        a new config with an old client (or vice versa) within one request."""
        return self.config, self.client, self.audit, self._companion_headers

    def running(self) -> None:
        # Mitmproxy calls this once after addons are wired up and the proxy
        # is about to accept connections.
        #
        # Order matters: run the security preflight FIRST.
        # One of the checks is "audit log lacks chattr +a" — emitting the
        # proxy_restart event before that check would write into a
        # potentially mutable log we're about to warn about. If preflight
        # is in strict mode and a warning fires, it raises and aborts
        # startup before any audit emission too.
        if self.config is not None:
            from kow._preflight import emit_preflight

            emit_preflight(self.config)
        # Now emit the startup record — closes G9's "restart itself
        # is audited" half (the "history preserved" half comes from chattr +a).
        if self.audit is not None:
            self.audit.emit({"type": "proxy_restart"})
        self._start_notes_refresh()

    def _start_notes_refresh(self) -> None:
        """ADR-0032: start the background notes-refresh loop when a running event
        loop exists (the mitmproxy runtime). No-op in the sync test/CLI harness —
        there, tests drive refresh_notes() directly."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = loop.create_task(self._notes_refresh_loop())

    async def _notes_refresh_loop(self) -> None:
        while True:
            config = self.config
            interval = config.notes_refresh_seconds if config is not None else 0
            if interval <= 0 or (config is not None and config.binding_source == "file"):
                # Disabled (possibly toggled off by a reload) — idle-poll so a
                # later reload can re-enable it without a restart.
                await asyncio.sleep(30)
                continue
            await asyncio.sleep(interval)
            try:
                await asyncio.to_thread(self.refresh_notes)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Fail-safe: keep the previous bindings, never crash the daemon.
                _log.exception("notes refresh failed; keeping previous bindings")

    def done(self) -> None:
        task = self._refresh_task
        if task is not None:
            task.cancel()
            self._refresh_task = None
        if self._credential_endpoint is not None:
            self._credential_endpoint.stop()
            self._credential_endpoint = None
        if self._ssh_agent is not None:
            self._ssh_agent.stop()
            self._ssh_agent = None

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        """ADR-0026: scope TLS termination to bound hosts.

        For a destination the live config has no binding for, tunnel the
        connection opaquely (``ignore_connection``) instead of MITM-terminating
        it — so kow never holds plaintext for traffic it does not broker, and a
        stolen kow CA cannot decrypt it (the client validates the upstream's
        real certificate end-to-end). The tunnel is logged (``tls_passthrough``,
        destination host only) so exfil *visibility* survives without
        interception. ``tls_termination: all`` restores full termination. Runs
        per-connection at handshake, so a binding added by hot-reload applies to
        new connections (existing tunnels stay tunnels).
        """
        config, _client, audit, _companion_headers = self._capture_state()
        if config is None or config.tls_termination == "all":
            return
        # SNI is what the client asked for; fall back to the CONNECT/server
        # address host when SNI is absent (non-SNI client).
        host = data.client_hello.sni
        if not host:
            server_address = data.context.server.address
            host = server_address[0] if server_address else None
        if host is not None and destination_in_any_binding(config, host):
            return  # bound -> terminate + inject (unchanged path)
        # Unbound (or unknown host) -> opaque passthrough. No leaf cert minted,
        # no decryption. unmatched_destination_policy: deny has already 403'd an
        # unbound CONNECT before reaching here, so this only tunnels what is
        # allowed through.
        data.ignore_connection = True
        if audit is not None:
            audit.emit(
                {
                    "type": "tls_passthrough",
                    "reason": "unbound_destination",
                    "destination": {"host": host or "<no-sni>"},
                }
            )

    def http_connect(self, flow: http.HTTPFlow) -> None:
        config, _client, audit, _companion_headers = self._capture_state()
        if config is None or audit is None:
            return
        # The address mitmproxy will dial, never the client-supplied authority:
        # pretty_host prefers the Host/:authority header, which a lower-trust
        # client controls independently of where the connection actually goes.
        target_host = flow.request.host
        if destination_in_any_binding(config, target_host):
            flow.metadata["avp_request_id"] = str(uuid.uuid4())
            flow.metadata["avp_connect_host"] = target_host
            return
        if config.unmatched_destination_policy == "deny":
            audit.emit(
                {
                    "type": "deny",
                    "reason": "unmatched_destination",
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                403,
                DestinationNotBoundError.client_message,
                {"Content-Type": "text/plain"},
            )

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # Three-stage pipeline at the same hook (P0.6):
        #
        # 1. Shared deny gates (SNI consistency, destination allow-list) —
        #    if they fire, flow.response is set and we abort.
        # 2. Header injection — one header per request gets substituted
        #    (or audited+denied) in :meth:`_execute_header_decision`, driven
        #    by the pure :func:`kow.policy.decide` verdict.
        # 3. Body injection streaming setup — for hosts with body bindings,
        #    attach a streaming replacer to ``flow.request.stream`` so the
        #    body never buffers in memory. Chunked transfer encoding lets
        #    kow emit modified bytes as they arrive without knowing the
        #    final body length in advance.
        #
        # Stages 2 and 3 can fire in the same request when different
        # secrets bind header + body on the same host. They never share
        # a secret in P0.6 — composite header+body injection lands with
        # MultiInjector in P0.7.
        #
        # Liveness/readiness probe (roadmap: Observability). Answered here,
        # BEFORE the destination allow-list, so the probe is not 403'd as an
        # unmatched destination; never proxied upstream and emits no audit
        # (health polling would otherwise flood the log). Ready = fully
        # configured (config + client + audit all published by configure()).
        if is_healthz_request(flow):
            flow.response = healthz_response(
                ready=(
                    self.config is not None and self.client is not None and self.audit is not None
                )
            )
            return
        #
        # Snapshot (config, client, audit) at handler entry. Any concurrent
        # configure() publishes a new triple that this request will never see.
        config, client, audit, companion_headers = self._capture_state()
        if config is None or client is None or audit is None:
            return
        request_id = flow.metadata.get("avp_request_id") or str(uuid.uuid4())
        flow.metadata["avp_request_id"] = request_id

        # Authorize on the address mitmproxy dials, not the authority the client
        # claims (pretty_host prefers the Host/:authority header). target_host
        # threads down to every injector, so this is the single decision input
        # for the header, body and signing paths alike.
        target_host = flow.request.host
        # G3 SNI/Host consistency: compare the claimed authority against that
        # dialed address. In transparent mode request.host IS the
        # CONNECT-established server address, so this reaches the tunnelled
        # requests that flow.metadata never crosses the CONNECT boundary for.
        claimed_host = flow.request.host_header
        if claimed_host is not None:
            claimed_host = claimed_host.split(":", 1)[0].rstrip(".").lower()
        connect_host = flow.metadata.get("avp_connect_host") or (
            claimed_host if claimed_host and claimed_host != target_host.lower() else None
        )
        method = flow.request.method.upper()
        raw_path, _, query = flow.request.path.partition("?")
        # Git smart-HTTP push/clone carries its write intent in the
        # `?service=` query the path scope strips; canonicalise the discovery
        # GET to its data-phase path so `paths:` scoping treats both phases as
        # one operation (no-op for all non-git traffic). See matching.py.
        path = git_smart_http_effective_path(raw_path, query or None)

        # Pure policy verdict (ADR-0013). decide() does no I/O and no flow
        # mutation; this method EXECUTES the verdict — the fetch/render/inject
        # and the G6-ordered audit live in _execute_header_decision, unchanged.
        decision = decide(
            config=config,
            header_index=self._index_for(config),
            host=target_host,
            port=flow.request.port,
            method=method,
            path=path,
            connect_host=connect_host,
            header_get=flow.request.headers.get,
        )

        # Hard pre-gates (SNI consistency, destination allow-list) abort with a
        # 4xx and fire BEFORE the unbound-placeholder audit — preserving the
        # original ordering. These emit ``type: deny``.
        if decision.reason in ("sni_host_mismatch", "unmatched_destination"):
            audit.emit(
                {
                    "type": "deny",
                    "request_id": request_id,
                    "reason": decision.reason,
                    "destination": decision.extra["destination"],
                }
            )
            assert decision.response_status is not None
            assert decision.response_body is not None
            flow.response = http.Response.make(
                decision.response_status,
                decision.response_body,
                {"Content-Type": "text/plain"},
            )
            return

        # BWS-notes fail-closed gate (ADR-0011): a placeholder for a secret
        # with NO binding (or a malformed one) has no SecretSpec, so the header
        # verdict never matches it and it forwards verbatim. We AUDIT it with
        # the precise reason so the operator sees the typo/no-binding rather
        # than silence. Pre-step; no-op in file mode.
        self._audit_unbound_placeholders(
            flow=flow,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        )

        self._audit_methods_default_deprecation(
            flow=flow,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            method=method,
            decision=decision,
        )

        # Execute the header verdict — may set flow.response on deny.
        self._header_handler.execute(
            flow=flow,
            decision=decision,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            companion_headers=companion_headers,
            token_cache=self._token_cache,
        )

        # Body streaming setup. Runs alongside header injection unless the
        # header path already set a response (request being aborted).
        if flow.response is None:
            self._body_handler.setup(
                flow=flow,
                config=config,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
            )

    def _audit_unbound_placeholders(
        self,
        *,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        """Audit any request header carrying a placeholder for a no-binding or
        invalid-binding BWS secret (ADR-0011 fail-closed reasons).

        These secrets have no SecretSpec, so the header pipeline never matches
        them — the placeholder is forwarded verbatim (fail closed, no real
        value injected). This method ONLY adds the audit record with the
        precise reason; it does NOT set flow.response (forward-unmodified is
        the documented default — an egress firewall enforces actual blocking).
        Emits at most one event per affected secret per request.

        Snapshot the attribution maps once; they are replaced atomically by
        configure(), so a single read is a consistent view. No-op in file mode
        (the maps are empty).
        """
        placeholder_to_name = self._placeholder_to_name
        if not placeholder_to_name:
            return
        no_binding = self._no_binding_names
        invalid = self._invalid_names
        allowlist_rejected = self._allowlist_rejected_names
        seen: set[str] = set()
        for value in flow.request.headers.values():
            if not value:
                continue
            for placeholder, secret_name in placeholder_to_name.items():
                if secret_name in seen:
                    continue
                if placeholder not in value:
                    continue
                if secret_name in invalid:
                    reason = REASON_INVALID_BINDING_METADATA
                elif secret_name in allowlist_rejected:
                    # ADR-0024: every host in this secret's note was outside
                    # the file-side allowlist — the binding never activated.
                    reason = REASON_HOST_NOT_IN_ALLOWLIST
                elif secret_name in no_binding:
                    reason = REASON_NO_BINDING_IN_NOTES
                else:
                    # Has a real spec — handled by the header/body pipeline.
                    continue
                seen.add(secret_name)
                audit.emit(
                    {
                        "type": "inject_decision",
                        "request_id": request_id,
                        "decision": "denied",
                        "reason": reason,
                        "secret_name": secret_name,
                        "binding_source": "bws_notes",
                        "destination": {"host": target_host, "port": flow.request.port},
                    }
                )

    def _audit_methods_default_deprecation(
        self,
        *,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        method: str,
        decision: Decision,
    ) -> None:
        """Advise once per (secret, host, verb) that a binding took a mutating
        verb without naming ``methods:``.

        Deduped per process: the advisory is a config smell, not a per-request
        event, and emitting it on every call would bury the injection records
        an operator actually reads (ADR-0047).
        """
        if decision.decision != "allowed":
            return
        binding = decision.matched_binding
        if binding is None or binding.methods is not None:
            return
        if method not in _MUTATING_METHODS:
            return
        secret_name = decision.secret_name
        assert secret_name is not None
        # Keyed on the CONFIGURED host pattern, never the request host: a
        # wildcard binding would otherwise let attacker-chosen subdomains grow
        # this set without bound for the process lifetime (Oracle C3).
        advisory_key = (secret_name, binding.host, method)
        with self._unscoped_advised_lock:
            if advisory_key in self._unscoped_advised:
                return
        written = _emit_advisory(
            audit,
            {
                "type": "policy_advisory",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_methods_unscoped",
                "secret_name": secret_name,
                "method": method,
                "destination": {"host": target_host, "port": flow.request.port},
            },
        )
        # Mark advised only on a SUCCESSFUL write. Marking first would let one
        # transient audit failure silence this config smell for the whole
        # process lifetime (Oracle final C2). A rare duplicate under
        # concurrency is the cheaper failure than a permanently lost signal.
        if written:
            with self._unscoped_advised_lock:
                self._unscoped_advised.add(advisory_key)

    def request(self, flow: http.HTTPFlow) -> None:
        """Sign a body-hashing request once the full body has buffered.

        ``requestheaders`` stashed the ALLOWED signing verdict on
        ``flow.metadata['avp_signing']`` — sigv4/hmac hash the request body,
        which had not arrived at header time (jwt rides the same seam for a
        single dispatch). This hook fires with the complete request, so the
        signer can hash it, then dispatches to the one matching signer. No-op for
        every non-signing request; fails closed (503) if the runtime state is
        gone (reload race) or the stashed injector is unrecognized
        (ADR-0027/0028/0030).
        """
        stashed = flow.metadata.get("avp_signing")
        if stashed is None:
            return
        decision, request_id, target_host = stashed
        _config, client, audit, _companion = self._capture_state()
        if client is None or audit is None:
            # Reload race (Oracle C2): requestheaders stashed an ALLOWED signing
            # verdict, but the runtime state needed to sign vanished before the
            # body arrived. Fail closed — never forward the placeholder-bearing
            # request unsigned. The header still carries the (non-secret)
            # placeholder, so nothing leaks, but kow must not emit a
            # half-processed request; deny with 503 like the signer key-missing
            # path does.
            if audit is not None:
                audit.emit(
                    {
                        "type": "deny",
                        "request_id": request_id,
                        "reason": "signing_state_unavailable",
                        "destination": {"host": target_host, "port": flow.request.port},
                    }
                )
            flow.response = http.Response.make(
                503,
                SigningStateUnavailableError.client_message,
                {"Content-Type": "text/plain"},
            )
            return
        # Exactly one signing injector reaches this hook: policy.decide() sets
        # exactly one, and only sigv4/hmac/jwt stash `avp_signing`. Dispatch is
        # explicit per type (Oracle C3) — a JWT default-branch would silently
        # misroute a future body-signer added to the stash path but not here, so
        # the (unreachable today) else fails closed instead of guessing JWT.
        if decision.sigv4_injector is not None:
            self._sigv4_resolver.sign_and_apply(
                flow=flow,
                decision=decision,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
            )
        elif decision.hmac_injector is not None:
            self._hmac_resolver.sign_and_apply(
                flow=flow,
                decision=decision,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
            )
        elif decision.jwt_injector is not None:
            self._jwt_resolver.sign_and_apply(
                flow=flow,
                decision=decision,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
            )
        else:
            audit.emit(
                {
                    "type": "deny",
                    "request_id": request_id,
                    "reason": "unrecognized_signing_injector",
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                UnrecognizedSigningInjectorError.client_message,
                {"Content-Type": "text/plain"},
            )

    def response(self, flow: http.HTTPFlow) -> None:
        if self.audit is None or flow.response is None:
            return
        request_id = flow.metadata.get("avp_request_id")
        if request_id is None:
            return
        self.audit.emit(
            {
                "type": "upstream_response",
                "request_id": request_id,
                "status": flow.response.status_code,
            }
        )


addons = [AgentVaultProxyAddon()]
