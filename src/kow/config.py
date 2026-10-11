from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    BaseModel,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from kow.config_models import _INJECTOR_TYPES as _INJECTOR_TYPES
from kow.config_models import _PLACEHOLDER_MARKER as _PLACEHOLDER_MARKER
from kow.config_models import _PLACEHOLDER_MIN_LEN as _PLACEHOLDER_MIN_LEN
from kow.config_models import (
    _STRICT_MODEL,
    GcpServiceAccountInjector,
    GithubAppInjector,
    HmacInjector,
    InjectorSpec,
    JwtBearerInjector,
    MultiInjector,
    Oauth2ClientCredentialsInjector,
    Oauth2RefreshInjector,
    Sigv4Injector,
    _validate_inject_block,
    iter_leaf_injectors,
    validate_placeholder_invariants,
)
from kow.config_models import BodyInjector as BodyInjector
from kow.config_models import HeaderInjector as HeaderInjector
from kow.matching import host_matches_pattern, path_glob_matches
from kow.sshagent.config import SshSpec
from kow.template import KowTemplate, UnsupportedTemplateError

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# A single DNS label: 1-63 chars, alphanumerics with internal hyphens.
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# A valid binding host: one or more dot-separated labels, with an OPTIONAL
# single leading "*." wildcard. Anchored/fullmatch. Rejects empty strings,
# whitespace, bare "*", embedded "*", and other non-hostname junk. The
# separate ">= 2 labels behind a wildcard" rule is enforced in the validator.
_HOST_RE = re.compile(rf"^(?:\*\.)?{_HOST_LABEL}(?:\.{_HOST_LABEL})*$")
# A single DNS label — the shape a `subdomains:` wildcard discriminator entry
# must take (the `*.` in `*.jfrog.io` matches exactly one label).
_SUBDOMAIN_LABEL_RE = re.compile(rf"^{_HOST_LABEL}$")

# Public suffixes a "*." wildcard must never span — `*.co.uk` would broker a
# credential to EVERY .co.uk registrant, a TLD-wide blast radius the naive
# ">= 2 labels" rule misses (co.uk has two labels but is a registry suffix,
# not a registrable domain). This is a curated subset of the Mozilla Public
# Suffix List covering the common multi-label registry suffixes AND the bare
# TLDs (the latter are also caught by the label-count rule; listed here for
# defense in depth). NOT exhaustive — the PSL has ~9000 entries. For full
# coverage, an operator enables strict PSL validation via a pinned dependency
# (see docs); this bundled set blocks the footguns without a runtime dep.
_PUBLIC_SUFFIX_WILDCARD_DENY = frozenset(
    {
        # bare TLDs (redundant with label-count rule; belt-and-suspenders)
        "com",
        "net",
        "org",
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "cloud",
        "xyz",
        # multi-label ccTLD registry suffixes (the real gap)
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "me.uk",
        "ltd.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "co.za",
        "co.jp",
        "or.jp",
        "com.br",
        "com.cn",
        "com.mx",
        "co.in",
        "co.kr",
        "com.tr",
        "com.sg",
        # common platform/SaaS suffixes that are effectively public
        "github.io",
        "gitlab.io",
        "herokuapp.com",
        "cloudfront.net",
        "s3.amazonaws.com",
        "azurewebsites.net",
        "web.app",
        "firebaseapp.com",
        "pages.dev",
        "workers.dev",
        "vercel.app",
        "netlify.app",
    }
)


class BindingSpec(BaseModel):
    model_config = _STRICT_MODEL

    host: str
    methods: list[str] | None = None
    paths: list[str] | None = None
    # Wildcard-host discriminator (ADR-0034): only meaningful on a `*.`
    # wildcard host. When set, the wildcard's single matched leftmost label
    # must be one of these exact labels — so a `*.jfrog.io` binding brokers
    # only to `mycompany.jfrog.io`, never to an attacker's `evil.jfrog.io`.
    # Shrinks a wildcard's blast radius from "every subdomain" to a named
    # allowlist without listing full hosts. None = wildcard matches any
    # single label (unchanged behaviour).
    subdomains: list[str] | None = None

    @field_validator("host")
    @classmethod
    def normalize_and_validate_host(cls, v: str) -> str:
        # A binding MUST name a real destination host. Enforced here so it is
        # STRUCTURALLY IMPOSSIBLE to define a secret with no concrete host: an
        # empty, whitespace, or match-all host would either give a credential
        # an unbounded blast radius, or (for bare "*") create a silently dead
        # binding the operator believes is active. Every secret already
        # requires >= 1 binding (reject_empty_bindings) and `host` is a
        # required field; this closes the "present but meaningless" gap.
        original = v
        v = v.strip()
        # DNS is case-insensitive; lowercase at load + warn on uppercase so
        # silent rewrites don't lose audit value.
        if v != v.lower():
            import logging

            logging.getLogger("kow.config").warning(
                "binding host %r contains uppercase; normalising to %r.",
                original,
                v.lower(),
            )
            v = v.lower()
        if not v:
            raise ValueError("binding host is required and cannot be empty or whitespace")
        if v == "*" or ("*" in v and not v.startswith("*.")):
            raise ValueError(
                f"host {original!r}: bare or embedded '*' is not allowed. Use an exact host "
                "(e.g. api.example.com) or a '*.suffix' wildcard with at least two labels."
            )
        if v.startswith("*."):
            if v.count(".") < 2:
                raise ValueError(f"wildcard '{v}' is too broad; require at least two DNS labels")
            base = v[2:]  # everything after the leading "*."
            if base in _PUBLIC_SUFFIX_WILDCARD_DENY:
                raise ValueError(
                    f"wildcard '{v}' spans the public suffix '{base}' — that would broker the "
                    "secret to EVERY domain under a registry TLD. Bind to a specific registrable "
                    "domain (e.g. '*.your-tenant.example.com') or an exact host instead."
                )
        if not _HOST_RE.fullmatch(v):
            raise ValueError(
                f"host {original!r} is not a valid hostname (dot-separated DNS labels of "
                "a-z, 0-9, '-'; optional single leading '*.')."
            )
        return v

    @field_validator("methods")
    @classmethod
    def normalize_and_validate_methods(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError(
                "empty methods = deny-all-methods; omit the field for any-method instead"
            )
        normalized: list[str] = []
        for m in v:
            up = m.upper()
            if up == "*":
                raise ValueError(
                    "methods cannot contain '*'; omit the field entirely for any-method"
                )
            if up not in _HTTP_METHODS:
                raise ValueError(f"unknown HTTP method '{m}'; allowed: {sorted(_HTTP_METHODS)}")
            normalized.append(up)
        return normalized

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError("empty paths = deny-all-paths; omit the field for any-path instead")
        for p in v:
            if not p.startswith("/"):
                raise ValueError(f"path '{p}' must start with '/'")
        return v

    @field_validator("subdomains")
    @classmethod
    def normalize_and_validate_subdomains(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError(
                "empty subdomains = deny-all-subdomains; omit the field for any-subdomain instead"
            )
        normalized: list[str] = []
        for label in v:
            lowered = label.strip().lower()
            if not _SUBDOMAIN_LABEL_RE.fullmatch(lowered):
                raise ValueError(
                    f"subdomain {label!r} is not a single DNS label "
                    "(a-z, 0-9, '-'; no dots, no wildcard)"
                )
            normalized.append(lowered)
        return normalized

    @model_validator(mode="after")
    def subdomains_require_wildcard_host(self) -> BindingSpec:
        # `subdomains:` narrows which leftmost label a `*.` wildcard may match;
        # it is meaningless (and almost certainly an operator error) on an
        # exact host, where the host itself already pins the subdomain. Reject
        # it fail-closed rather than silently ignore it.
        if self.subdomains is not None and not self.host.startswith("*."):
            raise ValueError(
                f"subdomains: is only valid on a '*.' wildcard host; host {self.host!r} "
                "is exact. Bind the exact host directly, or drop the subdomains field."
            )
        return self

    def matches_host(self, host: str) -> bool:
        """True if ``host`` matches this binding's host pattern AND, for a
        wildcard host with a ``subdomains:`` allowlist, the matched leftmost
        label is allowlisted. Caller passes the raw request host (case
        normalised here). This is the host gate ``matched_binding`` uses; the
        method/path gate is :meth:`matches_scope`."""
        if not host_matches_pattern(host, self.host):
            return False
        if self.subdomains is None:
            return True
        # host_matches_pattern already guaranteed a single-label wildcard match,
        # so the leftmost label is the discriminator.
        label = host.lower().split(".", 1)[0]
        return label in self.subdomains

    def matches_scope(self, method: str, path: str) -> bool:
        """True if this binding's optional method/path scope allows the
        request. Bindings with both fields omitted always allow. Caller
        passes the uppercased method and the query-stripped path."""
        if self.methods is not None and method not in self.methods:
            return False
        if self.paths is None:
            return True
        return any(path_glob_matches(p, path) for p in self.paths)


_COMPOSE_MIN = 1
_COMPOSE_MAX = 4  # covers tenant_id-style patterns


class SecretSpec(BaseModel):
    model_config = _STRICT_MODEL

    placeholder: str
    inject: InjectorSpec
    compose: list[str] | None = None
    bindings: list[BindingSpec]

    # Populated when inject.template is set; None for inject.format.
    _compiled_template: KowTemplate | None = PrivateAttr(default=None)
    # Which source produced this spec (ADR-0011 item 6). Defaults to "file":
    # a spec loaded from bindings.yaml is file-sourced. The BindingsResolver
    # sets "bws_notes" on specs built from a BWS secret's notes. The addon
    # reads this onto the inject_decision audit event's `binding_source`.
    # exclude=True keeps it OUT of model_dump()/JSON so the file-loaded
    # schema and the parity dumps are byte-unchanged; it's a settable runtime
    # attribute, not part of the serialised contract.
    binding_source: str = Field(default="file", exclude=True)

    # ADR-0019 §5: a honeytoken (canary) secret. When true, any inject_decision
    # naming this secret auto-emits a follow-up `honeytoken_triggered` audit
    # event (see audit.AuditWriter) so the fleet collector alerts on a single
    # unambiguous type. The tripwire fires on ANY use of the planted
    # placeholder — injected, denied, scope-violated, or aimed at the wrong
    # destination — before any real value moves. Per-secret (the kow "binding"
    # the audit `binding_name` names); honored regardless of binding_source.
    honeytoken: bool = False

    @field_validator("bindings")
    @classmethod
    def reject_empty_bindings(cls, v: list[BindingSpec]) -> list[BindingSpec]:
        if not v:
            raise ValueError("empty bindings = deny-all; add explicit bindings or remove the entry")
        return v

    @model_validator(mode="after")
    def validate_compose_and_template(self) -> SecretSpec:  # noqa: C901
        # Multi-injector bindings carry format/template on each child, not
        # the parent spec; `compose:` cannot combine with multi.
        if isinstance(self.inject, MultiInjector):
            if self.compose is not None:
                raise ValueError("compose: cannot be used with inject.type: multi")
            return self
        # OAuth2 refresh injects an *exchanged* access token, not a
        # vault-composed secret. ``compose:`` is for assembling multiple
        # vault secrets into one value; it has no meaning when the value
        # comes from an upstream token-exchange. Reject the combination.
        if isinstance(self.inject, Oauth2RefreshInjector):
            if self.compose is not None:
                raise ValueError("compose: cannot be used with inject.type: oauth2_refresh")
            return self
        # SigV4 signs the request from named credential secrets (access key +
        # secret key + optional session token); it has its own multi-secret
        # mechanism, so ``compose:`` (single-value assembly) is meaningless.
        if isinstance(self.inject, Sigv4Injector):
            if self.compose is not None:
                raise ValueError("compose: cannot be used with inject.type: sigv4")
            return self
        # hmac + jwt_bearer are computed signers keyed on a single vault secret;
        # compose: (assemble one value from many) has no meaning for them.
        if isinstance(self.inject, HmacInjector | JwtBearerInjector):
            if self.compose is not None:
                raise ValueError(f"compose: cannot be used with inject.type: {self.inject.type}")
            return self
        # Client-credentials / github_app inject an exchanged/minted token, not
        # a vault-composed value; compose: has no meaning.
        if isinstance(
            self.inject,
            Oauth2ClientCredentialsInjector | GithubAppInjector | GcpServiceAccountInjector,
        ):
            if self.compose is not None:
                raise ValueError(f"compose: cannot be used with inject.type: {self.inject.type}")
            return self
        has_compose = self.compose is not None
        has_template = self.inject.template is not None

        # compose: ↔ inject.template are co-required.
        if has_compose and not has_template:
            raise ValueError("compose: requires inject.template")
        if has_template and not has_compose:
            raise ValueError("inject.template requires compose: list of BWS secret names")

        if has_compose:
            assert self.compose is not None
            n = len(self.compose)
            if n < _COMPOSE_MIN or n > _COMPOSE_MAX:
                raise ValueError(
                    f"compose must contain {_COMPOSE_MIN}-{_COMPOSE_MAX} secret names; got {n}"
                )
            # Reject duplicates rather than silently coalesce.
            seen: set[str] = set()
            duplicates: list[str] = []
            for name in self.compose:
                if not isinstance(name, str):
                    raise ValueError(f"compose entry {name!r} must be a string")
                if not name:
                    raise ValueError("compose entries must be non-empty strings")
                if name in seen:
                    duplicates.append(name)
                seen.add(name)
            if duplicates:
                raise ValueError(
                    f"compose secret names must be unique; got duplicates: "
                    f"{sorted(set(duplicates))}"
                )
            assert self.inject.template is not None
            try:
                self._compiled_template = KowTemplate(self.inject.template, self.compose)
            except UnsupportedTemplateError as e:
                raise ValueError(f"inject.template invalid: {e}") from None

        return self

    @property
    def compiled_template(self) -> KowTemplate | None:
        return self._compiled_template


class CacheSpec(BaseModel):
    model_config = _STRICT_MODEL

    ttl_seconds: int = Field(default=300, ge=10, le=3600)
    max_entries: int = Field(default=100, ge=1)
    jitter_seconds: int = Field(default=30, ge=0)


class AuditSpec(BaseModel):
    model_config = _STRICT_MODEL

    path: str
    fail_on_unwritable: bool = True


class PreflightSpec(BaseModel):
    """Startup security preflight (src/kow/_preflight.py).

    Default is advisory: warnings emit to stderr + logger but the proxy
    still starts. Set fail_on_warning to convert any warning into a
    startup abort — useful for hardened environments that want hard-fail
    over advisory output.
    """

    model_config = _STRICT_MODEL

    fail_on_warning: bool = False


class BackendBlock(BaseModel):
    """Backend selector. `type` is the discriminator; `config` is the
    per-backend pydantic model from BACKEND_REGISTRY[type]."""

    model_config = _STRICT_MODEL

    type: str
    config: dict

    # Populated by the after-validator below. Holds the per-backend pydantic
    # model instance so build_backend() doesn't re-validate. Not serialised.
    _validated_config: BaseModel | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_inner_config(self) -> BackendBlock:
        """Eagerly validate ``config`` against the per-backend pydantic model.

        A typo under ``backend.config`` (e.g., ``organization_iddd`` for
        ``organization_id``) would otherwise only surface at first secret
        fetch, when the addon calls ``build_backend()``. Validating at
        config-load makes ``kow bindings diff`` and ``--check`` honest about
        backend-block correctness instead of deferring it to runtime.
        """
        from kow.backends import BACKEND_REGISTRY, _normalize_name

        type_name = _normalize_name(self.type)
        if type_name not in BACKEND_REGISTRY:
            raise ValueError(
                f"unknown backend type {self.type!r}; "
                f"available types: {sorted(BACKEND_REGISTRY.keys())}"
            )
        _backend_cls, config_cls = BACKEND_REGISTRY[type_name]
        # Let pydantic's ValidationError surface as-is — it carries the
        # field-level detail (which key was unknown / what type was wrong).
        self._validated_config = config_cls.model_validate(self.config)
        return self


class CredentialEndpointSpec(BaseModel):
    """The ADC credential endpoint (ADR-0050): a loopback listener that answers
    the Compute Engine metadata protocol so ADC-based clients authenticate with
    no code change.

    It serves the referenced binding's PLACEHOLDER as the access token, never a
    real credential — the injector substitutes on egress. That is what makes an
    unauthenticated local listener acceptable; see the module docstring in
    ``kow/credential_endpoint.py``.
    """

    model_config = _STRICT_MODEL

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=14380, ge=0, le=65535)
    # The secret whose placeholder is dispensed. Its binding is what scopes the
    # authority the placeholder can reach.
    binding: str
    # Derived from the bound injector unless the operator states them; a stated
    # value that disagrees with the binding is a config error, not an override.
    # The endpoint advertising one identity while kow authenticates as another
    # is precisely the confusion this refuses to allow (Oracle review).
    service_account_email: str = ""
    project_id: str | None = None
    numeric_project_id: int = 0
    scopes: str = ""
    expires_in_seconds: int = Field(default=3600, ge=60, le=3600)
    # Populated at Config validation from ``binding`` — never operator-set, so
    # the endpoint and the binding cannot drift apart.
    placeholder: str = Field(default="", exclude=True)

    def scopes_list(self) -> list[str]:
        return self.scopes.split()

    @field_validator("host")
    @classmethod
    def require_loopback(cls, v: str) -> str:
        """A metadata endpoint on a routable address would hand placeholders to
        the LAN. There is no deployment where that is the intent."""
        if v not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(
                "credential_endpoint.host must be loopback (127.0.0.1 / ::1); "
                "the endpoint is reachable by every local process as it is"
            )
        return v


class ConfigError(Exception):
    """Raised at config-load time for structural errors that pydantic
    can't express."""


class Config(BaseModel):
    model_config = _STRICT_MODEL

    # Schema version. Optional, pinned to 1; reserved for future
    # schema-breaking changes.
    version: Literal[1] = 1
    secrets: dict[str, SecretSpec]
    # Default `forward_unmodified`: kow is a credential broker, not an
    # egress firewall. Operators opt into allow-listing with `deny`.
    unmatched_destination_policy: Literal["deny", "forward_unmodified"] = "forward_unmodified"
    # ADR-0026: which destinations kow TLS-terminates (MITM). `bound` (default):
    # terminate + inject ONLY for hosts the config binds; every other CONNECT is
    # an opaque TCP passthrough (no leaf cert, no decryption) — kow never holds
    # plaintext for traffic it does not broker, and a `tls_passthrough` audit
    # event records the tunneled destination for exfil visibility. `all`:
    # terminate every destination (pre-ADR-0026 behaviour; max observability).
    # Orthogonal to unmatched_destination_policy: `deny` still 403s an unbound
    # CONNECT before TLS; this only decides terminate-vs-tunnel for what is
    # allowed through.
    tls_termination: Literal["bound", "all"] = "bound"
    # ADR-0032: for a listable vault backend in notes/both mode, re-resolve the
    # binding policy from the vault this often (seconds), in the background, so a
    # NEW secret + note is brokered without a restart. 0 disables. Ignored in
    # file mode (nothing to refresh). Warm value/token caches survive a refresh;
    # only the binding snapshot is swapped.
    notes_refresh_seconds: int = Field(default=60, ge=0, le=86400)
    # Where binding policy comes from (ADR-0011, ADR-0018). Default `both`:
    # bindings resolve from the backend's per-secret metadata (BWS notes / GSM
    # `avp-binding` annotations) AND `secrets:` in this file, notes winning for
    # the same secret. `notes` = notes only; `file` = the pre-ADR-0011 file-only
    # behaviour. Anything other than `file` requires a listable backend
    # (bws/gsm/static). Legacy `bws_notes` / `gsm_notes` are accepted as
    # deprecated aliases for `notes` (normalized below); the per-spec audit
    # provenance stays backend-typed via NOTES_SOURCE_LABEL.
    binding_source: Literal["file", "notes", "both"] = "both"
    # Path to the per-install salt used to derive placeholders in notes/both
    # mode. Defaults to install-salt next to this file's directory; overridable
    # for non-systemd layouts. Ignored in file mode.
    install_salt_path: str | None = None
    # Wildcard binding hosts (`*.suffix`) are OFF by default. A wildcard widens
    # a credential's blast radius to every subdomain, so it must be a deliberate
    # opt-in: set `allow_wildcard_hosts: true` to permit `*.` hosts. Even when
    # enabled, public-suffix wildcards (`*.co.uk`, `*.com`) are still rejected
    # at the field level. When false (default), any `*.` host fails config-load.
    allow_wildcard_hosts: bool = False
    # File-side host allowlist for NOTES-sourced bindings (ADR-0024).
    # OPT-IN: when None (default, key absent), behavior is unchanged — the
    # zero-config notes flow (add secret + note/annotation, `host:` alone
    # suffices) is untouched. When set, a notes/annotation-supplied host
    # must match an entry (exact string, or a `*.suffix` entry under
    # `allow_wildcard_hosts`) or that binding entry is rejected fail-closed
    # with audit reason `host_not_in_allowlist`. Closes the GSM
    # confused-deputy: a principal holding `secretmanager.secrets.update`
    # but not `versions.access` can no longer ADD an egress host via the
    # `avp-binding` annotation — annotations can only NARROW scope. File
    # `secrets:` entries are the trusted tier and exempt. An explicit empty
    # list means "no notes host is approved" (notes fully fenced off).
    notes_host_allowlist: list[str] | None = None
    cache: CacheSpec = Field(default_factory=CacheSpec)
    audit: AuditSpec
    preflight: PreflightSpec = Field(default_factory=PreflightSpec)
    backend: BackendBlock | None = None
    # ADR-0050: opt-in ADC credential endpoint. A listener is not a request, so
    # it lives in its own top-level section rather than inside ``secrets:``.
    credential_endpoint: CredentialEndpointSpec | None = None
    # ADR-0053: opt-in ssh-agent signing oracle (experimental). Same
    # listener-not-a-request reasoning as credential_endpoint; SSH bindings
    # name backend secrets directly and never touch the ``secrets:`` map.
    ssh: SshSpec | None = None

    @model_validator(mode="after")
    def resolve_credential_endpoint_placeholder(self) -> Config:
        """Fail at load time if the endpoint cannot be bound. Re-run against the
        EFFECTIVE config after notes activation (see ``resolve_endpoint``) —
        notes can replace a SecretSpec wholesale, so validating only here would
        leave the endpoint serving a placeholder the live binding no longer
        recognises."""
        resolve_endpoint(self)
        return self

    @field_validator("binding_source", mode="before")
    @classmethod
    def _normalize_binding_source(cls, v: object) -> object:
        """Accept the legacy per-backend values ``bws_notes`` / ``gsm_notes`` as
        deprecated aliases for the generic ``notes`` mode — the activation
        mechanism is backend-agnostic; audit provenance stays backend-typed via
        NOTES_SOURCE_LABEL, not this config field."""
        if v in ("bws_notes", "gsm_notes"):
            import warnings

            warnings.warn(
                f"binding_source: {v!r} is a deprecated alias for 'notes'; "
                "update bindings.yaml to `binding_source: notes`.",
                DeprecationWarning,
                stacklevel=2,
            )
            return "notes"
        return v

    @model_validator(mode="before")
    @classmethod
    def normalize_and_validate_injector_types(cls, data: object) -> object:
        """Before the ``InjectorSpec`` union dispatch: (1) default-inject
        ``type: "header"`` so v0.4.x configs without a ``type:`` field still
        parse; (2) reject unknown / unimplemented types with a one-line
        error (instead of Pydantic's verbose ``union_tag_invalid`` dump).
        No-ops on non-dict input."""
        if not isinstance(data, dict):
            return data
        secrets = data.get("secrets")
        if not isinstance(secrets, dict):
            return data

        # Shallow-copy only if some inject block actually needs a default.
        needs_default_injection = any(
            isinstance(spec, dict)
            and isinstance(spec.get("inject"), dict)
            and "type" not in spec["inject"]
            for spec in secrets.values()
        )

        if needs_default_injection:
            new_secrets: dict[str, object] = {}
            for name, spec in secrets.items():
                if isinstance(spec, dict):
                    inject = spec.get("inject")
                    if isinstance(inject, dict) and "type" not in inject:
                        new_secrets[name] = {**spec, "inject": {**inject, "type": "header"}}
                        continue
                new_secrets[name] = spec
            data = {**data, "secrets": new_secrets}
            secrets = new_secrets

        for name, spec in secrets.items():
            if not isinstance(spec, dict):
                continue
            inject = spec.get("inject")
            if isinstance(inject, dict):
                _validate_inject_block(name, inject)
        return data

    @model_validator(mode="after")
    def validate_placeholders(self) -> Config:
        validate_placeholder_invariants(
            {name: spec.placeholder for name, spec in self.secrets.items()}
        )
        return self

    @model_validator(mode="after")
    def validate_format_placeholders(self) -> Config:
        """Every leaf ``inject.format`` must contain ``{<entry_name>}``
        matching the parent secret's YAML key. Catches typos and the
        legacy ``{secret}`` alias."""
        for name, spec in self.secrets.items():
            for child in iter_leaf_injectors(spec.inject):
                # oauth2_refresh substitutes the exchanged access token
                # under the literal `{access_token}` placeholder — never
                # the vault-secret name. sigv4 computes the value (a request
                # signature) and has no `format` at all. Both plant the
                # secret's placeholder in the target header purely as the
                # detection trigger; skip the YAML-key format match here.
                if isinstance(
                    child,
                    Oauth2RefreshInjector
                    | Sigv4Injector
                    | HmacInjector
                    | JwtBearerInjector
                    | Oauth2ClientCredentialsInjector
                    | GithubAppInjector
                    | GcpServiceAccountInjector,
                ):
                    continue
                fmt = child.format
                if fmt is None:
                    continue
                named = "{" + name + "}"
                if named not in fmt:
                    raise ValueError(
                        f"secret {name!r}: inject.format must contain "
                        f"'{named}' as the substitution placeholder; got {fmt!r}"
                    )
        return self

    @model_validator(mode="after")
    def reject_body_signer_body_injector_host_conflict(self) -> Config:
        """ADR-0027/0028: a body-hashing signer (sigv4, or hmac with a
        ``{body_sha256}`` template) reads the intact request body, but the body
        injector STREAMS and mutates it. A host bound to both would sign wrong
        or absent bytes. Reject at load — loudly, not as a silent signing
        failure at request time. (jwt_bearer does not read the body, so it is
        exempt. Exact-host check; a wildcard overlap is an accepted gap.)"""
        signer_hosts: set[str] = set()
        body_hosts: set[str] = set()
        for spec in self.secrets.values():
            leaves = iter_leaf_injectors(spec.inject)
            has_body_signer = any(
                isinstance(child, Sigv4Injector | HmacInjector) for child in leaves
            )
            has_body = any(isinstance(child, BodyInjector) for child in leaves)
            for binding in spec.bindings:
                if has_body_signer:
                    signer_hosts.add(binding.host)
                if has_body:
                    body_hosts.add(binding.host)
        clash = signer_hosts & body_hosts
        if clash:
            raise ValueError(
                f"sigv4/hmac signing and body injection bind the same host(s) {sorted(clash)}; "
                "the signer hashes the whole request body but body injection "
                "streams and mutates it. Bind them to different hosts."
            )
        return self

    # Host-keyed indices: exact-host dict + linear wildcard list.
    _exact_host_index: dict[str, list[tuple[str, SecretSpec]]] = PrivateAttr(default_factory=dict)
    _wildcard_host_entries: list[tuple[str, str, SecretSpec]] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def build_host_index(self) -> Config:
        """Populate the host-keyed indices used by ``secrets_for_host``.
        O(total bindings) at load; O(1) exact + O(wildcards) per request.
        Body and Aho-Corasick injectors need the narrowing so the body
        scan stays bounded.
        """
        self.rebuild_host_index()
        return self

    def rebuild_host_index(self) -> None:
        """(Re)build the host-keyed indices from the current ``secrets`` map.

        Idempotent: clears then repopulates, so it is safe to call again
        after ``secrets`` is mutated at runtime (the BWS-notes activation
        merges resolved specs into ``secrets`` at configure() time and must
        rebuild the index for the merged set). Separate from the load-time
        ``build_host_index`` validator because pydantic wraps validators in a
        descriptor that isn't directly callable post-construction.
        """
        self._exact_host_index = {}
        self._wildcard_host_entries = []
        for name, spec in self.secrets.items():
            for binding in spec.bindings:
                if binding.host.startswith("*."):
                    self._wildcard_host_entries.append((binding.host, name, spec))
                else:
                    self._exact_host_index.setdefault(binding.host, []).append((name, spec))

    def secrets_for_host(self, host: str) -> list[tuple[str, SecretSpec]]:
        """``(secret_name, spec)`` pairs whose bindings include ``host``.
        Exact matches first, then ``*.suffix`` wildcards. Each secret
        appears at most once; config-load order preserved within each class.
        """
        host = host.lower()
        seen_names: set[str] = set()
        result: list[tuple[str, SecretSpec]] = []
        for name, spec in self._exact_host_index.get(host, ()):
            if name not in seen_names:
                seen_names.add(name)
                result.append((name, spec))
        for pattern, name, spec in self._wildcard_host_entries:
            if name in seen_names:
                continue
            if host_matches_pattern(host, pattern):
                seen_names.add(name)
                result.append((name, spec))
        return result

    @model_validator(mode="after")
    def enforce_wildcard_opt_in(self) -> Config:
        """Wildcard hosts (`*.suffix`) are a deliberate opt-in. Unless
        ``allow_wildcard_hosts: true`` is set, any binding with a `*.` host
        fails config-load — a wildcard silently widens a credential's blast
        radius to every subdomain, so it should never be reachable by accident
        or by a config paste. Public-suffix / malformed wildcards are already
        rejected at the field level; this gates *all* wildcards behind the
        explicit flag."""
        if self.allow_wildcard_hosts:
            return self
        offenders = [
            (name, b.host)
            for name, spec in self.secrets.items()
            for b in spec.bindings
            if b.host.startswith("*.")
        ]
        if offenders:
            shown = ", ".join(f"{n} -> {h}" for n, h in offenders[:5])
            raise ValueError(
                f"wildcard host(s) present but disabled: {shown}. Wildcards widen a "
                "secret's blast radius to every subdomain; set `allow_wildcard_hosts: true` "
                "at the top level to permit them, or bind to exact hosts."
            )
        return self

    @field_validator("notes_host_allowlist")
    @classmethod
    def _validate_notes_host_allowlist_entries(cls, v: list[str] | None) -> list[str] | None:
        """ADR-0024: allowlist entries are bare hostnames (optionally a
        one-label `*.suffix` wildcard, gated by ``allow_wildcard_hosts``
        in the model validator below). No scheme, port, path, bare `*`,
        or whitespace — the same shape binding hosts take.

        Entries are lowercased to match the host invariant everywhere else:
        notes hosts are lowercased when parsed and binding hosts at load
        (`normalize_and_validate_host`), and request-time matching is
        case-insensitive. Without this, a mixed-case allowlist entry (e.g.
        ``API.Corp.Internal``) would never equal the lowercased note host in
        the exact-match membership check, silently rejecting every legitimate
        notes binding with `host_not_in_allowlist` (fail-closed, but it
        breaks the control the operator just enabled)."""
        if v is None:
            return v
        for entry in v:
            if not isinstance(entry, str) or not entry or entry != entry.strip():
                raise ValueError(
                    f"notes_host_allowlist: invalid entry {entry!r} — bare hostnames only"
                )
            if entry == "*" or any(c in entry for c in "/: "):
                raise ValueError(
                    f"notes_host_allowlist: invalid entry {entry!r} — bare hostnames only "
                    "(no scheme, port, path, or bare '*')"
                )
        return [entry.lower() for entry in v]

    @model_validator(mode="after")
    def _allowlist_wildcards_require_opt_in(self) -> Config:
        """ADR-0024 + the wildcard opt-in: a `*.suffix` ALLOWLIST entry
        widens what notes may bind just like a wildcard binding host
        does, so it rides the same explicit flag."""
        if self.notes_host_allowlist and not self.allow_wildcard_hosts:
            wild = sorted(e for e in self.notes_host_allowlist if e.startswith("*."))
            if wild:
                raise ValueError(
                    f"notes_host_allowlist entries {wild} use wildcards but "
                    "allow_wildcard_hosts is false — enable the opt-in or list exact hosts."
                )
        return self

    @model_validator(mode="after")
    def reject_nested_composition(self) -> Config:
        """``compose:`` entries must point at leaf BWS secret names, never
        at another binding that itself has ``compose:`` set. Leaf-check
        only — same name may legitimately be both a standalone binding
        AND a compose entry."""
        for binding_name, spec in self.secrets.items():
            if spec.compose is None:
                continue
            for entry in spec.compose:
                referenced = self.secrets.get(entry)
                if referenced is not None and referenced.compose is not None:
                    raise ValueError(
                        f"binding {binding_name!r}: compose entry {entry!r} "
                        "is itself a composite binding; point compose at "
                        "leaf BWS secret names only."
                    )
        return self


# Back-compat alias for v0.4.x importers. Removed in v0.6.0.
InjectSpec = HeaderInjector


def resolve_endpoint(config: Config) -> CredentialEndpointSpec | None:
    """Bind the credential endpoint to the EFFECTIVE spec of its secret.

    Called twice by design: once at config validation (so a broken setup fails at
    load) and once by the addon after notes activation has merged vault-side
    bindings in, because that merge can replace the SecretSpec the endpoint was
    validated against.

    Derives the placeholder, service-account email and scopes from the binding
    itself. An endpoint advertising one identity while the injector authenticates
    as another is not a supported configuration, it is a way to be wrong quietly.
    """
    from kow.config_models import GcpServiceAccountInjector

    ep = config.credential_endpoint
    if ep is None or not ep.enabled:
        return None
    spec = config.secrets.get(ep.binding)
    if spec is None:
        raise ValueError(
            f"credential_endpoint.binding {ep.binding!r} is not a secret in this config"
        )
    if not isinstance(spec.inject, GcpServiceAccountInjector):
        raise ValueError(
            f"credential_endpoint.binding {ep.binding!r} is not a gcp_service_account "
            "binding; the endpoint can only front a binding that mints a Google "
            "credential for a bearer Authorization header"
        )
    if not spec.placeholder:
        raise ValueError(
            f"credential_endpoint.binding {ep.binding!r} has no literal placeholder; "
            "the endpoint needs one to serve"
        )
    injector_email = spec.inject.service_account_email
    if ep.service_account_email and ep.service_account_email != injector_email:
        raise ValueError(
            "credential_endpoint.service_account_email "
            f"({ep.service_account_email!r}) disagrees with the binding's "
            f"({injector_email!r}); the endpoint would advertise an identity kow "
            "does not authenticate as"
        )
    injector_scopes = spec.inject.scopes or ""
    if ep.scopes and injector_scopes and ep.scopes != injector_scopes:
        raise ValueError(
            "credential_endpoint.scopes disagrees with the binding's scopes; "
            "clients would be told they hold access the minted token does not carry"
        )
    object.__setattr__(ep, "placeholder", spec.placeholder)
    object.__setattr__(ep, "service_account_email", injector_email)
    object.__setattr__(ep, "scopes", ep.scopes or injector_scopes)
    return ep


def load_config(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return Config.model_validate(raw)


def build_backend(config: Config):
    """Instantiate the configured backend.

    Returns (backend_instance, backend_config_instance). Caller is
    responsible for wrapping the backend in CachingSecretsClient.
    """
    from kow.backends import BACKEND_REGISTRY, _normalize_name

    if config.backend is None:
        raise ConfigError(
            "no backend configured. Add a `backend: {type: ..., config: {...}}` "
            "block to bindings.yaml. Available types: "
            f"{sorted(BACKEND_REGISTRY.keys())}"
        )
    # Use the same NFKC+casefold normalization as register_backend so the
    # operator can't sneak past the dedup check via compat variants.
    type_name = _normalize_name(config.backend.type)
    if type_name not in BACKEND_REGISTRY:
        raise ConfigError(
            f"unknown backend type '{config.backend.type}'. "
            f"Available types: {sorted(BACKEND_REGISTRY.keys())}"
        )
    backend_cls, config_cls = BACKEND_REGISTRY[type_name]
    # BackendBlock's after-validator already validated this at config-load;
    # reuse the result so we don't double-validate (and so the model_validate
    # call here can't surface a different error than load_config did).
    backend_config = config.backend._validated_config
    if backend_config is None:  # pragma: no cover — defensive
        backend_config = config_cls.model_validate(config.backend.config)
    # SecretsBackend is a Protocol — it cannot statically express that every
    # concrete backend's __init__ takes a `config=` kwarg. The registry is
    # what enforces the convention at runtime (see backends/__init__.py
    # register_backend signature check).
    backend_instance = backend_cls(config=backend_config)  # type: ignore[call-arg]
    return backend_instance, backend_config
