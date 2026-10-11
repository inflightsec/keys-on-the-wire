from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    ValidationInfo,
    field_validator,
    model_validator,
)

from kow._textguard import assert_no_forbidden_chars
from kow.oauth_providers import PROVIDER_PRESETS, ProviderName

# RFC 7230 §3.2.6 token — the only characters legal in an HTTP field name.
_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _reject_url_credentials(url: object, field: str) -> None:
    """Reject an operator egress URL that embeds userinfo (``user:pass@host``).

    ADR-0035: a credential proxy has no business carrying secrets in a
    ``token_url`` / ``api_base_url``, and the userinfo is silently dropped by
    the HTTP transport today. Rejecting it at config-load turns a silent
    misconfiguration into a loud one. Applied to every operator-controlled
    token-egress URL (the three token-minting injectors)."""
    parsed = urlparse(str(url))
    if parsed.username or parsed.password:
        raise ValueError(
            f"{field} must not embed credentials (user:pass@host); the "
            "userinfo is silently dropped on the wire. Put the credential "
            "in a vault secret, not the URL."
        )


# Known injector types — closed enumeration. Maps each type name to the
# phase that ships it; entries whose value starts with "planned:" are in
# the v0.5.0 taxonomy but raise a "not yet implemented" error at config
# load until their phase lands. Single source of truth: adding a new
# type means one line here plus the matching class + InjectorSpec union
# extension, never a parallel edit to two tuples.
_INJECTOR_TYPES: dict[str, str] = {
    "header": "P0",
    "body": "P0.6",
    "multi": "P0.7",
    "oauth2_refresh": "P1",
    "github_app": "P1",
    "sigv4": "P2",
    "oauth2_client_credentials": "P2",
    "jwt_bearer": "P2",
    "hmac": "P4",
    "gcp_service_account": "P5",
}


def _validate_inject_block(name: str, inject: dict) -> None:
    """Validate the ``type`` field of one ``inject:`` block (and, for
    ``multi``, of each declared child). Raises ``ValueError`` with an
    operator-friendly message on unknown / unimplemented / malformed
    types. ``name`` is the parent secret's YAML key, interpolated into
    error messages so operators can locate the entry.

    Pre-condition: ``inject["type"]`` is set (the default-injection
    pass upstream guarantees this for v0.4.x-shape inputs).
    """
    t = inject.get("type")
    if t is None:
        return  # already defaulted upstream; defensive
    _check_injector_type(t, type_path=f"secret {name!r}: inject.type")
    if t != "multi":
        return
    children = inject.get("injectors")
    if not isinstance(children, list):
        return  # let standard validator raise (wrong shape)
    for i, child in enumerate(children):
        if not isinstance(child, dict):
            continue
        ct = child.get("type")
        if ct is None:
            # Multi is v0.5.0 P0.7 — no backward-compat reason to default
            # child types. Be explicit to avoid ambiguity ("which leaf
            # did the operator mean?") and keep errors tight.
            raise ValueError(
                f"secret {name!r}: inject.injectors[{i}] is missing the "
                "required ``type:`` field. Multi injector children must "
                "specify their leaf type explicitly; valid leaf types in "
                "v0.5.0: 'header', 'body'."
            )
        _check_injector_type(ct, type_path=f"secret {name!r}: inject.injectors[{i}].type")
        # ``multi`` inside ``multi`` is rejected at the MultiInjector
        # schema level (LeafInjectorSpec excludes "multi"), but catch
        # it here too with a tighter message — same operator-facing UX
        # as the other type checks.
        if ct == "multi":
            raise ValueError(
                f"secret {name!r}: inject.injectors[{i}].type is 'multi'; "
                "nested multi-injectors are not supported (use a single "
                "multi with all leaf children flat)."
            )


def _check_injector_type(t: object, *, type_path: str) -> None:
    """Validate a single ``inject.type`` value against the closed taxonomy.

    Raises ``ValueError`` with an operator-friendly message on:

    * type not a string / not in :data:`_INJECTOR_TYPES`
      ("unknown type"; lists every valid alternative)
    * type known but not yet implemented in this version
      ("planned for phase X"; points at the CHANGELOG)

    ``type_path`` is the dotted location of the offending ``type`` field —
    e.g. ``"secret 'FOO': inject.type"`` or
    ``"secret 'FOO': inject.injectors[2].type"``. Interpolated verbatim so
    the operator can locate the entry without guesswork.
    """
    if not isinstance(t, str) or t not in _INJECTOR_TYPES:
        raise ValueError(f"{type_path} {t!r} is unknown; valid types: {sorted(_INJECTOR_TYPES)}")
    phase = _INJECTOR_TYPES[t]
    if phase.startswith("planned:"):
        implemented = sorted(k for k, v in _INJECTOR_TYPES.items() if not v.startswith("planned:"))
        raise ValueError(
            f"{type_path} {t!r} is in the planned v0.5.0 taxonomy ({phase}) but "
            "not yet implemented in this version. Currently implemented: "
            f"{implemented}. See CHANGELOG.md for the per-phase ship order."
        )


# `extra="forbid"` everywhere: a `method:` typo for `methods:` would
# otherwise silently produce an unscoped binding.
_STRICT_MODEL = ConfigDict(extra="forbid")

# Placeholders must be ≥24 chars, contain the marker, be unique, and not
# substring-overlap (addon detects via `in` matching).
_PLACEHOLDER_MIN_LEN = 24
_PLACEHOLDER_MARKER = "PLACEHOLDER"

# Permissive at the injector layer; the strict name-match runs at Config
# level in `validate_format_placeholders`.
_FORMAT_PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")


def validate_placeholder_invariants(placeholders: dict[str, str]) -> None:
    """Assert the placeholder invariants over a ``{secret_name: placeholder}``
    map: each is non-empty, >= the min length, contains the PLACEHOLDER
    marker, printable, unique, and no placeholder is a substring of another
    (the addon's ``in`` matching would otherwise pick the wrong secret).

    Raised as ``ValueError`` so it surfaces identically whether invoked by
    the Config load-time validator or by the daemon's BWS-notes activation
    (which merges file + derived placeholders into one set that must ALSO
    satisfy these invariants — a derived placeholder colliding/overlapping
    with a file one is a hard, fail-closed startup error).
    """
    seen: dict[str, str] = {}
    for name, ph in placeholders.items():
        if not ph:
            raise ValueError(f"secret {name!r}: placeholder is empty")
        if len(ph) < _PLACEHOLDER_MIN_LEN:
            raise ValueError(
                f"secret {name!r}: placeholder must be at least "
                f"{_PLACEHOLDER_MIN_LEN} characters (got {len(ph)})"
            )
        if _PLACEHOLDER_MARKER not in ph:
            raise ValueError(
                f"secret {name!r}: placeholder must contain the "
                f"literal marker {_PLACEHOLDER_MARKER!r}"
            )
        if not ph.isprintable():
            raise ValueError(f"secret {name!r}: placeholder must be printable")
        if ph in seen:
            raise ValueError(f"secret {name!r}: placeholder is identical to secret {seen[ph]!r}")
        seen[ph] = name
    # Pairwise substring check — a placeholder that's a substring of another
    # would let the addon's `in` matching pick the wrong secret.
    for ph_a, name_a in seen.items():
        for ph_b, name_b in seen.items():
            if name_a != name_b and ph_a in ph_b:
                raise ValueError(
                    f"secret {name_a!r}: placeholder is a substring "
                    f"of secret {name_b!r}'s placeholder"
                )


def _assert_format_has_placeholder(format_str: str, *, context_label: str) -> None:
    """Require ``format_str`` to contain some ``{NAME}``-shaped placeholder."""
    if not _FORMAT_PLACEHOLDER_RE.search(format_str):
        raise ValueError(
            f"{context_label} must contain a `{{<SECRET_NAME>}}` "
            "placeholder for the value to substitute"
        )


def _render_substitution(format_str: str, *, real_secret: str, secret_name: str) -> str:
    """Substitute ``{<secret_name>}`` -> ``real_secret``. Uses ``str.replace``
    (not ``str.format``) so an operator-provided format can't traverse
    attributes via Python's format-mini-language."""
    return format_str.replace("{" + secret_name + "}", real_secret)


class HeaderInjector(BaseModel):
    """Header-injection rule. Exactly one of ``format`` (literal substitution)
    or ``template`` (Jinja2-sandboxed, requires ``compose:`` on the parent)
    must be set."""

    model_config = _STRICT_MODEL

    type: Literal["header"] = "header"
    header: str
    format: str | None = None
    template: str | None = None

    @field_validator("header", "format", "template")
    @classmethod
    def reject_control_characters(cls, v: str | None, info: ValidationInfo) -> str | None:
        """``header`` and ``format`` are settable from vault notes by a
        lower-trust author (ADR-0024), and both become HTTP header bytes. A
        break character here splits the field — or, in the flat-YAML note
        grammar, injects a second key. ``kow mcp`` refuses this class when
        writing a note; refuse it here too, where notes written by any other
        vault client arrive. Raising ValueError keeps a poisoned note
        per-secret fail-closed (notes_binding catches ValidationError and
        yields InvalidBinding) rather than failing the whole config.
        """
        if v is not None:
            assert_no_forbidden_chars(v, label=f"inject.{info.field_name}")
        # The category guard above refuses break characters everywhere, but
        # ':' and ' ' are ordinary punctuation to it. For the header NAME
        # specifically, enforce RFC 7230 token grammar: a colon in the name
        # relocates everything after it into the VALUE on the receiving end,
        # and a space makes the field unparseable. No new authority is at
        # stake — the note author chooses the name freely — this is shape
        # correctness, fail-closed per-secret. (Oracle review, 2026-10-11.)
        if v is not None and info.field_name == "header" and not _HTTP_TOKEN_RE.match(v):
            raise ValueError(
                f"inject.header {v!r} is not a valid HTTP field name "
                "(RFC 7230 token: letters, digits, and !#$%&'*+-.^_`|~)"
            )
        return v

    def render_value(self, *, real_secret: str, secret_name: str) -> str:
        """Substituted header value for a single-secret binding. Composite
        bindings go through ``SecretSpec.compiled_template``."""
        assert self.format is not None, (
            "render_value() expects inject.format; use compiled_template for composite bindings"
        )
        return _render_substitution(
            self.format,
            real_secret=real_secret,
            secret_name=secret_name,
        )

    @model_validator(mode="after")
    def exactly_one_of_format_or_template(self) -> HeaderInjector:
        has_format = self.format is not None
        has_template = self.template is not None
        if has_format and has_template:
            raise ValueError(
                "inject.format and inject.template are mutually exclusive; "
                "use format for literal substitution or template for Jinja2-syntax assembly"
            )
        if not has_format and not has_template:
            raise ValueError("inject requires either 'format' or 'template'")
        if has_format:
            assert self.format is not None
            _assert_format_has_placeholder(self.format, context_label="inject.format")
        return self


class BodyInjector(BaseModel):
    """Body-injection rule. The secret's ``placeholder`` (inherited from the
    parent :class:`SecretSpec`) is substituted in the request body via
    streaming replacement (constant memory, chunked transfer).

    ``format`` / ``template`` semantics mirror :class:`HeaderInjector` —
    the result is the bytes each placeholder occurrence gets replaced WITH.
    Single-secret bindings use ``format`` (literal ``{<SECRET_NAME>}``
    substitution); composite bindings use ``template`` (sandboxed Jinja2)
    together with ``compose:`` on the parent ``SecretSpec``. The render
    path is identical to headers — only the substitution target differs.

    ``content_type`` (optional): when set, the request's Content-Type must
    match (parameters stripped, case-insensitive) or the body forwards
    unmodified. Default None = any content-type eligible.
    """

    model_config = _STRICT_MODEL

    type: Literal["body"] = "body"
    content_type: str | None = None
    format: str | None = None
    template: str | None = None

    def render_value(self, *, real_secret: str, secret_name: str) -> str:
        """Bytes each in-body placeholder occurrence is replaced with (single-
        secret path only). Composite body bindings go through
        ``SecretSpec.compiled_template`` — same as composite header bindings."""
        assert self.format is not None, (
            "render_value() expects inject.format; use compiled_template for composite bindings"
        )
        return _render_substitution(
            self.format,
            real_secret=real_secret,
            secret_name=secret_name,
        )

    @model_validator(mode="after")
    def exactly_one_of_format_or_template(self) -> BodyInjector:
        has_format = self.format is not None
        has_template = self.template is not None
        if has_format and has_template:
            raise ValueError("body inject.format and inject.template are mutually exclusive")
        if not has_format and not has_template:
            raise ValueError("body inject requires either 'format' or 'template'")
        if has_format:
            assert self.format is not None
            _assert_format_has_placeholder(self.format, context_label="body inject.format")
        return self

    @field_validator("content_type")
    @classmethod
    def normalize_content_type(cls, v: str | None) -> str | None:
        # Normalise at config-load so the runtime gate is a single
        # case-insensitive compare against the wire's Content-Type.
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            raise ValueError("content_type must be a non-empty string, or omit the field")
        if ";" in v:
            raise ValueError(
                f"content_type {v!r} contains parameters; specify only the media-type "
                "(e.g. 'application/json')."
            )
        if "/" not in v:
            raise ValueError(
                f"content_type {v!r} is not a media-type (expected 'type/subtype' form)"
            )
        return v


class Oauth2RefreshInjector(BaseModel):
    """OAuth2 refresh-token grant (RFC 6749 §6) — exchanges a vault-held
    refresh token for a short-lived access token at request time and
    injects the result.

    The schema captures the planning surface (ADR-0017 §2); runtime
    resolution (cache, off-thread exchange, audit emission, write-back)
    lands in subsequent slices and lives in
    :mod:`kow.injectors.oauth2_refresh`.

    Either ``provider:`` is set — the bundled preset supplies
    ``token_url`` and ``client_auth_method`` — or both fields are
    declared explicitly. XOR validated at load time so the operator
    intent is unambiguous.
    """

    model_config = _STRICT_MODEL

    type: Literal["oauth2_refresh"] = "oauth2_refresh"

    # Either preset, or explicit fields, never both. Tenant-specific
    # presets (auth0, okta) supply auth_method but require an explicit
    # token_url — handled in the model_validator.
    provider: ProviderName | None = None
    token_url: HttpUrl | None = None
    client_auth_method: Literal["body_post", "basic"] | None = None

    # BWS secret references — always required regardless of preset usage.
    # The preset supplies URLs, not credentials.
    client_id_secret: str
    client_secret_secret: str
    refresh_token_secret: str

    # Target — header only in v0.7 (ADR-0017 §1). Body target lands in a
    # separate ADR with content-type-aware escaping.
    header: str = "Authorization"
    format: str = "Bearer {access_token}"

    # Optional scope override on refresh — RFC 6749 §6 allows narrowing
    # (not widening) the scopes against the refresh token's mint.
    scopes: str | None = None

    # Cache control — per-binding overrides on the derived-token cache
    # (ADR-0017 §3). ``safety`` is subtracted from upstream ``expires_in``;
    # ``max`` is the absolute ceiling regardless of upstream lifetime.
    cache_ttl_safety_seconds: int = Field(default=60, ge=0, le=600)
    cache_ttl_max_seconds: int = Field(default=3600, ge=60, le=86400)

    # Write-back on rotation — ADR-0017 §8. True (default) extends
    # ``SecretsBackend`` with ``update()``; backends that don't implement
    # it audit ``refresh_token_rotated:write_back_unavailable`` and the
    # operator must rotate manually.
    refresh_token_write_back: bool = True

    # Per-binding floor between write-back PUTs (ADR-0017 hardening
    # series — bounds vault write pressure when a hostile or broken
    # upstream forces a rotation on every exchange). ``0`` disables.
    # A rate-limited rotation is NOT persisted (audit outcome
    # ``write_back_rate_limited``); the next exchange uses the vault's
    # previous token and surfaces ``invalid_grant`` if the upstream
    # really revoked it — the audit trail is the operator's cue.
    write_back_min_interval_seconds: int = Field(default=60, ge=0, le=3600)

    def render_value(self, *, access_token: str) -> str:
        """Substitute ``{access_token}`` in :attr:`format` with the
        exchanged token. Mirrors :meth:`HeaderInjector.render_value`'s
        ``str.replace``-not-``str.format`` posture so an operator-
        controlled format cannot traverse attributes via Python's
        format-mini-language. The placeholder name is literal — the
        XOR/schema layer pinned the format default to ``Bearer
        {access_token}`` and any operator override is still constrained
        to that single placeholder name."""
        return self.format.replace("{access_token}", access_token)

    @model_validator(mode="after")
    def resolve_preset_xor(self) -> Oauth2RefreshInjector:
        """Enforce the preset/explicit semantics and apply the preset.

        Three valid shapes; everything else is rejected at load:

        - **Non-tenant preset only** (``provider: google|microsoft|
          slack|atlassian``): the catalog supplies BOTH ``token_url``
          and ``client_auth_method``. Operator MUST NOT supply either
          field — silent override of vetted defaults is a surprise.
        - **Tenant-specific preset + URL** (``provider: auth0|okta``,
          + explicit ``token_url``): tenant URL is operator-supplied;
          the preset supplies ``client_auth_method`` only. Operator
          MUST supply ``token_url``, MUST NOT override the auth
          method.
        - **Fully explicit** (no ``provider:``): operator supplies
          both ``token_url`` and ``client_auth_method``.

        After this runs, ``token_url`` and ``client_auth_method`` are
        populated regardless of which path the operator chose — so the
        runtime never needs to consult ``PROVIDER_PRESETS`` again.
        SSRF check runs on every operator-supplied URL (both the
        fully-explicit and the tenant-explicit paths)."""
        from kow._ssrf_guard import check_url_not_internal

        has_provider = self.provider is not None
        has_explicit_url = self.token_url is not None
        has_explicit_method = self.client_auth_method is not None

        if has_provider:
            preset = PROVIDER_PRESETS[self.provider]  # type: ignore[index]

            if has_explicit_method:
                raise ValueError(
                    f"oauth2_refresh: provider {self.provider!r} supplies "
                    "client_auth_method from the bundled preset; remove the "
                    "explicit value. Override is rejected to keep the schema "
                    "intent unambiguous."
                )

            if preset.token_url is None:
                # Tenant-specific: operator MUST supply token_url, preset
                # contributes auth method only.
                if not has_explicit_url:
                    raise ValueError(
                        f"oauth2_refresh: provider {self.provider!r} is tenant-"
                        "specific; supply token_url explicitly (e.g. "
                        "https://<tenant>.auth0.com/oauth/token). The preset "
                        "only contributes the auth method."
                    )
                # Operator-supplied URL → must pass SSRF guard.
                assert self.token_url is not None
                check_url_not_internal(self.token_url)
                object.__setattr__(self, "client_auth_method", preset.client_auth_method)
                return self

            # Non-tenant preset: catalog supplies everything; operator
            # must not duplicate.
            if has_explicit_url:
                raise ValueError(
                    f"oauth2_refresh: provider {self.provider!r} supplies "
                    "token_url from the bundled preset; remove the explicit "
                    "value (the preset URL was vetted at PR review)."
                )
            object.__setattr__(self, "token_url", HttpUrl(preset.token_url))
            object.__setattr__(self, "client_auth_method", preset.client_auth_method)
            return self

        # No provider — both explicit fields required.
        if not has_explicit_url:
            raise ValueError(
                "oauth2_refresh: either set provider: <name> for a bundled "
                "preset, or supply token_url explicitly. Neither was given."
            )
        if not has_explicit_method:
            raise ValueError(
                "oauth2_refresh: when token_url is supplied explicitly, "
                "client_auth_method ('body_post' or 'basic') is also "
                "required. RFC 6749 §2.3 — provider preference matters."
            )
        assert self.token_url is not None
        check_url_not_internal(self.token_url)
        return self

    @field_validator("token_url")
    @classmethod
    def require_https(cls, v: HttpUrl | None) -> HttpUrl | None:
        """HTTPS-only. A cleartext token endpoint would expose the
        refresh token on the very first exchange."""
        if v is None:
            return None
        if v.scheme != "https":
            raise ValueError(
                f"oauth2_refresh.token_url must use the https scheme; "
                f"got {v.scheme!r}. RFC 6749 §3.1 — token endpoint MUST "
                "use TLS."
            )
        _reject_url_credentials(v, "oauth2_refresh.token_url")
        return v


class Sigv4Injector(BaseModel):
    """AWS Signature Version 4 request signing (``AWS4-HMAC-SHA256``).

    Computes the request signature over the method, canonical URI + query, the
    signed header set, and a SHA-256 of the request body, then sets the
    ``Authorization`` + ``x-amz-date`` headers (and ``x-amz-security-token`` for
    temporary credentials). Unlike the substitution injectors it renders no
    value — the operator plants the secret's ``placeholder`` in the target
    header purely as the DETECTION trigger; the real signing material is the
    named credential secrets below (resolved to values at request time, like
    ``oauth2_refresh``'s named-secret fields). Signing lives in
    :mod:`kow.injectors.sigv4`; because the body must be hashed,
    the request path buffers it and signs in the addon ``request`` hook.
    """

    model_config = _STRICT_MODEL

    type: Literal["sigv4"] = "sigv4"

    # AWS credential-scope inputs. ``service`` is the AWS service code
    # ("s3", "execute-api", "sts", ...); ``region`` the AWS region.
    region: str
    service: str

    # Vault secret references — the AWS access-key id + secret access key, and
    # (for temporary/STS credentials) an optional session token. The preset
    # supplies nothing here; credentials always come from the vault.
    access_key_id_secret: str
    secret_access_key_secret: str
    session_token_secret: str | None = None

    # The header the computed signature is written to. AWS SigV4 always uses
    # Authorization; exposed for symmetry only — there is no ``format`` because
    # the value is computed, not substituted.
    header: str = "Authorization"

    @model_validator(mode="after")
    def require_non_empty_scope(self) -> Sigv4Injector:
        for field in ("region", "service"):
            value = getattr(self, field).strip()
            if not value:
                raise ValueError(f"sigv4.{field} is required and cannot be empty")
            setattr(self, field, value)
        return self


class HmacInjector(BaseModel):
    """Generic HMAC request signing (RFC 2104).

    Signs an operator-declared ``signing_string`` built from request parts
    (tokens ``{method}`` ``{path}`` ``{query}`` ``{host}`` ``{body_sha256}``
    ``{timestamp}``) with ``HMAC-<algorithm>`` and writes the ``hex``/``base64``
    digest to ``header``. The vault-held HMAC key is ``secret_key_secret``. HMAC
    schemes are service-specific in *what* they sign, so the operator supplies
    the template; the signer does no further canonicalisation. Signing lives in
    :mod:`kow.injectors.hmac_signer`; a ``{body_sha256}`` template
    needs the request body, so it signs in the addon ``request`` hook.
    """

    model_config = _STRICT_MODEL

    type: Literal["hmac"] = "hmac"
    secret_key_secret: str
    signing_string: str
    header: str
    algorithm: Literal["sha1", "sha256", "sha384", "sha512"] = "sha256"
    encoding: Literal["hex", "base64"] = "hex"
    # When set, the unix timestamp substituted for {timestamp} is also emitted
    # here so the server can bound request age.
    timestamp_header: str | None = None

    @model_validator(mode="after")
    def require_header_and_signing_string(self) -> HmacInjector:
        if not self.header.strip():
            raise ValueError("hmac.header is required and cannot be empty")
        if not self.signing_string:
            raise ValueError("hmac.signing_string is required")
        return self


class JwtBearerInjector(BaseModel):
    """Mint a signed JWT (RFC 7519 structure, RFC 7515 JWS) and inject it as a
    bearer credential.

    Signs the operator-declared claims — ``issuer`` (iss), ``subject`` (sub),
    ``audience`` (aud), ``iat``/``exp`` stamped from ``ttl_seconds`` at request
    time, and any ``extra_claims`` — with the vault-held ``signing_key_secret``
    (an HMAC secret for ``HS256``, a PEM private key for ``RS256``/``ES256``).
    The token renders into ``header`` via ``format`` (``Bearer {jwt}`` default).
    Minting lives in :mod:`kow.injectors.jwt_bearer`.
    """

    model_config = _STRICT_MODEL

    type: Literal["jwt_bearer"] = "jwt_bearer"
    signing_key_secret: str
    algorithm: Literal["HS256", "RS256", "ES256"] = "RS256"
    issuer: str | None = None
    subject: str | None = None
    audience: str | None = None
    ttl_seconds: int = Field(default=300, ge=1, le=86400)
    header: str = "Authorization"
    format: str = "Bearer {jwt}"
    extra_claims: dict[str, str] | None = None

    @model_validator(mode="after")
    def require_jwt_token_placeholder(self) -> JwtBearerInjector:
        if "{jwt}" not in self.format:
            raise ValueError("jwt_bearer.format must contain the '{jwt}' placeholder")
        return self


class Oauth2ClientCredentialsInjector(BaseModel):
    """OAuth 2.0 client-credentials grant (RFC 6749 §4.4).

    Exchanges a vault-held client id + secret for a short-lived access token at
    ``token_url`` and injects it (default ``Bearer {access_token}``). The
    machine-to-machine sibling of ``oauth2_refresh`` — no refresh token, no
    rotation. Resolution lives in
    :mod:`kow.injectors.oauth2_client_credentials`. (Provider
    presets are a later slice; v1 takes an explicit ``token_url``.)
    """

    model_config = _STRICT_MODEL

    type: Literal["oauth2_client_credentials"] = "oauth2_client_credentials"
    token_url: HttpUrl
    client_auth_method: Literal["body_post", "basic"] = "body_post"
    client_id_secret: str
    client_secret_secret: str
    scopes: str | None = None
    header: str = "Authorization"
    format: str = "Bearer {access_token}"
    cache_ttl_safety_seconds: int = Field(default=60, ge=0, le=600)
    cache_ttl_max_seconds: int = Field(default=3600, ge=60, le=86400)

    def render_value(self, *, access_token: str) -> str:
        """Substitute ``{access_token}`` — ``str.replace``, not format-language,
        so an operator format cannot traverse attributes."""
        return self.format.replace("{access_token}", access_token)

    @field_validator("token_url")
    @classmethod
    def require_https(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError(
                "oauth2_client_credentials.token_url must use https "
                "(RFC 6749 §3.1 — the token endpoint MUST use TLS)"
            )
        _reject_url_credentials(v, "oauth2_client_credentials.token_url")
        return v


class GithubAppInjector(BaseModel):
    """GitHub App installation access-token minting.

    Mints an App JWT (RS256) from the App's PEM private key, exchanges it at
    ``{api_base_url}/app/installations/{installation_id}/access_tokens`` for a
    short-lived installation token, caches it, and injects it (default
    ``Authorization: token {token}``). Resolution lives in
    :mod:`kow.injectors.github_app`; it reuses the JWT signer and
    the shared token transport.
    """

    model_config = _STRICT_MODEL

    type: Literal["github_app"] = "github_app"
    app_id: str
    installation_id: str
    private_key_secret: str
    api_base_url: str = "https://api.github.com"
    header: str = "Authorization"
    format: str = "token {token}"
    cache_ttl_safety_seconds: int = Field(default=60, ge=0, le=600)

    def render_value(self, *, token: str) -> str:
        """Substitute ``{token}`` — ``str.replace``, not format-language."""
        return self.format.replace("{token}", token)

    @field_validator("api_base_url")
    @classmethod
    def normalize_api_base(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith("https://"):
            raise ValueError("github_app.api_base_url must use the https scheme")
        _reject_url_credentials(v, "github_app.api_base_url")
        return v

    @model_validator(mode="after")
    def require_jwt_token_placeholder(self) -> GithubAppInjector:
        if "{token}" not in self.format:
            raise ValueError("github_app.format must contain the '{token}' placeholder")
        return self


class GcpServiceAccountInjector(BaseModel):
    """Google service-account authority, brokered (ADR-0050).

    Three modes, one type:

    - ``self_signed_jwt`` — sign an RS256 JWT with the vault-held service-account
      key and present it directly as the bearer credential. No network call. Works
      only for the Google APIs that accept a self-signed assertion.
    - ``jwt_bearer_grant`` — sign the same assertion and exchange it at Google's
      token endpoint (RFC 7523 §2.1) for an access token. Covers the whole API
      surface. Requires an exported key, which Google's own guidance discourages.
    - ``impersonate`` (**default**) — mint a token for ``service_account_email``
      via IAM Credentials ``generateAccessToken``. No service-account key is
      created or stored for the target at all. The *source* identity is either
      the daemon's Application Default Credentials (``source: adc``) or a
      vault-held impersonation-seat key (``source: seat_key``), per ADR-0050
      decision 4.

    The agent never holds the key or the minted token: it presents the binding's
    placeholder and kow substitutes on egress, exactly as with every other
    computed injector.
    """

    model_config = _STRICT_MODEL

    type: Literal["gcp_service_account"] = "gcp_service_account"
    mode: Literal["self_signed_jwt", "jwt_bearer_grant", "impersonate"] = "impersonate"
    service_account_email: str
    # Required for self_signed_jwt / jwt_bearer_grant, and for impersonate when
    # source is ``seat_key``. Never set for impersonate + adc.
    private_key_secret: str | None = None
    # impersonate only: where the *calling* identity comes from.
    source: Literal["adc", "seat_key"] = "adc"
    # The seat's own email — required when source is ``seat_key`` so the
    # assertion it signs identifies the seat, not the target.
    source_service_account_email: str | None = None
    # Space-delimited OAuth scopes. Required for jwt_bearer_grant + impersonate;
    # optional for self_signed_jwt (where Google accepts a scope claim).
    scopes: str | None = None
    # self_signed_jwt only: the `aud` claim (the service endpoint).
    audience: str | None = None
    # Domain-wide delegation. Lets one binding act as an arbitrary user in a
    # Workspace domain, so it is gated behind an explicit opt-in (ADR-0050).
    subject: str | None = None
    allow_domain_wide_delegation: bool = False
    token_url: HttpUrl = HttpUrl("https://oauth2.googleapis.com/token")
    iam_credentials_base_url: str = "https://iamcredentials.googleapis.com"
    # Assertion lifetime (self-signed JWT / exchange assertion). Google caps at 1h.
    assertion_ttl_seconds: int = Field(default=300, ge=60, le=3600)
    # impersonate only: requested token lifetime. Google's ceiling without the
    # extended-lifetime org policy is 3600s; kow does not offer the 12h variant.
    lifetime_seconds: int = Field(default=3600, ge=60, le=3600)
    header: str = "Authorization"
    format: str = "Bearer {access_token}"
    cache_ttl_safety_seconds: int = Field(default=60, ge=0, le=600)

    def render_value(self, *, access_token: str) -> str:
        """Substitute ``{access_token}`` — ``str.replace``, not format-language,
        so an operator format cannot traverse attributes."""
        return self.format.replace("{access_token}", access_token)

    @field_validator("token_url")
    @classmethod
    def require_https_token_url(cls, v: HttpUrl) -> HttpUrl:
        if v.scheme != "https":
            raise ValueError("gcp_service_account.token_url must use https")
        _reject_url_credentials(v, "gcp_service_account.token_url")
        return v

    @field_validator("iam_credentials_base_url")
    @classmethod
    def normalize_iam_base(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith("https://"):
            raise ValueError("gcp_service_account.iam_credentials_base_url must use https")
        _reject_url_credentials(v, "gcp_service_account.iam_credentials_base_url")
        return v

    @field_validator("service_account_email", "source_service_account_email")
    @classmethod
    def require_email_shape(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if "@" not in v or v.startswith("@") or v.endswith("@"):
            raise ValueError("service-account fields must be an email address (name@project.iam…)")
        return v

    def _check_impersonate(self) -> None:
        """Impersonation: the target has no key by construction, so the only
        questions are which source identity mints and what it may ask for."""
        if self.subject is not None:
            raise ValueError(
                "gcp_service_account.subject is not supported in impersonate mode "
                "(generateAccessToken has no delegation claim); use jwt_bearer_grant"
            )
        if not self.scopes:
            raise ValueError("gcp_service_account.scopes is required in impersonate mode")
        if self.source == "seat_key":
            if not self.private_key_secret:
                raise ValueError("source: seat_key requires private_key_secret")
            if not self.source_service_account_email:
                raise ValueError("source: seat_key requires source_service_account_email")
        elif self.private_key_secret is not None:
            raise ValueError(
                "private_key_secret is meaningless with source: adc — the daemon's "
                "own credentials are used; set source: seat_key to bind a key"
            )

    def _check_key_modes(self) -> None:
        """The two key-bearing modes: a key is mandatory, and the source fields
        (which belong to impersonation) must be absent."""
        if self.source != "adc" or self.source_service_account_email is not None:
            raise ValueError("source / source_service_account_email apply only to impersonate mode")
        if not self.private_key_secret:
            raise ValueError(f"gcp_service_account.private_key_secret is required in {self.mode}")
        if self.mode == "jwt_bearer_grant" and not self.scopes:
            raise ValueError("gcp_service_account.scopes is required in jwt_bearer_grant mode")
        if self.mode == "self_signed_jwt" and not (self.audience or self.scopes):
            raise ValueError(
                "gcp_service_account.self_signed_jwt requires audience (the service "
                "endpoint) or scopes"
            )

    @model_validator(mode="after")
    def require_mode_coherence(self) -> GcpServiceAccountInjector:
        if "{access_token}" not in self.format:
            raise ValueError(
                "gcp_service_account.format must contain the '{access_token}' placeholder"
            )
        if self.subject is not None and not self.allow_domain_wide_delegation:
            raise ValueError(
                "gcp_service_account.subject performs domain-wide delegation (act as any "
                "user in the Workspace domain); set allow_domain_wide_delegation: true to "
                "confirm that is intended"
            )
        if self.mode == "impersonate":
            self._check_impersonate()
        else:
            self._check_key_modes()
        return self


# Leaf injectors permitted inside MultiInjector. Nested multi is rejected
# at config-load. ``oauth2_refresh`` and ``sigv4`` are NOT permitted children —
# their computed resolution steps (which child triggers, sibling sharing, audit
# ordering; and, for sigv4, whole-request signing) need single-bind semantics.
LeafInjectorSpec = Annotated[HeaderInjector | BodyInjector, Field(discriminator="type")]


_MULTI_MIN_CHILDREN = 2
_MULTI_MAX_CHILDREN = 4  # mirrors compose: cap


class MultiInjector(BaseModel):
    """One secret's placeholder feeds multiple injection sites in one request
    (e.g. an Authorization header AND a JSON body field). 2-4 leaf children.
    Nested multi rejected; ``compose:`` cannot wrap a multi."""

    model_config = _STRICT_MODEL

    type: Literal["multi"] = "multi"
    injectors: list[LeafInjectorSpec]

    @model_validator(mode="after")
    def validate_children(self) -> MultiInjector:
        n = len(self.injectors)
        if n < _MULTI_MIN_CHILDREN or n > _MULTI_MAX_CHILDREN:
            raise ValueError(
                f"multi inject.injectors must contain "
                f"{_MULTI_MIN_CHILDREN}-{_MULTI_MAX_CHILDREN} children; got {n}. "
                "Single-injector secrets should use the leaf type directly."
            )
        # Header names compared case-insensitively per RFC 7230 §3.2 —
        # otherwise `Authorization` + `authorization` would silently
        # overwrite on the wire.
        header_names_lower: set[str] = set()
        body_count = 0
        for child in self.injectors:
            if isinstance(child, HeaderInjector):
                lowered = child.header.lower()
                if lowered in header_names_lower:
                    raise ValueError(
                        f"multi inject.injectors contains two header children "
                        f"targeting the same header {child.header!r} "
                        "(HTTP header names are case-insensitive). Pick one."
                    )
                header_names_lower.add(lowered)
            elif isinstance(child, BodyInjector):
                body_count += 1
        # One body child per multi — multiple would race on the same
        # placeholder occurrence in the body bytes.
        if body_count > 1:
            raise ValueError(
                "multi inject.injectors contains more than one body child; "
                "use one body child per multi (or split into separate secrets)."
            )
        return self


# Discriminated union of all injector specs. Default-type injection at
# `Config.normalize_and_validate_injector_types` keeps v0.4.x configs
# parsing without a `type:` field.
InjectorSpec = Annotated[
    HeaderInjector
    | BodyInjector
    | MultiInjector
    | Oauth2RefreshInjector
    | Sigv4Injector
    | HmacInjector
    | JwtBearerInjector
    | Oauth2ClientCredentialsInjector
    | GithubAppInjector
    | GcpServiceAccountInjector,
    Field(discriminator="type"),
]


def iter_leaf_injectors(
    spec: InjectorSpec,
) -> list[
    HeaderInjector
    | BodyInjector
    | Oauth2RefreshInjector
    | Sigv4Injector
    | HmacInjector
    | JwtBearerInjector
    | Oauth2ClientCredentialsInjector
    | GithubAppInjector
    | GcpServiceAccountInjector
]:
    """Flatten ``spec`` to its ordered leaf injectors. Single-leaf bindings
    yield ``[spec]``; multi yields ``spec.injectors``. ``oauth2_refresh``
    is a leaf — its runtime resolution step is single-bind by design."""
    if isinstance(spec, MultiInjector):
        return list(spec.injectors)
    return [spec]
