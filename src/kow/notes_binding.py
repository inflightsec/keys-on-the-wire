"""Parse a secret's ``notes`` / annotation field into a binding spec (ADR-0011
items 2 & 4; ADR-0018 §4).

Backend-agnostic: this parser serves BOTH the Bitwarden ``notes`` field and the
GSM ``avp-binding`` annotation — the input is just a string. (Renamed from
``bws_notes``; ``kow.bws_notes`` re-exports this module for
back-compat.)

A note is only parsed as a binding when its first non-blank line is exactly
``# avp-binding`` (the ADR-0025 marker); anything unmarked is a human
description and yields :class:`NoBinding` — the file bindings stand. After
the marker, the body is a flat top-level YAML blob. ``host`` is the only
required field; everything else defaults. ``host`` accepts a single hostname string
or a list of hostnames (a ``hosts:`` alias is also accepted); a list fans out
to one binding per host under a single injector, gated by the multi-host trust
invariant (ADR-0021 §4): the note must set an explicit ``format`` (no silent
bare-Bearer broadcast) and may not list a host that carries curated per-host
defaults (those bind in their own single-host note). The substitution token in the note is
the generic ``{secret}`` (the note has no separate name key); the parser
rewrites it to ``{<secret_name>}`` so config.py's per-entry placeholder
invariant holds.

Three outcomes (a small tagged union), so the caller can audit each
distinctly per the ADR amendment:

  * :class:`NoBinding`      — empty/missing note, or a well-formed mapping
                              with no ``host``. NOT malformed. Audit reason
                              ``no_binding_in_notes``.
  * :class:`InvalidBinding` — malformed YAML, wrong shape, unknown key,
                              bad value. FAIL CLOSED. Audit reason
                              ``invalid_binding_metadata`` + diagnostic.
  * :class:`ParsedBinding`  — a validated, file-parity SecretSpec plus any
                              companion headers from the exception table.

Validation is NOT forked: the built dict is fed through config.py's
``SecretSpec`` (which runs HeaderInjector + BindingSpec validators — host
normalization, method/path rules, extra=forbid). A note that fails those
validators surfaces as InvalidBinding, exactly like the file path rejects
a bad bindings.yaml entry.
"""

from __future__ import annotations

import logging
import re
import textwrap
from dataclasses import dataclass, field

import yaml
from pydantic import ValidationError

from kow.config import SecretSpec
from kow.placeholders import STORED_PLACEHOLDER_RE

_log = logging.getLogger(__name__)

# ADR-0025: a note/annotation is ONLY parsed as a binding when its first
# non-blank line is exactly this marker. The notes field is an ambient
# free-text channel — human descriptions live there. Parsing unmarked text
# cost a fleet outage (2026-07-18): host-shaped descriptions became malformed
# bindings, which fail-closed KILLED those secrets' real file bindings under
# binding_source `both`. Marker present = binding intent (errors after it fail
# LOUD as InvalidBinding); marker absent = description (NoBinding, file
# bindings stand untouched). Uniform across sources (BWS notes AND the GSM
# `avp-binding` annotation) — one contract, no source-plumbing.
NOTES_MARKER = "# kow-binding"  # canonical marker: emitted by tooling, shown in docs.
# `# avp-binding` is accepted as a backward-compat alias (the ADR-0045 rename):
# both markers select a binding identically, so existing avp-binding notes keep
# working while kow-binding is the default going forward. Alias drops in 2.0.0.
_ACCEPTED_MARKERS: tuple[str, ...] = (NOTES_MARKER, "# avp-binding")

# Generic substitution token in a note (vs the file path's {SECRET_NAME}).
# Not a credential — it's the literal placeholder marker the operator types.
_NOTE_SECRET_TOKEN = "{secret}"  # noqa: S105  # nosec B105 — substitution token, not a secret

# Flat note keys we accept. A key outside this set is a typo and fails
# closed (mirrors config.py's extra="forbid" for bindings.yaml). The note
# parser owns this list because the note schema is flat/defaulted, unlike
# the nested file schema — but the VALUES still go through config.py
# validators, so semantics stay identical across sources.
_ALLOWED_NOTE_KEYS = {"host", "hosts", "header", "format", "methods", "paths", "placeholder"}

# The bare-string shorthand (`api.openai.com` as the whole note, ADR-0018 §4
# Tier 0) may ONLY fire when the string is actually shaped like a hostname.
# Vault secrets routinely carry a free-text human DESCRIPTION in their note
# ("HackerOne API identifier", "GCP project ID", "Sentry API token (scope
# unknown)"). Treating such a description as a host manufactures a garbage
# binding, and under binding_source `both` (notes win per secret) that garbage
# host shadows the real bindings.yaml host — the secret then silently stops
# injecting. This pattern requires ≥2 dot-separated DNS labels (FQDN, IPv4, or
# a `*.`-wildcard); anything with whitespace/punctuation or a single label is a
# description, not a host, and carries no binding. Explicit `host:` mappings
# bypass this gate entirely.
_BARE_HOSTNAME_RE = re.compile(
    r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$"
)

_DEFAULT_HEADER = "Authorization"
_DEFAULT_FORMAT = f"Bearer {_NOTE_SECRET_TOKEN}"


@dataclass(frozen=True)
class _ExceptionRow:
    """One host-keyed exception-table row. Supplies non-Bearer defaults for
    a known host. Any field left None falls back to the bare Bearer default
    (or, for scope, to no narrowing). ``companion_headers`` are extra static
    headers the integration requires alongside the credential header."""

    header: str = _DEFAULT_HEADER
    # format uses the generic {secret} token; rewritten per-secret later.
    format: str = _DEFAULT_FORMAT
    companion_headers: dict[str, str] = field(default_factory=dict)
    default_methods: list[str] | None = None
    default_paths: list[str] | None = None


# Bundled exception table (ADR-0011 amendment table, verbatim). Keyed on the
# host the human typed — NEVER inferred from key bytes. Default scopes ship
# TIGHT: the GitHub row is the worked example (a PAT bound to api.github.com
# with no scope could POST /gists and exfiltrate to a public gist, so the
# default is GET-read-only across documented read paths; writes require an
# explicit methods/paths override in the note).
EXCEPTION_TABLE: dict[str, _ExceptionRow] = {
    "api.anthropic.com": _ExceptionRow(
        header="x-api-key",
        format=_NOTE_SECRET_TOKEN,  # raw value, no Bearer
        companion_headers={"anthropic-version": "2023-06-01"},
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.openai.com": _ExceptionRow(  # Bearer default
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.github.com": _ExceptionRow(
        # Bearer default; GET read-only scope — NO POST, NO /gists, no writes.
        default_methods=["GET"],
        default_paths=["/repos/**", "/user", "/users/**", "/orgs/**", "/search/**"],
    ),
    "api.stripe.com": _ExceptionRow(  # Bearer default; Stripe also accepts Basic
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.notion.com": _ExceptionRow(  # Bearer default
        companion_headers={"Notion-Version": "2022-06-28"},
        default_methods=["POST", "PATCH"],
        default_paths=["/v1/**"],
    ),
    "api.linear.app": _ExceptionRow(
        header=_DEFAULT_HEADER,
        format=_NOTE_SECRET_TOKEN,  # raw Authorization: {secret}, no Bearer
        default_methods=["POST"],
        default_paths=["/graphql"],
    ),
}


@dataclass(frozen=True)
class NoBinding:
    """The note carries no binding (empty / missing / no host). Fail-closed
    by omission, but distinguished from malformed in the audit log."""

    secret_name: str


@dataclass(frozen=True)
class InvalidBinding:
    """The note is malformed — fail closed, with a precise human diagnostic
    (ADR diagnostic-UX requirement)."""

    secret_name: str
    diagnostic: str


@dataclass(frozen=True)
class ParsedBinding:
    """A validated binding built from a note."""

    secret_name: str
    spec: SecretSpec
    companion_headers: dict[str, str]


def _rewrite_token(fmt: str, secret_name: str) -> str:
    """Rewrite the generic ``{secret}`` token to ``{<secret_name>}`` so the
    SecretSpec satisfies config.py's per-entry format invariant. Only the
    exact ``{secret}`` token is rewritten; an operator who hand-wrote
    ``{secret}`` in the note for some other reason still maps to the value
    (that IS the substitution token by spec), and any other ``{...}`` is
    left untouched — config.py's HeaderInjector validator will reject a
    format that ends up with no matching placeholder."""
    return fmt.replace(_NOTE_SECRET_TOKEN, "{" + secret_name + "}")


def _load_note_mapping(secret_name: str, note: str) -> dict | NoBinding | InvalidBinding:
    """YAML-load + shape/key checks. Returns the raw mapping on success, or
    the terminal NoBinding/InvalidBinding outcome. Split from
    parse_notes_binding to keep each function under the complexity gate."""
    # Tolerate hand-pasted notes whose body is uniformly indented (a common
    # shape when copied out of a rendered/quoted block, or tab-indented —
    # which raw YAML rejects outright). Our note grammar is FLAT with
    # flow-style lists, so removing the COMMON leading whitespace is safe:
    # it never changes key nesting, and a block list keeps its relative
    # indent (dedent only strips the shared prefix). Inconsistent indentation
    # has no common prefix, so it is left untouched and still fails loud.
    note = textwrap.dedent(note)
    try:
        raw = yaml.safe_load(note)
    except yaml.YAMLError as e:
        return InvalidBinding(
            secret_name,
            f"note is not valid YAML: {type(e).__name__}. "
            "Expected a flat mapping like `host: api.example.com`.",
        )
    if raw is None:
        # e.g. a note that is only a YAML comment.
        return NoBinding(secret_name)
    if isinstance(raw, str):
        # Bare-hostname shorthand (ADR-0018 §4 Tier 0): the note is just a host
        # string, e.g. `api.openai.com`. Treat it as {host: <string>} so the
        # North-Star "add a secret, tag it with the host" path needs no YAML.
        # A blank/whitespace string is no binding, NOT malformed.
        stripped = raw.strip()
        if not stripped:
            return NoBinding(secret_name)
        # Only reached with the ADR-0025 marker present — binding intent is
        # explicit, so a scalar that is not hostname-shaped is an operator
        # ERROR (typo'd host), not an ignorable description: fail LOUD.
        # (_BARE_HOSTNAME_RE stays as the second belt behind the marker.)
        if not _BARE_HOSTNAME_RE.match(stripped):
            return InvalidBinding(
                secret_name,
                f"marked binding note body {stripped!r} is not a valid bare "
                "hostname (dot-separated DNS labels). Use `api.example.com`, "
                "or a flat mapping with `host:`.",
            )
        return {"host": stripped}
    if not isinstance(raw, dict):
        return InvalidBinding(
            secret_name,
            f"note must be a bare hostname string or a flat YAML mapping "
            f"(got {type(raw).__name__}). Expected `api.example.com`, or flat "
            "keys like `host:`, `header:`, `format:`.",
        )
    # Unknown key -> fail closed (mirror extra="forbid"). Catch typos like
    # `hots:` / `methdos:` before they become a silent unscoped binding.
    unknown = set(raw) - _ALLOWED_NOTE_KEYS
    if unknown:
        # str() every key before sorting: YAML permits non-string keys
        # (`1: x`, `true: y`), and sorting a mixed int/str/bool set raises
        # TypeError — which would escape the parser and abort the reload
        # instead of recording this as invalid metadata. Fail closed, cleanly.
        return InvalidBinding(
            secret_name,
            f"unknown note key(s) {sorted(map(str, unknown))}; "
            f"allowed keys: {sorted(_ALLOWED_NOTE_KEYS)}.",
        )
    return raw


def _strip_binding_marker(secret_name: str, note: str) -> str | NoBinding | InvalidBinding:
    """ADR-0025 marker gate. Returns the marker-stripped body on success, or the
    terminal NoBinding (unmarked = description) / InvalidBinding (marker with no
    body) outcome. Split from parse_notes_binding to hold the complexity gate."""
    lines = note.splitlines()
    first_idx = next((i for i, ln in enumerate(lines) if ln.strip()), None)
    if first_idx is None or lines[first_idx].strip() not in _ACCEPTED_MARKERS:
        # Migration aid: an unmarked note that LOOKS like a binding (bare
        # hostname, or a host:/hosts: line) is silently inert — name it at
        # load so a forgotten marker is self-diagnosing, not a mystery.
        host_shaped = bool(_BARE_HOSTNAME_RE.match(note.strip())) or bool(
            re.search(r"(?m)^\s*hosts?\s*:", note)
        )
        if host_shaped:
            _log.warning(
                "secret %r: note looks host-shaped but lacks the %r marker line — "
                "ignored (no binding). Prepend the marker line if it is meant to bind.",
                secret_name,
                NOTES_MARKER,
            )
        return NoBinding(secret_name)
    body = "\n".join(lines[first_idx + 1 :])
    if not body.strip():
        # Marker present but nothing after it: binding intent was declared,
        # content is missing — fail LOUD, not silently inert.
        return InvalidBinding(
            secret_name,
            f"note starts with the {NOTES_MARKER!r} marker but has no binding "
            "content after it. Add a bare hostname or a flat mapping "
            "(`host: api.example.com`).",
        )
    return body


def parse_notes_binding(
    *,
    secret_name: str,
    placeholder: str,
    note: str | None,
) -> NoBinding | InvalidBinding | ParsedBinding:
    """Parse one secret's note into a binding outcome.

    ``placeholder`` is the env-side placeholder the daemon assigned to this
    secret (from the placeholder map); it's stamped into the SecretSpec so
    the addon's placeholder matching works identically to the file path.
    """
    # Empty / whitespace-only / absent -> no binding (NOT malformed).
    if note is None or not note.strip():
        return NoBinding(secret_name)

    # ADR-0025 marker gate (extracted to keep this function under the C901
    # complexity gate, like _load_note_mapping): unmarked -> NoBinding /
    # marker-only -> InvalidBinding / else the marker-stripped body.
    gated = _strip_binding_marker(secret_name, note)
    if isinstance(gated, NoBinding | InvalidBinding):
        return gated
    body = gated

    loaded = _load_note_mapping(secret_name, body)
    if isinstance(loaded, NoBinding | InvalidBinding):
        return loaded
    raw = loaded

    resolved_placeholder = _resolve_stored_placeholder(secret_name, raw, placeholder)
    if isinstance(resolved_placeholder, InvalidBinding):
        return resolved_placeholder
    placeholder = resolved_placeholder

    host = raw.get("host")
    hosts_alias = raw.get("hosts")
    if host is not None and hosts_alias is not None:
        return InvalidBinding(secret_name, "set either `host` or `hosts`, not both.")
    if host is None:
        host = hosts_alias
    if host is None:
        # Well-formed mapping with no host => no binding, not malformed.
        return NoBinding(secret_name)

    if isinstance(host, list):
        # ADR-0021: a list of hostnames fans out to one binding per host under a
        # single injector, gated by the multi-host trust invariant (§4).
        return _parse_multihost_note(
            secret_name=secret_name, placeholder=placeholder, raw=raw, hosts=host
        )
    if not isinstance(host, str) or not host.strip():
        return InvalidBinding(
            secret_name,
            "`host` must be a non-empty string or a list of hostnames.",
        )
    return _parse_single_host_note(
        secret_name=secret_name, placeholder=placeholder, raw=raw, host=host
    )


def _binding_dict(host: str, methods: object, paths: object) -> dict[str, object]:
    """Build one binding mapping, omitting scope fields that are None so the
    BindingSpec defaults (any-method / any-path) apply."""
    binding: dict[str, object] = {"host": host}
    if methods is not None:
        binding["methods"] = methods
    if paths is not None:
        binding["paths"] = paths
    return binding


def _finalize_spec(
    secret_name: str,
    placeholder: str,
    header: str,
    fmt: str,
    bindings: list[dict[str, object]],
    companion: dict[str, str],
) -> ParsedBinding | InvalidBinding:
    """Rewrite the token, build the header-inject SecretSpec, and validate it
    through config.py (shared with the file path). Bad shape -> InvalidBinding."""
    rewritten_format = _rewrite_token(fmt, secret_name)
    # Parity with the file path's Config-level `validate_format_placeholders`
    # (which does NOT re-run over notes-merged specs): the format MUST carry
    # this secret's own substitution token. A typo'd/foreign placeholder
    # (`Bearer {OTHER}`) would otherwise ship an unsubstituted literal header
    # at request time. Fail closed on malformed metadata.
    if "{" + secret_name + "}" not in rewritten_format:
        return InvalidBinding(
            secret_name,
            f"`format` must contain the substitution token `{{secret}}` "
            f"(or the literal `{{{secret_name}}}`); got {fmt!r}.",
        )
    spec_dict = {
        "placeholder": placeholder,
        "inject": {"type": "header", "header": header, "format": rewritten_format},
        "bindings": bindings,
    }
    try:
        spec = SecretSpec.model_validate(spec_dict)
    except ValidationError as e:
        # pydantic's message carries the field + reason; prefix with the secret
        # name so an operator can locate it.
        return InvalidBinding(
            secret_name,
            f"note failed binding validation: {_first_error(e)}",
        )
    return ParsedBinding(secret_name, spec, companion)


def _parse_single_host_note(
    *, secret_name: str, placeholder: str, raw: dict, host: str
) -> ParsedBinding | InvalidBinding:
    """Scalar-host note: exception-table defaults + one binding (pre-ADR-0021
    behaviour, unchanged)."""
    # Exception-table row for the typed host (default Bearer when absent).
    # Host is matched case-insensitively; config.py lowercases downstream anyway.
    row = EXCEPTION_TABLE.get(host.strip().lower(), _ExceptionRow())

    # Precedence: explicit note field > exception table > bare Bearer default.
    header = raw.get("header", row.header)
    fmt = raw.get("format", row.format)
    # Scope: explicit note methods/paths override the table's default scope.
    methods = raw.get("methods", row.default_methods)
    paths = raw.get("paths", row.default_paths)

    if not isinstance(fmt, str):
        return InvalidBinding(secret_name, "`format` must be a string.")
    if not isinstance(header, str):
        return InvalidBinding(secret_name, "`header` must be a string.")

    binding = _binding_dict(host, methods, paths)
    return _finalize_spec(
        secret_name, placeholder, header, fmt, [binding], dict(row.companion_headers)
    )


def _normalize_host_list(hosts: list) -> list[str] | str:
    """Strip + lowercase + de-duplicate a note `host`/`hosts` list. Returns the
    normalized list, or a diagnostic string if any element is not a non-empty
    string (DNS is case-insensitive, so case-variant duplicates collapse)."""
    normalized: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if not isinstance(h, str) or not h.strip():
            return "every entry in a `host` list must be a non-empty string"
        hl = h.strip().lower()
        if hl not in seen:
            seen.add(hl)
            normalized.append(hl)
    return normalized


def _multihost_guard(secret_name: str, raw: dict, hosts: list[str]) -> InvalidBinding | None:
    """Enforce the multi-host note invariant (ADR-0021 §4) for a list of >1 host:
    the note must be self-describing (explicit `format` — no silent bare-Bearer
    broadcast across hosts), and may not include a host that carries curated
    per-host defaults (scope/companion headers), which must bind in their own
    single-host note. Returns InvalidBinding on a violation, else None."""
    if "format" not in raw:
        return InvalidBinding(
            secret_name,
            "a multi-host `host` list must set an explicit `format` "
            '(e.g. `format: "Bearer {secret}"`); the bare-Bearer default is not '
            "applied silently across multiple hosts.",
        )
    # Wildcards are barred inside a multi-host list: a `*.suffix` element can
    # SUPERSET a curated host (e.g. `*.github.com` matches api.github.com) and
    # slip past the exact-membership curated check below, reaching a curated
    # host unscoped when allow_wildcard_hosts is enabled. Bind a wildcard in its
    # own single-host note (still gated by allow_wildcard_hosts at the merge).
    wildcard = sorted(h for h in hosts if h.startswith("*."))
    if wildcard:
        return InvalidBinding(
            secret_name,
            f"wildcard host(s) {wildcard} are not allowed in a multi-host note; "
            "bind a wildcard in its own single-host note.",
        )
    curated = sorted(h for h in hosts if h in EXCEPTION_TABLE)
    if curated:
        return InvalidBinding(
            secret_name,
            f"host(s) {curated} carry curated per-host defaults (scope/headers) that "
            "a multi-host note cannot apply safely; bind each in its own note "
            "(single `host:`).",
        )
    return None


def _parse_multihost_note(
    *, secret_name: str, placeholder: str, raw: dict, hosts: list
) -> ParsedBinding | InvalidBinding:
    """Fan a `host` list out to one binding per host under a single injector.
    A single-element list is equivalent to the scalar path; >1 host is gated by
    the multi-host trust invariant (:func:`_multihost_guard`)."""
    normalized = _normalize_host_list(hosts)
    if isinstance(normalized, str):
        return InvalidBinding(secret_name, normalized + ".")
    if not normalized:
        return InvalidBinding(secret_name, "`host` list is empty.")
    if len(normalized) == 1:
        return _parse_single_host_note(
            secret_name=secret_name, placeholder=placeholder, raw=raw, host=normalized[0]
        )

    guard = _multihost_guard(secret_name, raw, normalized)
    if guard is not None:
        return guard

    header = raw.get("header", _DEFAULT_HEADER)
    fmt = raw["format"]
    if not isinstance(fmt, str):
        return InvalidBinding(secret_name, "`format` must be a string.")
    if not isinstance(header, str):
        return InvalidBinding(secret_name, "`header` must be a string.")

    methods = raw.get("methods")
    paths = raw.get("paths")
    bindings = [_binding_dict(h, methods, paths) for h in normalized]
    # No companion headers for multi-host: curated (companion-bearing) hosts are
    # rejected by _multihost_guard, so a multi-host spec never carries them.
    return _finalize_spec(secret_name, placeholder, header, fmt, bindings, {})


def _resolve_stored_placeholder(secret_name: str, raw: dict, fallback: str) -> str | InvalidBinding:
    """ADR-0029: a note may PIN its placeholder (minted by `kow binding new`)
    instead of relying on the salt derivation the caller passed in. The
    stored value is format-gated hard: prefix + lowercase-base32 tail of
    >=21 chars, so a hand-typed weak string ("token") cannot parse and can
    never match innocent traffic. Global uniqueness is enforced one layer
    up (runtime_bindings), where the whole secret set is visible."""
    stored = raw.get("placeholder")
    if stored is None:
        return fallback
    if not isinstance(stored, str) or not STORED_PLACEHOLDER_RE.match(stored):
        return InvalidBinding(
            secret_name,
            "`placeholder` must be a string matching "
            "`kow-PLACEHOLDER-<21-64 lowercase base32 chars>` "
            "(the legacy `avp-` prefix is still accepted) "
            f"(mint one with `kow binding new`); got {stored!r}.",
        )
    return stored


def stored_placeholder_from_note(note: str | None, *, secret_name: str) -> str | None:
    """Extract a note's valid stored placeholder, or None (ADR-0029).

    Read-side helper for surfaces that need the placeholder WITHOUT running a
    full binding parse (``kow env`` projecting consumer export lines). Any
    note that is unmarked, malformed, or carries an invalid/missing
    ``placeholder`` yields None — such a secret either has no binding or will
    fail loud through the real parser; the caller falls back to derivation.

    ``secret_name`` is REQUIRED (keyword-only) so the marker-gate's
    forgot-the-marker warning names the real secret. It used to pass a literal
    ``<stored-placeholder-probe>`` sentinel, which reached operators as a warning
    about a secret that does not exist — the diagnostic was right, the subject
    was nonsense. No default, so a future caller cannot reintroduce that.
    """
    if note is None or not note.strip():
        return None
    gated = _strip_binding_marker(secret_name, note)
    if isinstance(gated, NoBinding | InvalidBinding):
        return None
    loaded = _load_note_mapping(secret_name, gated)
    if isinstance(loaded, NoBinding | InvalidBinding):
        return None
    stored = loaded.get("placeholder")
    if isinstance(stored, str) and STORED_PLACEHOLDER_RE.match(stored):
        return stored
    return None


def _first_error(e: ValidationError) -> str:
    """Compact one-line diagnostic from a pydantic ValidationError. The full
    error is multi-line; operators want the first concrete cause."""
    errors = e.errors()
    if not errors:
        return str(e)
    first = errors[0]
    loc = ".".join(str(p) for p in first.get("loc", ()))
    msg = first.get("msg", "invalid")
    return f"{loc}: {msg}" if loc else msg
