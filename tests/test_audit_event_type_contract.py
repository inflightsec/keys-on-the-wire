"""ADR-0023 audit contract guard — the structural 'strong rule'.

The stateful no-leak machines (test_addon*_noleak_stateful.py) prove that
secret BYTES never appear in the audit stream for the paths they drive. This
file closes the residual gap: a FUTURE new audit event type (or a type removed
from the closed set) — which those machines wouldn't automatically cover.

Two layers, both cheap and prod-safe (no hot-path behaviour change beyond the
choke-point type guard already in AuditWriter.emit):

  1. FREEZE — the set of `"type": "..."` literals at the real emit sites must
     equal AUDIT_EVENT_TYPES. A new emit type that isn't added to the closed
     set fails here, forcing a conscious update + no-leak coverage (ADR-0023).
  2. GUARD — AuditWriter.emit refuses any unlisted type at the single choke
     point. Proven here to fire.

The per-type field allowlist below is the declared contract (documentation +
the basis for a future field-level runtime guard); representative records are
asserted to stay within it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kow.audit import (
    AUDIT_EVENT_TYPES,
    EVENT_HONEYTOKEN_TRIGGERED,
    AuditWriter,
)

# Modules that call AuditWriter.emit. A new emit site in a NEW module is caught
# at runtime by the emit() guard; this static freeze is the friendly early
# warning for the common case (a new type at an existing site).
_SRC = Path(__file__).resolve().parent.parent / "src" / "kow"
_EMIT_SITE_MODULES = [
    _SRC / "addon.py",
    _SRC / "handlers.py",
    _SRC / "_fail_closed.py",
    _SRC / "injectors" / "oauth2_refresh.py",
    _SRC / "injectors" / "body.py",
    _SRC / "sshagent" / "server.py",
]

_TYPE_LITERAL = re.compile(r'"type":\s*"([a-z_]+)"')

# The declared per-type field contract (ADR-0023 / ADR-0017 §7). Top-level
# keys only; `ts` + `v` are stamped by the writer and always allowed. Nested
# `destination` keys are pinned separately. Every field here is metadata or a
# vault REFERENCE name — never a secret VALUE.
_WRITER_STAMPED = frozenset({"ts", "v"})
ALLOWED_TOP_LEVEL_FIELDS: dict[str, frozenset[str]] = {
    "inject_decision": frozenset(
        {
            "type",
            "request_id",
            "decision",
            "reason",
            "secret_name",
            "binding_source",
            "matched_secret_names",
            "method",
            "path",
            "compose",
            "destination",
        }
    ),
    # ADR-0047 advisory: same minimized shape as inject_decision, minus the
    # binding/compose bookkeeping an advisory has no opinion about.
    "policy_advisory": frozenset(
        {
            "type",
            "request_id",
            "decision",
            "reason",
            "secret_name",
            "method",
            "destination",
        }
    ),
    "deny": frozenset({"type", "request_id", "reason", "destination"}),
    "token_exchange": frozenset(
        {
            "type",
            "request_id",
            "binding_name",
            "token_url_host",
            "outcome",
            "cache_ttl_effective_seconds",
            "used_default_expiry",
            "error_description",
        }
    ),
    "refresh_token_rotated": frozenset(
        {"type", "request_id", "binding_name", "refresh_token_secret", "outcome", "error_type"}
    ),
    EVENT_HONEYTOKEN_TRIGGERED: frozenset(
        {"type", "request_id", "binding_name", "dest_host", "underlying_reason"}
    ),
    "proxy_restart": frozenset({"type"}),
    "upstream_response": frozenset({"type", "request_id", "status"}),
    # ADR-0026: unbound TLS connection tunneled un-terminated. Metadata only —
    # dest host + reason; the connection was never decrypted (no secret value).
    "tls_passthrough": frozenset({"type", "reason", "destination"}),
    # ADR-0032: background notes-refresh changed the bound set. Secret NAMES
    # added/removed only — never values.
    "notes_refreshed": frozenset({"type", "added", "removed"}),
    # ADR-0053: ssh-agent oracle events. Keys are named by SHA256 fingerprint
    # only — never a key blob, never signed data, never a signature.
    "ssh_session_bound": frozenset(
        {"type", "request_id", "peer_uid", "host_key_fpr", "forwarding"}
    ),
    "ssh_sign_allowed": frozenset(
        {
            "type",
            "request_id",
            "peer_uid",
            "key_fpr",
            "binding_name",
            "reason",
            "user",
            "dest_host_key_fpr",
            "session_bound",
        }
    ),
    "ssh_sign_denied": frozenset(
        {
            "type",
            "request_id",
            "peer_uid",
            "key_fpr",
            "binding_name",
            "reason",
            "user",
            "dest_host_key_fpr",
            "session_bound",
        }
    ),
}
ALLOWED_DESTINATION_KEYS = frozenset(
    {"host", "port", "path_prefix", "connect_host", "request_host"}
)


def _emitted_type_literals() -> set[str]:
    found: set[str] = set()
    for mod in _EMIT_SITE_MODULES:
        for match in _TYPE_LITERAL.finditer(mod.read_text()):
            found.add(match.group(1))
    # honeytoken_triggered is constructed inside audit.py itself, not at an
    # emit site, so add it explicitly (it IS a real audited type).
    found.add(EVENT_HONEYTOKEN_TRIGGERED)
    return found


def test_emitted_types_equal_declared_closed_set() -> None:
    """FREEZE: the types the code actually emits == AUDIT_EVENT_TYPES exactly.

    Extra emitted type not in the set -> someone shipped a new audit event
    without registering it (and without no-leak coverage). Declared type never
    emitted -> dead contract entry. Both are failures."""
    emitted = _emitted_type_literals()
    assert emitted == set(AUDIT_EVENT_TYPES), (
        f"audit type contract drift: emitted-but-undeclared={emitted - set(AUDIT_EVENT_TYPES)}, "
        f"declared-but-unemitted={set(AUDIT_EVENT_TYPES) - emitted}"
    )


def test_every_declared_type_has_a_field_allowlist() -> None:
    """Each closed-set type must have a declared field allowlist — so the
    contract can never name a type whose permitted fields are unspecified."""
    assert set(ALLOWED_TOP_LEVEL_FIELDS) == set(AUDIT_EVENT_TYPES)


def test_emit_rejects_unlisted_type(tmp_path: Path) -> None:
    """GUARD: the choke point refuses an unclassified record fail-closed."""
    w = AuditWriter(str(tmp_path / "audit.jsonl"))
    with pytest.raises(ValueError, match="not in AUDIT_EVENT_TYPES"):
        w.emit({"type": "surprise_new_event", "secret_leak": "hunter2"})
    # And nothing was written — fail-closed means no partial record on disk.
    assert not (tmp_path / "audit.jsonl").exists() or (tmp_path / "audit.jsonl").read_text() == ""


def test_emit_accepts_every_declared_type(tmp_path: Path) -> None:
    """Smoke: each declared type is accepted by the guard (no false-trip)."""
    w = AuditWriter(str(tmp_path / "audit.jsonl"))
    for t in AUDIT_EVENT_TYPES:
        w.emit({"type": t})  # minimal record; field completeness is tested elsewhere


def test_representative_records_stay_within_field_allowlist() -> None:
    """The declared field allowlist covers the maximal representative record of
    each type. Guards against a value-bearing field silently entering the
    contract. (Full-path field coverage is the no-leak state machines' job.)"""
    corpus: dict[str, dict] = {
        "inject_decision": {
            "type": "inject_decision",
            "request_id": "r",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "FOO",
            "binding_source": "file",
            "matched_secret_names": ["A", "B"],
            "method": "POST",
            "path": "/v1/x",
            "compose": ["A", "B"],
            "destination": {"host": "api.example.com", "port": 443, "path_prefix": "/v1/x"},
        },
        "deny": {
            "type": "deny",
            "request_id": "r",
            "reason": "sni_host_mismatch",
            "destination": {"connect_host": "a.com", "request_host": "b.com"},
        },
        "token_exchange": {
            "type": "token_exchange",
            "request_id": "r",
            "binding_name": "FOO",
            "token_url_host": "oauth2.googleapis.com",
            "outcome": "success",
            "cache_ttl_effective_seconds": 3539,
            "used_default_expiry": False,
            "error_description": "n/a",
        },
        "refresh_token_rotated": {
            "type": "refresh_token_rotated",
            "request_id": "r",
            "binding_name": "FOO",
            "refresh_token_secret": "FOO_RT",
            "outcome": "success",
            "error_type": "None",
        },
        EVENT_HONEYTOKEN_TRIGGERED: {
            "type": EVENT_HONEYTOKEN_TRIGGERED,
            "request_id": "r",
            "binding_name": "FOO",
            "dest_host": "api.example.com",
            "underlying_reason": "binding_matched",
        },
        # ADR-0047: maximal advisory record (binding_methods_unscoped carries
        # `method`).
        "policy_advisory": {
            "type": "policy_advisory",
            "request_id": "r",
            "decision": "allowed",
            "reason": "binding_methods_unscoped",
            "secret_name": "FOO",
            "method": "POST",
            "destination": {"host": "api.example.com", "port": 443},
        },
        "proxy_restart": {"type": "proxy_restart"},
        "upstream_response": {"type": "upstream_response", "request_id": "r", "status": 200},
        "tls_passthrough": {
            "type": "tls_passthrough",
            "reason": "unbound_destination",
            "destination": {"host": "api.example.com"},
        },
        "notes_refreshed": {
            "type": "notes_refreshed",
            "added": ["NEW_SECRET"],
            "removed": [],
        },
        # ADR-0053: maximal ssh oracle records — fingerprints, names, and
        # verdict metadata only.
        "ssh_session_bound": {
            "type": "ssh_session_bound",
            "request_id": "r",
            "peer_uid": 1000,
            "host_key_fpr": "SHA256:abc",
            "forwarding": False,
        },
        "ssh_sign_allowed": {
            "type": "ssh_sign_allowed",
            "request_id": "r",
            "peer_uid": 1000,
            "key_fpr": "SHA256:abc",
            "binding_name": "MAINFRAME",
            "reason": "sign_allowed",
            "user": "ansible",
            "dest_host_key_fpr": "SHA256:def",
            "session_bound": True,
        },
        "ssh_sign_denied": {
            "type": "ssh_sign_denied",
            "request_id": "r",
            "peer_uid": 1000,
            "key_fpr": "SHA256:abc",
            "binding_name": "MAINFRAME",
            "reason": "host_key_not_pinned",
            "user": "ansible",
            "dest_host_key_fpr": None,
            "session_bound": False,
        },
    }
    assert set(corpus) == set(AUDIT_EVENT_TYPES), "representative corpus must cover every type"
    for t, record in corpus.items():
        allowed = ALLOWED_TOP_LEVEL_FIELDS[t] | _WRITER_STAMPED
        extra = set(record) - allowed
        assert not extra, f"{t}: fields outside declared allowlist: {extra}"
        dest = record.get("destination")
        if isinstance(dest, dict):
            dest_extra = set(dest) - ALLOWED_DESTINATION_KEYS
            assert not dest_extra, f"{t}.destination: keys outside allowlist: {dest_extra}"


@pytest.mark.parametrize(
    "record",
    [
        {
            "type": "policy_advisory",
            "request_id": "r",
            "decision": "allowed",
            "reason": "binding_methods_unscoped",
            "secret_name": "FOO",
            "method": "POST",
            "destination": {"host": "api.example.com", "port": 443},
        },
    ],
)
def test_adr0047_advisory_records_stay_within_field_allowlist(
    record: dict[str, object],
) -> None:
    record_type = str(record["type"])
    allowed = ALLOWED_TOP_LEVEL_FIELDS[record_type] | _WRITER_STAMPED
    extra = set(record) - allowed
    assert not extra, f"{record_type}: fields outside declared allowlist: {extra}"
    destination = record.get("destination")
    assert isinstance(destination, dict)
    dest_extra = set(destination) - ALLOWED_DESTINATION_KEYS
    assert not dest_extra, f"inject_decision.destination: keys outside allowlist: {dest_extra}"
