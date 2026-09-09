"""Stored (note-carried) placeholders — ADR-0029.

A note may pin its secret's placeholder explicitly (`placeholder:` key,
minted by `avp binding new`) instead of relying on salt derivation. These
tests cover the four layers:

  * parser — format-gated acceptance, fail-loud rejection, back-compat;
  * mint — CSPRNG shape;
  * runtime — global uniqueness fail-closed, attribution map;
  * env / cli / addon — the stored placeholder is what surfaces end-to-end.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.cli.env import build_export_lines
from kow.cli.main import main
from kow.notes_binding import (
    InvalidBinding,
    ParsedBinding,
    parse_notes_binding,
    stored_placeholder_from_note,
)
from kow.placeholders import (
    STORED_PLACEHOLDER_RE,
    derive_placeholder,
    mint_placeholder,
)
from kow.runtime_bindings import resolve_runtime_bindings
from tests.fakes import FakeNotesListBackend as _FakeNotesListBackend

_SALT = b"\x0b" * 32
_DERIVED_FALLBACK = "avp-PLACEHOLDER-derivedfallbackaaaaaaaaaaa"
# A syntactically valid stored placeholder (25-char lowercase-base32 tail,
# >= the 21-char floor), fixed rather than minted so assertions are deterministic.
_STORED = "avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p"


def _parse(note: str, name: str = "SECRET"):
    return parse_notes_binding(secret_name=name, placeholder=_DERIVED_FALLBACK, note=note)


# ── parser ──────────────────────────────────────────────────────────────────


def test_valid_stored_placeholder_wins_over_derived():
    note = f"# avp-binding\nhost: api.example.com\nplaceholder: {_STORED}\n"
    result = _parse(note)
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _STORED


def test_note_without_placeholder_keeps_derived():
    result = _parse("# avp-binding\nhost: api.example.com\n")
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _DERIVED_FALLBACK


def test_wrong_prefix_rejected():
    note = (
        "# avp-binding\nhost: api.example.com\nplaceholder: my-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m\n"
    )
    result = _parse(note)
    assert isinstance(result, InvalidBinding)
    assert "placeholder" in result.diagnostic


def test_illegal_charset_rejected():
    # Uppercase + underscore are outside the lowercase-base32 alphabet.
    note = (
        "# avp-binding\nhost: api.example.com\n"
        "placeholder: avp-PLACEHOLDER-ABC_DEF_GHI_JKL_MNO_PQRS\n"
    )
    assert isinstance(_parse(note), InvalidBinding)


def test_short_tail_rejected():
    note = "# avp-binding\nhost: api.example.com\nplaceholder: avp-PLACEHOLDER-a2b3c4\n"
    assert isinstance(_parse(note), InvalidBinding)


def test_non_string_placeholder_rejected():
    note = "# avp-binding\nhost: api.example.com\nplaceholder: 12345\n"
    result = _parse(note)
    assert isinstance(result, InvalidBinding)
    assert "placeholder" in result.diagnostic


def test_stored_placeholder_in_multihost_note():
    note = (
        "# avp-binding\n"
        "host: [api.example.com, cdn.example.com]\n"
        f"placeholder: {_STORED}\n"
        'format: "Bearer {secret}"\n'
    )
    result = _parse(note)
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _STORED
    assert len(result.spec.bindings) == 2


def test_bare_host_shorthand_still_derives():
    result = _parse("# avp-binding\napi.example.com\n")
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _DERIVED_FALLBACK


def test_indented_note_body_parses():
    # Hand-pasted notes are often uniformly indented (copied from a rendered
    # block). Body indented 2 spaces under a col-0 marker must still bind.
    note = (
        "# avp-binding\n"
        "  host: api.example.com\n"
        f"  placeholder: {_STORED}\n"
        "  header: Authorization\n"
        '  format: "Bearer {secret}"\n'
    )
    result = _parse(note)
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _STORED
    assert result.spec.bindings[0].host == "api.example.com"


def test_tab_indented_note_body_parses():
    # Raw YAML rejects tab indentation; the dedent normalization must rescue
    # a uniformly tab-indented body.
    note = f"# avp-binding\n\thost: api.example.com\n\tplaceholder: {_STORED}\n"
    result = _parse(note)
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == _STORED


def test_inconsistent_indentation_still_fails_loud():
    note = f"# avp-binding\nhost: api.example.com\n    placeholder: {_STORED}\n"
    assert isinstance(_parse(note), InvalidBinding)


# ── stored_placeholder_from_note helper ─────────────────────────────────────


def test_helper_extracts_valid_stored():
    note = f"# avp-binding\nhost: api.example.com\nplaceholder: {_STORED}\n"
    assert stored_placeholder_from_note(note, secret_name="K") == _STORED


def test_helper_none_for_unmarked_missing_or_invalid():
    assert stored_placeholder_from_note(None, secret_name="K") is None
    assert stored_placeholder_from_note("just a human description", secret_name="K") is None
    assert (
        stored_placeholder_from_note("# avp-binding\nhost: api.example.com\n", secret_name="K")
        is None
    )
    assert (
        stored_placeholder_from_note(
            "# avp-binding\nhost: api.example.com\nplaceholder: weak\n", secret_name="K"
        )
        is None
    )


# ── mint ────────────────────────────────────────────────────────────────────


def test_mint_matches_stored_regex():
    assert STORED_PLACEHOLDER_RE.match(mint_placeholder())


def test_two_mints_differ():
    assert mint_placeholder() != mint_placeholder()


# ── runtime uniqueness + attribution ────────────────────────────────────────


def _resolve(secrets: dict[str, tuple[str, str | None]]):
    return resolve_runtime_bindings(
        backend=_FakeNotesListBackend(secrets),
        binding_source="notes",
        install_salt=_SALT,
        file_config=None,
    )


def test_stored_placeholder_attributed_and_spec_carries_it():
    note = f"# avp-binding\nhost: api.example.com\nplaceholder: {_STORED}\n"
    resolved = _resolve({"ACME": ("real", note)})
    spec, _src, _comp = resolved.specs["ACME"]
    assert spec.placeholder == _STORED
    assert resolved.placeholder_to_name[_STORED] == "ACME"
    # The derived placeholder stays attributable (a stale consumer fails
    # closed with a named secret, not an anonymous string).
    assert resolved.placeholder_to_name[derive_placeholder("ACME", _SALT)] == "ACME"


def test_stored_stored_collision_drops_both():
    note = f"# avp-binding\nhost: api.example.com\nplaceholder: {_STORED}\n"
    note2 = f"# avp-binding\nhost: api2.example.com\nplaceholder: {_STORED}\n"
    resolved = _resolve({"A_ONE": ("v1", note), "B_TWO": ("v2", note2)})
    assert "A_ONE" not in resolved.specs
    assert "B_TWO" not in resolved.specs
    assert "A_ONE" in resolved.invalid and "B_TWO" in resolved.invalid
    # Diagnostic names both conflicting secrets.
    assert "A_ONE" in resolved.invalid["A_ONE"] and "B_TWO" in resolved.invalid["A_ONE"]


def test_stored_superstring_of_derived_drops_thief_only():
    # C1 (cross-vendor review): an OVERLAPPING (not equal) stored placeholder
    # must drop per-secret here — otherwise the merge-level substring
    # validator raises and fails the whole configure() (metadata-write DoS).
    victim_derived = derive_placeholder("VICTIM", _SALT)
    thief_note = f"# avp-binding\nhost: api.example.com\nplaceholder: {victim_derived}aa\n"
    resolved = _resolve(
        {
            "VICTIM": ("v1", "# avp-binding\nhost: api2.example.com\n"),
            "THIEF": ("v2", thief_note),
        }
    )
    assert "THIEF" not in resolved.specs
    assert "VICTIM" in resolved.specs
    assert "substring" in resolved.invalid["THIEF"]
    # The dropped stored claim stays attributable, never injectable.
    assert resolved.placeholder_to_name[victim_derived + "aa"] == "THIEF"


def test_stored_stored_overlap_drops_both():
    note_short = f"# avp-binding\nhost: api.example.com\nplaceholder: {_STORED}\n"
    note_long = f"# avp-binding\nhost: api2.example.com\nplaceholder: {_STORED}a2\n"
    resolved = _resolve({"A_ONE": ("v1", note_short), "B_TWO": ("v2", note_long)})
    assert "A_ONE" not in resolved.specs and "B_TWO" not in resolved.specs
    assert "A_ONE" in resolved.invalid and "B_TWO" in resolved.invalid


def test_stored_colliding_with_file_placeholder_drops_stored_only(tmp_path):
    # `both` mode: the file source (root-owned config) is a legitimate
    # claimant; a note storing the same placeholder drops alone.
    from kow.config import load_config

    file_ph = "avp-PLACEHOLDER-ffffffffffffffffffffffff"
    config_yaml = f"""
version: 1
secrets:
  FILE_SEC:
    placeholder: "{file_ph}"
    inject:
      header: "Authorization"
      format: "Bearer {{FILE_SEC}}"
    bindings:
      - host: "files.example.com"
audit:
  path: {tmp_path / "a.jsonl"}
binding_source: both
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(config_yaml)
    file_config = load_config(str(p))
    thief_note = f"# avp-binding\nhost: api.example.com\nplaceholder: {file_ph}\n"
    resolved = resolve_runtime_bindings(
        backend=_FakeNotesListBackend({"THIEF": ("v", thief_note)}),
        binding_source="both",
        install_salt=_SALT,
        file_config=file_config,
    )
    assert "THIEF" not in resolved.specs
    assert "FILE_SEC" in resolved.specs
    assert "FILE_SEC" in resolved.invalid["THIEF"]


def test_stored_colliding_with_other_secrets_derived_is_dropped():
    victim_derived = derive_placeholder("VICTIM", _SALT)
    thief_note = f"# avp-binding\nhost: api.example.com\nplaceholder: {victim_derived}\n"
    resolved = _resolve(
        {
            "VICTIM": ("v1", "# avp-binding\nhost: api2.example.com\n"),
            "THIEF": ("v2", thief_note),
        }
    )
    assert "THIEF" not in resolved.specs
    assert "VICTIM" in resolved.specs
    assert "VICTIM" in resolved.invalid["THIEF"]
    # The contested string attributes to its derived owner, never the thief.
    assert resolved.placeholder_to_name[victim_derived] == "VICTIM"


# ── avp env ─────────────────────────────────────────────────────────────────


def test_env_prefers_stored_placeholder():
    lines, skipped = build_export_lines(["ACME"], _SALT, stored={"ACME": _STORED})
    assert lines == [f"export ACME='{_STORED}'"]
    assert skipped == []


def test_env_derives_for_legacy_secrets():
    lines, _ = build_export_lines(["LEGACY"], _SALT)
    assert lines == [f"export LEGACY='{derive_placeholder('LEGACY', _SALT)}'"]


def test_env_degrades_to_derived_when_notes_unreadable(tmp_path, monkeypatch, capsys):
    import kow.backends as backends_mod
    import kow.config as config_mod
    from kow.cli.env import run_env

    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
secrets: {{}}
binding_source: notes
install_salt_path: {salt_path}
audit:
  path: {tmp_path / "a.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    backend = _FakeNotesListBackend({"ACME": ("v", None)})
    monkeypatch.setattr(config_mod, "build_backend", lambda _cfg: (backend, None))

    def _boom(_backend):
        raise RuntimeError("boom")

    monkeypatch.setattr(backends_mod, "list_secret_notes", _boom)
    code = run_env(config_path=str(config_path), print_only=True)
    captured = capsys.readouterr()
    assert code == 0
    assert "boom" in captured.err and "derived placeholders only" in captured.err
    assert f"export ACME='{derive_placeholder('ACME', _SALT)}'" in captured.out


# ── avp binding new ─────────────────────────────────────────────────────────


def _run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_binding_new_mints_placeholder_by_default(capsys):
    code, out, err = _run(
        ["binding", "new", "--host", "api.stripe.com", "--name", "STRIPE_KEY"], capsys
    )
    assert code == 0
    ph_lines = [ln for ln in out.splitlines() if ln.startswith("placeholder: ")]
    assert len(ph_lines) == 1
    minted = ph_lines[0].removeprefix("placeholder: ")
    assert STORED_PLACEHOLDER_RE.match(minted)
    # Round-trip through the daemon parser: the stored value is the spec's.
    result = parse_notes_binding(secret_name="STRIPE_KEY", placeholder=_DERIVED_FALLBACK, note=out)
    assert isinstance(result, ParsedBinding)
    assert result.spec.placeholder == minted
    # Consumer wiring hint on stderr, stdout stays a pure paste artifact.
    assert f"export STRIPE_KEY='{minted}'" in err


def test_binding_new_no_placeholder_flag_keeps_legacy(capsys):
    code, out, err = _run(
        ["binding", "new", "--host", "api.stripe.com", "--no-placeholder"], capsys
    )
    assert code == 0
    assert "placeholder:" not in out
    assert "export" not in err


def test_binding_new_gsm_embeds_placeholder(capsys):
    code, out, _ = _run(
        ["binding", "new", "--host", "api.example.com", "--name", "K", "--backend", "gsm"],
        capsys,
    )
    assert code == 0
    # Newly minted placeholders carry the `kow-` prefix; `avp-` ones are still
    # accepted on read but are no longer emitted. See test_rename_backcompat.
    assert "placeholder: kow-PLACEHOLDER-" in out.replace("\\n", "\n")


# ── addon end-to-end ────────────────────────────────────────────────────────


def _make_request(host: str, headers: dict[str, str]) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.path = "/v1/messages"
    flow.request.method = "POST"
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


def test_daemon_injects_real_secret_under_stored_placeholder(tmp_path: Path) -> None:
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
secrets: {{}}
binding_source: notes
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    )
    real = "sk-ant-REAL-value"
    note = f"# avp-binding\nhost: api.anthropic.com\nplaceholder: {_STORED}\n"
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(config_path),
        backend_override=_FakeNotesListBackend({"ANTHROPIC": (real, note)}),
    )
    flow = _make_request("api.anthropic.com", {"x-api-key": _STORED})
    addon.requestheaders(flow)
    assert flow.request.headers["x-api-key"] == real
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln]
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["secret_name"] == "ANTHROPIC"
    assert real not in audit_path.read_text()


def test_overlapping_stored_placeholder_does_not_brick_configure(tmp_path: Path) -> None:
    """C1 regression: a crafted stored placeholder overlapping another
    secret's placeholder must NOT fail the whole configure() (the merge
    validator raises on substring overlaps) — the thief drops alone and the
    victim keeps injecting."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
secrets: {{}}
binding_source: notes
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    )
    real = "sk-ant-REAL-value"
    victim_derived = derive_placeholder("ANTHROPIC", _SALT)
    thief_note = f"# avp-binding\nhost: api.example.com\nplaceholder: {victim_derived}aa\n"
    addon = AgentVaultProxyAddon()
    # Would raise PlaceholderCollisionError/ValueError pre-fix; must not now.
    addon.configure_from_path(
        str(config_path),
        backend_override=_FakeNotesListBackend(
            {
                "ANTHROPIC": (real, "# avp-binding\nhost: api.anthropic.com"),
                "THIEF": ("stolen", thief_note),
            }
        ),
    )
    flow = _make_request("api.anthropic.com", {"x-api-key": victim_derived})
    addon.requestheaders(flow)
    assert flow.request.headers["x-api-key"] == real
