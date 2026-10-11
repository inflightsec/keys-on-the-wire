"""A vault note silently shadowing a file binding — the Verda trap.

Replicates the 2026-09-20 incident. Verda's token endpoint ignores the
`Authorization` header and wants credentials in the request body, so the
notes-only Basic binding was inert and had to be replaced with a file-source
`oauth2_client_credentials` injector. Writing that injector was not enough: the
old note was still in the vault, and under `binding_source: both` a note wins
over a file binding for the same secret. The file injector never ran.

Because kow is fail-closed, the symptom was silence. Nothing in the logs named
the stale note. These tests pin the two halves of the fix:

  1. notes stay first-class — a note still wins, which is the documented and
     intended precedence, and nothing here weakens it;
  2. it is no longer silent — the override is named at load, and named LOUDER
     when the note downgrades a richer injector to static header substitution,
     which is exactly the Verda shape.
"""

from __future__ import annotations

import logging
from pathlib import Path

from kow.addon import AgentVaultProxyAddon
from tests.fakes import FakeNotesListBackend

_SALT = b"\x0c" * 32
_NOTE_PH = "avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p"


def _config(tmp_path: Path, *, file_inject: str) -> Path:
    """A file binding for VERDA, plus whatever the note later says. `file_inject`
    is the YAML block for the injector under test."""
    salt = tmp_path / "install-salt"
    salt.write_bytes(_SALT)
    salt.chmod(0o600)
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: both
install_salt_path: {salt}
unmatched_destination_policy: forward_unmodified
secrets:
  VERDA:
    placeholder: "avp-PLACEHOLDER-filesecretaaaaaaaaaaaaaaaa"
{file_inject}
    bindings:
      - host: api.verda.example
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    return cfg


_HEADER_INJECT = """    inject:
      header: Authorization
      format: "Bearer {VERDA}\""""

_OAUTH_INJECT = """    inject:
      type: oauth2_client_credentials
      token_url: https://api.verda.example/oauth2/token
      client_id_secret: VERDA_ID
      client_secret_secret: VERDA_SECRET
      header: Authorization
      format: "Bearer {access_token}\""""

_NOTE = (
    "# kow-binding\n"
    "host: api.verda.example\n"
    f"placeholder: {_NOTE_PH}\n"
    "header: Authorization\n"
    'format: "Basic {secret}"\n'
)


def _load(tmp_path: Path, cfg: Path, note: str | None) -> AgentVaultProxyAddon:
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(cfg), backend_override=FakeNotesListBackend({"VERDA": ("real-value", note)})
    )
    return addon


def test_note_still_wins_over_the_file_binding(tmp_path: Path) -> None:
    """Notes stay first-class. This is the documented precedence and the fix
    must not quietly reverse it."""
    addon = _load(tmp_path, _config(tmp_path, file_inject=_HEADER_INJECT), _NOTE)
    assert addon.config is not None
    assert addon.config.secrets["VERDA"].placeholder == _NOTE_PH


def test_note_overriding_a_same_type_file_binding_is_named(tmp_path: Path, caplog) -> None:
    """Like-for-like override: worth naming, rarely a mistake."""
    with caplog.at_level(logging.WARNING):
        _load(tmp_path, _config(tmp_path, file_inject=_HEADER_INJECT), _NOTE)
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert "VERDA" in msg
    assert "overriding the file binding" in msg


def test_note_downgrading_a_richer_injector_is_named_loudly(tmp_path: Path, caplog) -> None:
    """THE Verda shape: a header-only note silently replacing an
    `oauth2_client_credentials` injector. A note cannot express that injector,
    so the configured capability is gone. The operator must be told which
    injector stopped running, and that deleting the note is the fix."""
    with caplog.at_level(logging.WARNING):
        _load(tmp_path, _config(tmp_path, file_inject=_OAUTH_INJECT), _NOTE)
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert "VERDA" in msg
    assert "DIFFERENT injector types" in msg
    assert "oauth2_client_credentials" in msg
    assert "NOT active" in msg
    assert "DELETE the note" in msg


def test_no_warning_when_the_file_binding_stands_alone(tmp_path: Path, caplog) -> None:
    """Control: a file binding with no note must not produce shadow noise, or
    the warning becomes background hum and stops being read."""
    with caplog.at_level(logging.WARNING):
        _load(tmp_path, _config(tmp_path, file_inject=_OAUTH_INJECT), None)
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert "overriding the file binding" not in msg


def test_no_warning_for_a_note_only_secret(tmp_path: Path, caplog) -> None:
    """Control: the notes-first happy path. A note with no file binding to
    shadow is the normal way to onboard a credential and must stay silent."""
    salt = tmp_path / "install-salt"
    salt.write_bytes(_SALT)
    salt.chmod(0o600)
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: both
install_salt_path: {salt}
unmatched_destination_policy: forward_unmodified
secrets: {{}}
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    with caplog.at_level(logging.WARNING):
        addon = _load(tmp_path, cfg, _NOTE)
    assert addon.config is not None
    assert "VERDA" in addon.config.secrets
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert "overriding the file binding" not in msg


def test_warns_when_deleting_the_note_would_widen_access(tmp_path: Path, caplog) -> None:
    """Oracle review 2026-09-24: "delete the note" is only safe advice if the
    file binding is at least as narrow. A note that narrows scope is the normal
    case, so following the advice blindly can broaden the credential's reach."""
    salt = tmp_path / "install-salt"
    salt.write_bytes(_SALT)
    salt.chmod(0o600)
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: both
install_salt_path: {salt}
unmatched_destination_policy: forward_unmodified
secrets:
  VERDA:
    placeholder: "avp-PLACEHOLDER-filesecretaaaaaaaaaaaaaaaa"
{_HEADER_INJECT}
    bindings:
      - host: api.verda.example
      - host: admin.verda.example
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    with caplog.at_level(logging.WARNING):
        _load(tmp_path, cfg, _NOTE)  # note pins only api.verda.example
    msg = "\n".join(r.getMessage() for r in caplog.records)
    assert "NARROWER than the file binding" in msg
    assert "admin.verda.example" in msg
