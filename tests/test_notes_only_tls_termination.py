"""A notes-only binding must make its host TLS-terminated (ADR-0026 + ADR-0011).

Regression cover for the reported failure mode "a notes-only binding is counted
injectable but never intercepted": a secret whose NOTE binds a host that appears
nowhere in ``bindings.yaml`` was believed to be tunnelled opaquely
(``tls_passthrough`` / ``unbound_destination``) so injection could never happen.

The interception decision is ``tls_clienthello`` -> ``destination_in_any_binding``
-> ``Config.secrets_for_host``, which reads the host index. The index is built at
config load from ``bindings.yaml`` and REBUILT by the notes activation after it
merges note-sourced specs (``handlers.py`` ``rebuild_host_index``). These tests
pin that rebuild on both publish paths — the cold load and the ADR-0032
background refresh — because a regression in either silently reverts a
notes-only host to an opaque tunnel, and the injectable tally would keep
claiming it was brokered.
"""

from __future__ import annotations

from pathlib import Path

from kow.addon import AgentVaultProxyAddon
from kow.policy import destination_in_any_binding
from tests.fakes import FakeNotesListBackend

_SALT = b"\x0b" * 32
_STORED = "avp-PLACEHOLDER-y6gdwanb5jinrnc5imrextpojq"
_NOTES_ONLY_HOST = "www.kaggle.com"
_FILE_HOST = "api.github.com"

_NOTE = (
    "# kow-binding\n"
    f"host: {_NOTES_ONLY_HOST}\n"
    f"placeholder: {_STORED}\n"
    "header: Authorization\n"
    'format: "Basic {secret}"\n'
)


def _write_config(tmp_path: Path) -> Path:
    """A config whose FILE side knows about `_FILE_HOST` and nothing else, so
    `_NOTES_ONLY_HOST` can only ever become bound via the note."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
binding_source: both
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
secrets:
  GITHUB_PAT:
    placeholder: "avp-PLACEHOLDER-filesecretaaaaaaaaaaaaaaaa"
    inject:
      header: Authorization
      format: "Bearer {{GITHUB_PAT}}"
    bindings:
      - host: {_FILE_HOST}
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    )
    return config_path


def test_notes_only_host_is_bound_after_cold_load(tmp_path: Path) -> None:
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(_write_config(tmp_path)),
        backend_override=FakeNotesListBackend(
            {"GITHUB_PAT": ("ghp_real", None), "KAGGLE_BASIC": ("kaggle_real", _NOTE)}
        ),
    )
    config = addon.config
    assert config is not None
    assert "KAGGLE_BASIC" in config.secrets
    # The whole point: bound purely by the note, no bindings.yaml entry.
    assert [n for n, _ in config.secrets_for_host(_NOTES_ONLY_HOST)] == ["KAGGLE_BASIC"]
    assert destination_in_any_binding(config, _NOTES_ONLY_HOST) is True


def test_notes_only_host_is_bound_after_background_refresh(tmp_path: Path) -> None:
    """ADR-0032 refresh path. A secret added to the vault AFTER startup must
    become bound without a restart, or the notes-first workflow needs a redeploy
    to take effect — which is exactly what it exists to avoid."""
    backend = FakeNotesListBackend({"GITHUB_PAT": ("ghp_real", None)})
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(_write_config(tmp_path)), backend_override=backend)

    config = addon.config
    assert config is not None
    assert destination_in_any_binding(config, _NOTES_ONLY_HOST) is False

    # Simulate the operator adding the secret in the vault UI after startup.
    backend._secrets["KAGGLE_BASIC"] = ("kaggle_real", _NOTE)
    addon.refresh_notes()

    refreshed = addon.config
    assert refreshed is not None
    assert "KAGGLE_BASIC" in refreshed.secrets
    assert destination_in_any_binding(refreshed, _NOTES_ONLY_HOST) is True


def test_unbound_host_stays_unbound(tmp_path: Path) -> None:
    """Fail-closed guard: making notes-only hosts bound must NOT widen
    termination to hosts nothing binds (ADR-0026)."""
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(_write_config(tmp_path)),
        backend_override=FakeNotesListBackend(
            {"GITHUB_PAT": ("ghp_real", None), "KAGGLE_BASIC": ("kaggle_real", _NOTE)}
        ),
    )
    config = addon.config
    assert config is not None
    assert destination_in_any_binding(config, "example.invalid") is False
    assert destination_in_any_binding(config, "kaggle.com") is False


def test_unmarked_note_does_not_bind_its_host(tmp_path: Path) -> None:
    """Fail-closed guard: a host-shaped but UNMARKED note is inert, so its host
    must not be terminated either."""
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(_write_config(tmp_path)),
        backend_override=FakeNotesListBackend(
            {"GITHUB_PAT": ("ghp_real", None), "KAGGLE_BASIC": ("kaggle_real", "www.kaggle.com")}
        ),
    )
    config = addon.config
    assert config is not None
    assert destination_in_any_binding(config, _NOTES_ONLY_HOST) is False
