"""Backward-compat guarantees for the agent-vault-proxy -> keys-on-the-wire rename.

The rename keeps every EXISTING deployment injecting with zero migration
(ADR-0045): config paths and the systemd unit are unchanged, and the
note/annotation marker DEFAULTS to `# kow-binding` while still accepting the old
`# avp-binding` (both parse identically).

Placeholders are now split, because minting and derivation have different
compatibility properties:

  * MINTING emits `kow-PLACEHOLDER-`. A minted placeholder is stored in the
    vault note and read back from it, so the daemon matches whatever string is
    there. New bindings get `kow-`; every `avp-` one already in a vault keeps
    parsing because recognition accepts both eras.
  * DERIVATION still emits `avp-PLACEHOLDER-`. It is recomputed independently by
    `kow env` and the daemon and stored nowhere, so flipping it would make the
    daemon derive `kow-…` while an already-written `~/.config/kow/env` still
    exported `avp-…`, and injection would stop silently. That flip needs its own
    migration.

Also locked here:

  * the deprecated `AVP_CONFDIR` env var still works, with a warning, and
    resolves the SAME salt path, so derivation is identical;
  * `KOW_CONFDIR` + `AVP_CONFDIR` set to DIFFERENT paths fails loud (never
    silently re-derives placeholders);
  * the deprecated `avp` CLI alias is still wired.

2.0.0 flips derivation to `kow-` (with a migration) and drops the `avp` CLI
alias and `AVP_CONFDIR` fallback.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

from kow.placeholders import (
    ACCEPTED_PREFIXES,
    DERIVE_PREFIX,
    LEGACY_PREFIX,
    MINT_PREFIX,
    STORED_PLACEHOLDER_RE,
    InstallSaltError,
    _confdir_from_env,
    derive_placeholder,
    mint_placeholder,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_minting_uses_the_kow_prefix() -> None:
    assert MINT_PREFIX == "kow-PLACEHOLDER-"
    ph = mint_placeholder()
    assert ph.startswith(MINT_PREFIX)
    assert STORED_PLACEHOLDER_RE.match(ph)


def test_legacy_avp_placeholders_are_still_recognised() -> None:
    """The whole point of splitting mint from recognition: an `avp-` placeholder
    already pasted into a vault note must keep parsing after the upgrade, or
    existing installs silently stop injecting."""
    assert LEGACY_PREFIX == "avp-PLACEHOLDER-"
    legacy = LEGACY_PREFIX + "a2b3c4d5e6f7g2h3j4k5m6n7p"
    assert STORED_PLACEHOLDER_RE.match(legacy)
    assert legacy.startswith(ACCEPTED_PREFIXES)


def test_derivation_still_uses_the_avp_prefix() -> None:
    """Derived placeholders are stored nowhere and recomputed on both sides, so
    this one is NOT safe to flip without a migration. Locked deliberately."""
    assert DERIVE_PREFIX == "avp-PLACEHOLDER-"
    derived = derive_placeholder("SOME_SECRET", b"\x01" * 32)
    assert derived.startswith(DERIVE_PREFIX)
    assert STORED_PLACEHOLDER_RE.match(derived)


def test_both_eras_satisfy_the_same_shape() -> None:
    """Equal length matters: config_models' >=24-char and PLACEHOLDER-marker
    invariants must hold identically whichever prefix a placeholder carries."""
    assert len(MINT_PREFIX) == len(LEGACY_PREFIX)
    for prefix in ACCEPTED_PREFIXES:
        assert "PLACEHOLDER" in prefix
        assert len(prefix + "a" * 21) >= 24


def test_kow_confdir_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KOW_CONFDIR", "/same")
    monkeypatch.delenv("AVP_CONFDIR", raising=False)
    assert _confdir_from_env() == "/same"


def test_avp_confdir_still_works_but_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KOW_CONFDIR", raising=False)
    monkeypatch.setenv("AVP_CONFDIR", "/old")
    with pytest.warns(DeprecationWarning):
        assert _confdir_from_env() == "/old"


def test_both_confdir_same_path_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KOW_CONFDIR", "/same")
    monkeypatch.setenv("AVP_CONFDIR", "/same")
    assert _confdir_from_env() == "/same"


def test_both_confdir_same_dir_trailing_slash_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # /etc/kow and /etc/kow/ are the SAME directory — must not trip the guard.
    monkeypatch.setenv("KOW_CONFDIR", "/etc/kow")
    monkeypatch.setenv("AVP_CONFDIR", "/etc/kow/")
    assert _confdir_from_env() == "/etc/kow"


def test_both_confdir_different_paths_fails_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    # Silently preferring one would re-derive every placeholder and brick injection.
    monkeypatch.setenv("KOW_CONFDIR", "/new")
    monkeypatch.setenv("AVP_CONFDIR", "/old")
    with pytest.raises(InstallSaltError):
        _confdir_from_env()


def test_no_confdir_env_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KOW_CONFDIR", raising=False)
    monkeypatch.delenv("AVP_CONFDIR", raising=False)
    assert _confdir_from_env() is None


def test_deprecated_cli_aliases_still_wired() -> None:
    scripts = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text())["project"]["scripts"]
    # canonical
    assert scripts["kow"] == "kow.cli.main:main"
    assert scripts["keys-on-the-wire"] == "kow.__main__:main"
    # deprecated aliases (removed in 2.0.0)
    assert scripts["avp"] == "kow.cli.main:main"
    assert scripts["agent-vault-proxy"] == "kow.__main__:main"


def test_kow_binding_marker_parses_as_binding() -> None:
    """`# kow-binding` (the new default marker) selects a binding."""
    from kow.notes_binding import ParsedBinding, parse_notes_binding

    result = parse_notes_binding(
        secret_name="SOME_KEY",
        placeholder="avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p",
        note="# kow-binding\nhost: api.example.com\n",
    )
    assert isinstance(result, ParsedBinding)


def test_avp_binding_marker_still_parses_as_binding() -> None:
    """`# avp-binding` (the deprecated alias) still selects a binding (back-compat)."""
    from kow.notes_binding import ParsedBinding, parse_notes_binding

    result = parse_notes_binding(
        secret_name="SOME_KEY",
        placeholder="avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p",
        note="# avp-binding\nhost: api.example.com\n",
    )
    assert isinstance(result, ParsedBinding)


def test_gsm_reads_both_binding_annotation_keys() -> None:
    """GSM reads the canonical `kow-binding` annotation and the `avp-binding` alias."""
    from kow.backends.gsm import _read_binding_annotation

    assert _read_binding_annotation({"kow-binding": "api.example.com"}) == "api.example.com"
    assert _read_binding_annotation({"avp-binding": "api.example.com"}) == "api.example.com"
    assert _read_binding_annotation({"other": "x"}) is None
    assert _read_binding_annotation(None) is None
