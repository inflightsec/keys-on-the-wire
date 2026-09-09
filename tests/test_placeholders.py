"""Deterministic salted placeholder derivation (ADR-0011 amendment,
"Placeholder origin").

A placeholder is derived as::

    avp-PLACEHOLDER-<base32(HMAC-SHA256(install_salt, secret_name)).lower()[:N]>

with N chosen so the derived string satisfies config.py's placeholder
invariants (>=24 chars, contains "PLACEHOLDER", printable) AND carries
>=104 bits of entropy in the truncated tail so collisions across a
realistic secret-name set are negligible.

The per-install ``install_salt`` (random 32 bytes, generated once at
``avp setup``, stored 0600) makes placeholders NOT globally precomputable:
without the salt an attacker cannot pre-derive the placeholder for a known
secret name.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from kow.config import (
    _PLACEHOLDER_MIN_LEN,
    Config,
    validate_placeholder_invariants,
)
from kow.placeholders import (
    DERIVE_PREFIX,
    InstallSaltError,
    PlaceholderCollisionError,
    derive_placeholder,
    derive_placeholder_map,
    load_or_create_install_salt,
    resolve_install_salt_path,
)

_SALT = b"\x00" * 32
_SALT_B = b"\x11" * 32


# --------------------------------------------------------------------------
# derive_placeholder — shape + invariants
# --------------------------------------------------------------------------


def test_derive_placeholder_has_avp_prefix() -> None:
    # Derivation deliberately still emits `avp-` — see test_rename_backcompat.
    # Minting is the half that flipped to `kow-`.
    ph = derive_placeholder("ANTHROPIC_API_KEY", _SALT)
    assert ph.startswith(DERIVE_PREFIX)


def test_derive_placeholder_satisfies_config_invariants() -> None:
    """The derived placeholder must pass every check config.py enforces:
    >= min length, carries an accepted marker, printable, unique."""
    ph = derive_placeholder("ANTHROPIC_API_KEY", _SALT)
    assert len(ph) >= _PLACEHOLDER_MIN_LEN
    assert ph.isprintable()
    # No raise = passes the full invariant set (marker, length, uniqueness).
    validate_placeholder_invariants({"ANTHROPIC_API_KEY": ph})


def test_derive_placeholder_tail_is_lowercase_base32_no_padding() -> None:
    ph = derive_placeholder("ANTHROPIC_API_KEY", _SALT)
    tail = ph[len(DERIVE_PREFIX) :]
    # base32 alphabet is A-Z2-7; lowercased -> a-z2-7. No '=' padding.
    assert "=" not in tail
    assert all(c in "abcdefghijklmnopqrstuvwxyz234567" for c in tail), tail


def test_derive_placeholder_tail_has_at_least_104_bits() -> None:
    """>=104 bits of entropy => >=21 base32 chars (21 * 5 = 105 bits)."""
    ph = derive_placeholder("ANTHROPIC_API_KEY", _SALT)
    tail = ph[len(DERIVE_PREFIX) :]
    assert len(tail) >= 21


def test_derive_placeholder_is_deterministic_for_same_salt() -> None:
    a = derive_placeholder("FOO", _SALT)
    b = derive_placeholder("FOO", _SALT)
    assert a == b


def test_derive_placeholder_differs_per_secret_name() -> None:
    a = derive_placeholder("FOO", _SALT)
    b = derive_placeholder("BAR", _SALT)
    assert a != b


def test_derive_placeholder_salt_makes_it_not_globally_precomputable() -> None:
    """Same secret name, different install salt => different placeholder.
    This is the property that prevents an attacker who knows only the
    secret name from precomputing the placeholder."""
    a = derive_placeholder("FOO", _SALT)
    b = derive_placeholder("FOO", _SALT_B)
    assert a != b


def test_derive_placeholder_rejects_empty_salt() -> None:
    with pytest.raises(ValueError, match="salt"):
        derive_placeholder("FOO", b"")


def test_derive_placeholder_rejects_short_salt() -> None:
    """A salt shorter than 32 bytes is a misuse (weakens the keyed HMAC)."""
    with pytest.raises(ValueError, match="salt"):
        derive_placeholder("FOO", b"\x00" * 8)


# --------------------------------------------------------------------------
# derive_placeholder_map — collision detection across a name set
# --------------------------------------------------------------------------


def test_derive_placeholder_map_round_trips_names() -> None:
    names = ["ANTHROPIC", "OPENAI", "GITHUB_PAT"]
    mapping = derive_placeholder_map(names, _SALT)
    assert set(mapping) == set(names)
    # All distinct.
    assert len(set(mapping.values())) == len(names)


def test_derive_placeholder_map_satisfies_config_uniqueness(tmp_path) -> None:
    """A full Config built from the derived placeholders must load — i.e.
    the derived set satisfies the unique + no-substring-overlap invariants
    config.py enforces in validate_placeholders."""
    names = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_PAT", "STRIPE"]
    mapping = derive_placeholder_map(names, _SALT)
    secrets = {
        name: {
            "placeholder": ph,
            "inject": {"header": "Authorization", "format": "Bearer {" + name + "}"},
            "bindings": [{"host": "api.example.com"}],
        }
        for name, ph in mapping.items()
    }
    cfg = Config.model_validate({"secrets": secrets, "audit": {"path": str(tmp_path / "a.jsonl")}})
    assert set(cfg.secrets) == set(names)


def test_derive_placeholder_map_raises_on_collision(monkeypatch) -> None:
    """If two distinct names derive the same placeholder (forced here by
    stubbing the digest), the map builder raises a hard error naming BOTH
    conflicting secrets — never silently coalesces."""
    import kow.placeholders as mod

    # Force a constant tail so every name collides.
    monkeypatch.setattr(mod, "_derive_tail", lambda name, salt: "a" * 21)
    with pytest.raises(PlaceholderCollisionError) as exc:
        derive_placeholder_map(["FOO", "BAR"], _SALT)
    msg = str(exc.value)
    assert "FOO" in msg
    assert "BAR" in msg


# --------------------------------------------------------------------------
# install salt — load-or-create, 0600
# --------------------------------------------------------------------------


def test_load_or_create_install_salt_creates_32_bytes_0600(tmp_path) -> None:
    salt_path = tmp_path / "install-salt"
    salt = load_or_create_install_salt(salt_path)
    assert len(salt) == 32
    assert salt_path.exists()
    mode = stat.S_IMODE(os.stat(salt_path).st_mode)
    assert mode == 0o600, oct(mode)


def test_load_or_create_install_salt_is_stable_across_calls(tmp_path) -> None:
    salt_path = tmp_path / "install-salt"
    first = load_or_create_install_salt(salt_path)
    second = load_or_create_install_salt(salt_path)
    assert first == second


def test_load_or_create_install_salt_creates_parent_dir(tmp_path) -> None:
    salt_path = tmp_path / "nested" / "dir" / "install-salt"
    salt = load_or_create_install_salt(salt_path)
    assert len(salt) == 32
    assert salt_path.exists()


def test_load_or_create_install_salt_rejects_corrupt_short_file(tmp_path) -> None:
    """A salt file that exists but is too short is a corruption/tamper
    signal — fail loud, do not silently regenerate (regenerating would
    invalidate every already-derived placeholder)."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(b"short")
    with pytest.raises(ValueError, match="salt"):
        load_or_create_install_salt(salt_path)


def test_load_or_create_install_salt_rejects_group_or_world_readable_file(tmp_path) -> None:
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(os.urandom(32))
    salt_path.chmod(0o644)
    with pytest.raises(ValueError, match="insecure mode"):
        load_or_create_install_salt(salt_path)


def test_load_or_create_install_salt_rejects_wrong_owner(tmp_path, monkeypatch) -> None:
    """CI can't chown to a foreign uid, so simulate the current euid instead."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(os.urandom(32))
    salt_path.chmod(0o600)
    current_uid = os.stat(salt_path).st_uid
    if current_uid == 0:
        pytest.skip("temp file is root-owned in this environment")
    monkeypatch.setattr(os, "geteuid", lambda: current_uid + 1)
    with pytest.raises(ValueError, match="owned by uid"):
        load_or_create_install_salt(salt_path)


def test_load_or_create_install_salt_root_run_gets_hint(tmp_path, monkeypatch) -> None:
    """Run-as-root against a daemon-owned salt: the error is an InstallSaltError
    carrying a hint that names the likely cause (ran as root) plus the fix."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(os.urandom(32))
    salt_path.chmod(0o600)
    owner_uid = os.stat(salt_path).st_uid
    if owner_uid == 0:
        pytest.skip("temp file is root-owned in this environment")
    # Simulate running as root (euid 0) while the salt is owned by another user.
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    with pytest.raises(InstallSaltError) as excinfo:
        load_or_create_install_salt(salt_path)
    hint = excinfo.value.hint
    assert hint is not None
    assert "root" in hint.lower()
    assert "sudo -u" in hint


def test_resolve_install_salt_path_prefers_explicit_then_confdir_then_home(
    tmp_path, monkeypatch
) -> None:
    explicit = tmp_path / "explicit-salt"
    confdir = tmp_path / "confdir"
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("KOW_CONFDIR", str(confdir))
    assert resolve_install_salt_path(explicit) == str(explicit)
    assert resolve_install_salt_path(None) == str(confdir / "install-salt")
    monkeypatch.delenv("KOW_CONFDIR")
    assert resolve_install_salt_path(None) == str(home / "install-salt")


def test_resolve_install_salt_path_raises_when_home_is_unavailable(monkeypatch) -> None:
    import kow.placeholders as mod

    monkeypatch.delenv("AVP_CONFDIR", raising=False)

    def _boom(_cls) -> Path:
        raise RuntimeError("no home")

    monkeypatch.setattr(mod.Path, "home", classmethod(_boom))
    with pytest.raises(RuntimeError, match="could not determine HOME"):
        resolve_install_salt_path(None)
