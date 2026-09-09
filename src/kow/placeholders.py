"""Deterministic, salted placeholder derivation (ADR-0011 amendment).

Simple mode does NOT ask the operator to hand-author placeholder strings.
Instead the daemon and ``kow env`` both derive the SAME placeholder for a
secret name, so the env file the agent sees and the map the daemon enforces
agree without a second config file::

    avp-PLACEHOLDER-<base32(HMAC-SHA256(install_salt, secret_name)).lower()[:N]>

Design choices and why:

* **HMAC, not a bare hash.** The per-install ``install_salt`` is the HMAC
  key. Keying (rather than concatenating salt+name into a plain SHA-256)
  is the textbook construction for "derive an unpredictable-but-stable
  token from a known input under a secret." An attacker who knows the
  secret NAME but not the salt cannot precompute the placeholder, so a
  placeholder leaking on the wire/env doesn't reveal which BWS secret it
  maps to without the salt.
* **base32, lowercased, no padding.** base32's alphabet (A-Z2-7) is
  case-insensitive-safe and shell/env-safe: no ``/ + =`` (base64) and no
  characters that need quoting in ``export NAME='...'``. Lowercasing keeps
  it visually distinct from real ALL-CAPS tokens. ``=`` padding is
  stripped because it carries no entropy and would need quoting.
* **N = 21 base32 chars => 105 bits.** >=104 bits keeps the truncated-tail
  collision probability negligible for any realistic per-install secret
  set (birthday bound ~2^52 names before a 1e-9 collision chance). The
  full 37-char placeholder (16-char prefix + 21-char tail) comfortably
  exceeds config.py's >=24 char invariant and contains "PLACEHOLDER".

Collision handling: even at 105 bits a collision is *possible*, and a
silent coalesce would map two secrets to one placeholder (the daemon's
substring/uniqueness invariant would then reject the config, or worse,
inject the wrong secret). :func:`derive_placeholder_map` detects a
collision across the supplied name set and raises
:class:`PlaceholderCollisionError` listing BOTH conflicting names — a hard,
loud, fail-closed error, never a guess.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import warnings
from pathlib import Path

# 16 chars each. Both contain the "PLACEHOLDER" marker config.py requires, and
# both are the same length, so every downstream length invariant is unaffected
# by which one a placeholder carries.
#
# ADR-0045 (rename) originally kept ``avp-`` for BOTH minting and derivation.
# That is now split, because the two have different compatibility properties:
#
#   * MINTED placeholders (:func:`mint_placeholder`, ADR-0029) are written into
#     the vault note and read back from it, so the daemon matches whatever
#     string is stored. Changing what we mint touches only NEW bindings, and
#     old ones keep working as long as we still ACCEPT ``avp-``. Flipped.
#
#   * DERIVED placeholders (:func:`derive_placeholder`) are recomputed
#     independently by both ``kow env`` and the daemon and stored nowhere. The
#     daemon matches by ``spec.placeholder in value`` (policy.py), so flipping
#     the derived prefix would make the daemon derive ``kow-…`` while an
#     already-written ``~/.config/kow/env`` still exports ``avp-…``, and
#     injection would silently stop until the operator re-ran ``kow env``.
#     NOT flipped here; that needs its own migration.
#
# Recognition is deliberately wider than minting: anything that ASKS "is this a
# placeholder?" must accept both eras, or a legacy placeholder gets mistaken
# for a live credential.
MINT_PREFIX = "kow-PLACEHOLDER-"
LEGACY_PREFIX = "avp-PLACEHOLDER-"
ACCEPTED_PREFIXES = (MINT_PREFIX, LEGACY_PREFIX)

# What derivation still emits. Separate name so the two decisions above can
# move independently and a reader can see which is which.
DERIVE_PREFIX = LEGACY_PREFIX

# Back-compat alias for callers that mean "the prefix we emit today" (the CLI
# self-validation sentinels). Never use it to RECOGNISE a placeholder — use
# ACCEPTED_PREFIXES or STORED_PLACEHOLDER_RE for that.
PLACEHOLDER_PREFIX = MINT_PREFIX

# Truncated base32 tail length. 21 chars * 5 bits/char = 105 bits of
# entropy (>=104). Total placeholder length = 16 + 21 = 37 >= 24.
_TAIL_CHARS = 21

# Minimum acceptable install-salt length in bytes. HMAC-SHA256's security
# margin wants a key at least as long as the block/output size; we mandate
# 32 bytes (256 bits) to match the digest and to make a short/truncated
# salt file a detectable corruption signal rather than a silent weakening.
_SALT_BYTES = 32
_DEFAULT_SALT_BASENAME = "install-salt"

# Stored (note-carried) placeholders — ADR-0029. A note may pin its secret's
# placeholder explicitly (minted by `kow binding new`) instead of relying on
# the salt derivation above. The stored shape is deliberately IDENTICAL in
# alphabet and prefix to the derived one (prefix + lowercase-base32 tail) so:
#   * config.py's placeholder invariants (>=24 chars, PLACEHOLDER marker,
#     shell-metachar-free) hold by construction;
#   * consumers can't tell (and never need to care) which era minted theirs;
#   * the tail's minimum length (21 chars = 105 bits) keeps a hand-typed
#     low-entropy string ("token", "Bearer") structurally unrepresentable —
#     a weak placeholder can't match innocent traffic because it can't parse.
# Built from ACCEPTED_PREFIXES so the prefixes live in exactly one place. Both
# eras match: we mint ``kow-`` now, but every ``avp-`` placeholder already
# pasted into a vault note must keep parsing, or upgrading kow would silently
# stop injecting for existing users.
_PREFIX_ALT = "|".join(re.escape(p) for p in ACCEPTED_PREFIXES)
STORED_PLACEHOLDER_RE = re.compile(rf"^(?:{_PREFIX_ALT})[a-z2-7]{{21,64}}$")

# Minted tail length: 26 base32 chars = 130 bits from a 16-byte CSPRNG draw.
_MINT_TAIL_CHARS = 26


def mint_placeholder() -> str:
    """Mint a fresh random stored placeholder (ADR-0029).

    Uses the ``secrets`` CSPRNG — never derived from any name or salt, so a
    minted placeholder carries no linkable information and survives salt
    rotation and secret renames unchanged. Output always satisfies
    :data:`STORED_PLACEHOLDER_RE`.
    """
    tail = base64.b32encode(secrets.token_bytes(16)).decode("ascii").lower().rstrip("=")
    return MINT_PREFIX + tail[:_MINT_TAIL_CHARS]


class PlaceholderCollisionError(RuntimeError):
    """Two distinct secret names derived the same truncated placeholder.

    Raised by :func:`derive_placeholder_map`. The message lists every
    colliding name so the operator can rename one secret (or, in the
    astronomically unlikely event this fires legitimately, rotate the
    install salt). This is a hard startup failure by design — a silent
    coalesce could route the wrong real secret onto the wire.
    """


class InstallSaltError(ValueError):
    """The install salt can't be safely loaded (perms, ownership, or corruption).

    Subclasses :class:`ValueError` for backward compatibility with callers that
    already ``except ValueError``. Carries an optional ``hint`` — a human-facing
    remediation line the CLI surfaces (instead of a raw traceback) when the most
    likely cause is operator error, e.g. running ``kow env`` as root when the
    salt is owned by the daemon's unprivileged service user.
    """

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


def _check_salt(install_salt: bytes) -> None:
    """Validate the salt before it's used as an HMAC key. A too-short salt
    is a misuse/corruption signal — fail loud rather than derive weak,
    low-entropy-keyed placeholders."""
    if not isinstance(install_salt, (bytes, bytearray)):
        raise TypeError(f"install_salt must be bytes, got {type(install_salt).__name__}")
    if len(install_salt) < _SALT_BYTES:
        raise ValueError(
            f"install_salt must be at least {_SALT_BYTES} bytes "
            f"(got {len(install_salt)}); a short salt weakens the keyed HMAC. "
            "Regenerate via `kow setup` (this invalidates existing placeholders)."
        )


def _derive_tail(secret_name: str, install_salt: bytes) -> str:
    """The lowercased, unpadded, truncated base32 HMAC tail for one name.

    Factored out so tests can stub it to force a collision, and so the
    digest construction lives in exactly one place.
    """
    digest = hmac.new(install_salt, secret_name.encode("utf-8"), hashlib.sha256).digest()
    b32 = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
    return b32[:_TAIL_CHARS]


def derive_placeholder(secret_name: str, install_salt: bytes) -> str:
    """Derive the deterministic, salted placeholder for ``secret_name``.

    Stable for a given (name, salt). Satisfies config.py's placeholder
    invariants (>=24 chars, contains the PLACEHOLDER marker, printable,
    no shell metacharacters). See module docstring for the construction.
    """
    _check_salt(install_salt)
    if not secret_name:
        raise ValueError("secret_name must be a non-empty string")
    return DERIVE_PREFIX + _derive_tail(secret_name, install_salt)


def derive_placeholder_map(
    secret_names: list[str],
    install_salt: bytes,
) -> dict[str, str]:
    """Derive ``{secret_name: placeholder}`` for a set of names, detecting
    collisions.

    A collision on the truncated tail raises :class:`PlaceholderCollisionError`
    naming every conflicting secret. Duplicate names in the input are
    deduplicated (the same name deriving the same placeholder is not a
    collision).
    """
    _check_salt(install_salt)
    mapping: dict[str, str] = {}
    # placeholder -> first name that produced it, for collision diagnostics.
    seen: dict[str, str] = {}
    collisions: list[tuple[str, str, str]] = []
    for name in secret_names:
        if name in mapping:
            continue  # same name twice — derives the same placeholder, fine.
        ph = derive_placeholder(name, install_salt)
        if ph in seen and seen[ph] != name:
            collisions.append((ph, seen[ph], name))
            continue
        seen[ph] = name
        mapping[name] = ph
    if collisions:
        detail = "; ".join(f"{a!r} and {b!r} -> {ph}" for ph, a, b in collisions)
        raise PlaceholderCollisionError(
            "derived placeholder collision across secret names: "
            f"{detail}. Rename one of the conflicting secrets in BWS "
            "(or rotate the install salt, which re-derives all placeholders)."
        )
    return mapping


def load_or_create_install_salt(salt_path: str | Path) -> bytes:
    """Load the per-install salt from ``salt_path``, creating it (32 random
    bytes, mode 0600) on first call.

    The salt is generated ONCE per install and must remain stable: it keys
    every derived placeholder, so regenerating it silently would invalidate
    every secret's placeholder (the daemon would stop recognising the env
    file the agent already has). Therefore:

    * An existing file that is the right length is returned as-is.
    * An existing file that is TOO SHORT is treated as corruption/tamper and
      raises (never silently regenerated) — the operator must decide to
      rotate deliberately.
    * The parent directory is created (0700) if missing, so a fresh install
      under ``$AVP_CONFDIR`` works without a separate mkdir step.

    Concurrency note: creation uses ``O_CREAT | O_EXCL`` so two racing
    processes can't both write a salt; the loser re-reads the winner's.
    """
    path = Path(salt_path)
    if path.exists():
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise InstallSaltError(
                f"install salt at {path} has insecure mode {oct(mode)}; expected 0o600. "
                "Restrict it to owner read/write only before starting the daemon."
            )
        euid = os.geteuid()
        if st.st_uid not in {euid, 0}:
            hint = None
            if euid == 0:
                # Overwhelmingly the real cause: the command was run as root (e.g.
                # via sudo), but the salt belongs to the daemon's unprivileged
                # service user. The CLI must run AS that user, not root.
                hint = (
                    f"You're running as root, but the salt is owned by uid {st.st_uid} — "
                    "the keys-on-the-wire daemon's own service user. This almost always "
                    "means the command was run as root (e.g. via sudo). Run it as the "
                    "salt's owner instead, for example:\n"
                    f"    sudo -u '#{st.st_uid}' kow env --print"
                )
            raise InstallSaltError(
                f"install salt at {path} is owned by uid {st.st_uid}; expected uid {euid} "
                "or root (0). Fix the owner before starting the daemon.",
                hint=hint,
            )
        data = path.read_bytes()
        if len(data) < _SALT_BYTES:
            raise InstallSaltError(
                f"install salt at {path} is {len(data)} bytes; expected at least "
                f"{_SALT_BYTES}. Refusing to use a short/corrupt salt. If this is "
                "intentional rotation, delete the file and re-run setup (this "
                "invalidates all existing placeholders)."
            )
        return data

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    salt = secrets.token_bytes(_SALT_BYTES)
    # O_EXCL: fail if another process created it between the exists() check
    # and now. 0o600: owner read/write only — the salt is key material.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # Lost the create race; read the winner's salt.
        return load_or_create_install_salt(path)
    try:
        os.write(fd, salt)
    finally:
        os.close(fd)
    # Re-assert 0600 explicitly — key material; belt over O_EXCL's mode arg.
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return salt


def _confdir_from_env() -> str | None:
    """Config dir from the environment.

    Prefers ``KOW_CONFDIR``; falls back to the deprecated ``AVP_CONFDIR`` (with a
    :class:`DeprecationWarning`) so pre-rename installs keep working. The fallback
    is removed in 2.0.0 (ADR-0045).

    ``KOW_CONFDIR`` and ``AVP_CONFDIR`` name the SAME directory across the rename;
    the confdir keys the install-salt and therefore every derived placeholder. If
    both are set to DIFFERENT paths that is a migration misconfiguration — silently
    preferring one would re-derive every placeholder and stop injection. Fail loud
    instead of guessing.
    """
    new = os.environ.get("KOW_CONFDIR")
    legacy = os.environ.get("AVP_CONFDIR")
    # normpath so trailing-slash / `.` / `..` variants of the SAME directory
    # don't trip the guard; only a genuinely different target fails loud.
    if new and legacy and os.path.normpath(new) != os.path.normpath(legacy):
        raise InstallSaltError(
            "KOW_CONFDIR and AVP_CONFDIR are both set to different paths "
            f"({new!r} vs {legacy!r}); they name the same directory across the "
            "keys-on-the-wire rename. Set only KOW_CONFDIR, or point both at the "
            "same directory — otherwise the install salt (and every derived "
            "placeholder) would change."
        )
    if new:
        return new
    if legacy:
        warnings.warn(
            "AVP_CONFDIR is deprecated and will be removed in the next major "
            "release; set KOW_CONFDIR instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return legacy
    return None


def resolve_install_salt_path(explicit: str | Path | None) -> str:
    """Resolve the install-salt path.

    Precedence: explicit path, then ``$KOW_CONFDIR/install-salt`` (or the
    deprecated ``$AVP_CONFDIR``), then ``$HOME/install-salt`` (via
    :func:`Path.home`). The HOME fallback keeps the default in the daemon-user's
    writable confdir rather than next to ``bindings.yaml``.
    """
    if explicit:
        return str(explicit)
    confdir = _confdir_from_env()
    if confdir:
        return str(Path(confdir) / _DEFAULT_SALT_BASENAME)
    try:
        home = Path.home()
    except RuntimeError as e:
        raise RuntimeError("could not determine HOME for install salt path") from e
    return str(home / _DEFAULT_SALT_BASENAME)
