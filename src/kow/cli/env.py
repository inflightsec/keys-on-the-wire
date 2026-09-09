"""``kow env`` — project the BWS project's secrets to a placeholder env file.

This is the operator-facing half of the "edit only Bitwarden" workflow
(ADR-0011 amendment, "Placeholder origin"). It:

1. Loads the daemon config to find the configured backend.
2. Enumerates the project's secret NAMES via the backend (never values).
3. Validates each name against ``^[A-Za-z_][A-Za-z0-9_]*$`` — REJECTING
   (not sanitizing) any name that wouldn't be a safe shell identifier. A
   bad name is skipped with a warning so one mistyped secret can't break
   the whole env file.
4. Derives the deterministic, salted placeholder for each valid name
   (see :mod:`kow.placeholders`) — the SAME derivation the
   daemon uses, so the env file and the daemon's enforced map agree.
5. Writes ``export NAME='<placeholder>'`` lines, single-quoted, to a 0600
   file (default ``~/.config/kow/env``).

Security posture:

* **Never emit anything eval-unsafe.** Names are validated to a strict
  identifier charset; placeholders are metachar-free by construction
  (``avp-PLACEHOLDER-`` + lowercase base32). We single-quote the value
  anyway as defense in depth. The profile snippet we print uses
  ``set -a; . file; set +a`` — a plain *source*, NEVER ``eval $(...)``,
  because sourcing a file of ``export NAME='literal'`` lines cannot run
  code, whereas ``eval`` of arbitrary command output can.
* **Names are validated, not sanitized.** Silently rewriting ``FOO-BAR``
  to ``FOO_BAR`` would create a placeholder under a name the daemon never
  derives — a silent mismatch. Reject + warn keeps the two sides honest.
"""

from __future__ import annotations

import re
import stat
import sys
from pathlib import Path

from kow import _paths

# A secret name must be a POSIX-shell-safe identifier: leading letter or
# underscore, then letters/digits/underscores. This is intentionally
# STRICTER than what BWS allows in a secret name — anything outside this
# set is rejected (not rewritten) so the daemon's derived placeholder and
# the env file always agree on the exact name.
VALID_SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Default env-file location for simple mode. ``~/.config/kow/env``, falling
# back to the pre-rename ``~/.config/avp/env`` when that is the one the
# operator already has (ADR-0045; fallback drops in 2.0.0).
_DEFAULT_ENV_PATH = "~/.config/kow/env"
_LEGACY_ENV_PATH = "~/.config/avp/env"


def default_env_path() -> Path:
    new = Path(_DEFAULT_ENV_PATH).expanduser()
    if _paths.exists(new):
        return new
    legacy = Path(_LEGACY_ENV_PATH).expanduser()
    return legacy if _paths.exists(legacy) else new


def list_secret_names(backend: object) -> list[str]:
    """Enumerate secret names via the backend's listing contract.

    Thin wrapper over :func:`kow.backends.list_secret_names`
    so this module is the single import surface the CLI uses.
    """
    from kow.backends import list_secret_names as _list

    return _list(backend)  # type: ignore[arg-type]


def build_export_lines(
    secret_names: list[str],
    install_salt: bytes,
    stored: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Build ``export NAME='<placeholder>'`` lines for valid names.

    Returns ``(lines, skipped)`` where ``skipped`` is the list of names
    rejected by :data:`VALID_SECRET_NAME_RE` (reported, never written).

    ``stored`` maps names to note-pinned placeholders (ADR-0029); a stored
    placeholder wins over derivation for its secret — matching the daemon's
    precedence. Remaining placeholders are derived per
    :func:`derive_placeholder_map`, which also fails closed on a
    derived-placeholder collision across the name set.
    """
    from kow.placeholders import derive_placeholder_map

    valid: list[str] = []
    skipped: list[str] = []
    for name in secret_names:
        if VALID_SECRET_NAME_RE.match(name):
            valid.append(name)
        else:
            skipped.append(name)

    mapping = derive_placeholder_map(valid, install_salt)
    lines: list[str] = []
    for name in valid:
        placeholder = (stored or {}).get(name) or mapping[name]
        # Single-quote the value. Both name (regex-validated identifier) and
        # placeholder (avp-PLACEHOLDER- + lowercase base32) are metachar-free,
        # so no escaping is needed inside the single quotes; we assert this
        # invariant defensively rather than trusting it silently.
        assert "'" not in placeholder and "'" not in name
        lines.append(f"export {name}='{placeholder}'")
    return lines, skipped


def write_env_file(env_path: str | Path, lines: list[str]) -> None:
    """Write ``lines`` to ``env_path`` as a 0600 file, creating parents.

    Overwrites any existing file (``kow env --refresh`` re-projects from
    scratch). Opens with ``O_TRUNC`` and mode 0600 so the file never exists
    world/group-readable even momentarily.
    """
    path = Path(env_path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    header = (
        "# Generated by `kow env`. Do not edit by hand — re-run `kow env --refresh`.\n"
        "# These are PLACEHOLDERS, not real secrets. The keys-on-the-wire daemon\n"
        "# swaps them for real credentials on the wire; the real values never\n"
        "# enter this process's environment.\n"
    )
    body = header + "\n".join(lines) + ("\n" if lines else "")
    # O_TRUNC over an existing path keeps perms of the existing file, so we
    # also chmod after to guarantee 0600 regardless of prior state.
    import os

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, body.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _resolve_salt_path(config_salt_path: str | None, explicit: str | None) -> str:
    """Resolve the install-salt path, mirroring the DAEMON's precedence so
    ``kow env`` derives the SAME placeholders the running proxy enforces:
    explicit ``--salt`` > the config's ``install_salt_path`` > the
    ``$KOW_CONFDIR`` (or deprecated ``$AVP_CONFDIR``) / ``$HOME`` fallback.

    The daemon resolves via ``resolve_install_salt_path(config.install_salt_path)``
    (handlers.py). Passing the CLI ``--salt`` (if any) ahead of the config value
    keeps an explicit override working while otherwise defaulting to the config —
    so when the config pins ``install_salt_path``, no ``--salt`` flag is needed
    and ``kow env`` can't silently derive against the wrong salt (e.g. a sudo
    shell's ``$HOME`` instead of the daemon's state dir)."""
    from kow.placeholders import resolve_install_salt_path

    return resolve_install_salt_path(explicit or config_salt_path)


def run_env(
    *,
    config_path: str,
    env_path: str | None = None,
    salt_path: str | None = None,
    print_only: bool = False,
    refresh: bool = False,
) -> int:
    """Execute ``kow env``. Returns a process exit code.

    ``refresh`` is accepted for symmetry with the CLI surface; since every
    run re-projects from BWS, it currently only affects messaging (a plain
    ``kow env`` and ``kow env --refresh`` both rewrite the file). ``print_only``
    writes the export lines to stdout and does NOT touch the env file.
    """
    from kow.config import build_backend, load_config
    from kow.placeholders import load_or_create_install_salt

    config = load_config(config_path)
    backend, _ = build_backend(config)
    names = list_secret_names(backend)

    resolved_salt = _resolve_salt_path(config.install_salt_path, salt_path)
    salt = load_or_create_install_salt(resolved_salt)

    # Stored placeholders (ADR-0029): read each note's pinned placeholder so
    # the projected env matches what the daemon actually enforces. A backend
    # that can't serve notes degrades to derived-only with a warning rather
    # than failing the whole projection.
    # File-declared placeholders come FIRST: in `binding_source: file` the
    # daemon enforces exactly `spec.placeholder`, so projecting a derived one
    # would hand the agent a token the proxy does not recognise — the
    # documented `kow env && kow run` flow would silently never inject.
    stored: dict[str, str] = {
        name: spec.placeholder for name, spec in config.secrets.items() if spec.placeholder
    }
    try:
        from kow.backends import list_secret_notes
        from kow.notes_binding import stored_placeholder_from_note

        notes = list_secret_notes(backend)
        for name, note in notes.items():
            pinned = stored_placeholder_from_note(note, secret_name=name)
            # A file declaration is authoritative for the secrets it names;
            # note pins fill in the rest (ADR-0029).
            if pinned is not None and name not in stored:
                stored[name] = pinned
    except Exception as e:  # noqa: BLE001 — degrade, don't brick the projection
        print(
            f"[kow env] WARNING: could not read notes for stored placeholders "
            f"({type(e).__name__}: {e}); projecting derived placeholders only — "
            "secrets with a note-pinned placeholder will NOT match this env.",
            file=sys.stderr,
        )

    lines, skipped = build_export_lines(names, salt, stored=stored)

    for name in skipped:
        print(
            f"[kow env] WARNING: skipping secret name {name!r} — not a valid shell "
            "identifier (must match ^[A-Za-z_][A-Za-z0-9_]*$). Rename it in BWS to "
            "include it.",
            file=sys.stderr,
        )

    if print_only:
        for line in lines:
            print(line)
        return 0

    target = env_path or str(default_env_path())
    write_env_file(target, lines)
    print(
        f"[kow env] wrote {len(lines)} placeholder export(s) to {target} "
        f"(skipped {len(skipped)} invalid name(s)).",
        file=sys.stderr,
    )
    # Profile snippet — sourced, never eval'd.
    print(
        f"\nAdd to your shell profile:\n  set -a; . {target}; set +a\n",
        file=sys.stderr,
    )
    return 0
