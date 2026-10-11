"""``kow secret`` secret management for the two local backends.

Two backends keep their secrets on this machine and so can be managed from
here: ``static`` (a YAML file) and ``keychain`` (a macOS keychain, ADR-0046).
The networked backends are managed by their own vendor tooling. No verb in this
module ever prints a secret value.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from kow import _paths
from kow.config import load_config

_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Backends whose secrets live on this machine, and which `kow secret` can
# therefore manage. Networked vaults are managed with their own vendor tooling.
_LOCAL_BACKENDS = frozenset({"static", "keychain"})
_LINUX_CONFIG = _paths.resolve(_paths.LINUX_CONFDIR / "bindings.yaml")
_MACOS_CONFIG = _paths.resolve(_paths.MACOS_CONFDIR / "bindings.yaml")


class SecretNameInput(BaseModel):
    """Validated env-var-shaped secret name."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _NAME_RE.fullmatch(value):
            raise ValueError("must match ^[A-Z][A-Z0-9_]*$")
        return value


def _default_config_path() -> Path:
    return _MACOS_CONFIG if sys.platform == "darwin" else _LINUX_CONFIG


def _die(message: str) -> SystemExit:
    return SystemExit(message)


def _validate_name(name: str) -> str:
    try:
        return SecretNameInput.model_validate({"name": name}).name
    except ValidationError:
        raise _die(f"invalid secret name {name!r}: must match ^[A-Z][A-Z0-9_]*$") from None


def _load_backend_block(config_path: str):
    """Return the validated ``backend:`` block, or die with an operator-readable
    message. Shared by the static and keychain paths so a bad config produces
    the same diagnostic whichever backend is selected."""
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        raise _die(f"config file not found: {config_path}") from None
    except OSError as exc:
        raise _die(f"could not read config {config_path}: {type(exc).__name__}") from None
    except Exception as exc:
        raise _die(f"invalid config {config_path}: {type(exc).__name__}") from None

    if config.backend is None or config.backend.type not in _LOCAL_BACKENDS:
        raise _die(
            "kow secret manages locally-stored secrets only; it requires "
            f"backend.type to be one of {sorted(_LOCAL_BACKENDS)} "
            "(networked vaults are managed with their own vendor tooling)"
        )
    return config.backend


def _load_keychain_backend(config_path: str):
    """Build a :class:`KeychainBackend` from the configured backend block."""
    from kow.backends.keychain import KeychainBackend

    block = _load_backend_block(config_path)
    if block.type != "keychain":
        raise _die("internal: _load_keychain_backend called for a non-keychain backend")
    return KeychainBackend(config=block._validated_config)


def _load_static_path(config_path: str) -> Path:
    block = _load_backend_block(config_path)
    if block.type != "static":
        raise _die("internal: _load_static_path called for a non-static backend")

    backend_config = block._validated_config
    raw_path = getattr(backend_config, "path", None)
    if not isinstance(raw_path, str) or not raw_path:
        raise _die("kow secret requires backend.config.path for the static backend")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = path.resolve()
    return path


def _ensure_writable(path: Path) -> None:
    if not os.access(path, os.W_OK):
        raise _die(f"cannot write {path} as uid {os.geteuid()}: run with sudo as the service user")


def _reject_symlink(path: Path) -> None:
    """Refuse to operate on a symlinked secrets file. A symlinked configured
    path would let an attacker who controls the link redirect reads/writes
    elsewhere; safer to fail closed than to follow."""
    try:
        if path.is_symlink():
            raise _die(f"static secrets file {path} is a symlink — refusing for safety")
    except OSError as exc:
        raise _die(f"could not lstat {path}: {type(exc).__name__}") from None


def _ensure_parent_safe(path: Path) -> None:
    """Match _file_is_safe's parent-dir invariant: 0o700, owner-only, no
    symlink. We enforce at write time so a permissive parent dir can't be
    used to substitute the secrets file between our temp-write and rename."""
    parent = path.parent
    try:
        st = parent.lstat()
    except OSError as exc:
        raise _die(f"could not lstat {parent}: {type(exc).__name__}") from None
    if (st.st_mode & 0o777) & 0o077:
        raise _die(
            f"parent dir {parent} mode {oct(st.st_mode & 0o777)} is group/world "
            "accessible — refuse to write secrets through it. Expected 0o700."
        )


def _read_secrets(path: Path, *, for_write: bool = False) -> dict[str, str]:
    _reject_symlink(path)
    if not path.exists():
        raise _die(f"static secrets file not found: {path}")
    if for_write:
        _ensure_writable(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except OSError as exc:
        raise _die(f"could not read static secrets file {path}: {type(exc).__name__}") from None
    except yaml.YAMLError as exc:
        raise _die(f"static secrets file malformed: {type(exc).__name__}") from None

    if not isinstance(raw, dict) or "secrets" not in raw:
        raise _die(f"static secrets file {path} missing top-level 'secrets:' map")
    secrets_raw = raw["secrets"]
    if not isinstance(secrets_raw, dict):
        raise _die("'secrets:' must be a mapping of name -> value")
    return {str(key): str(value) for key, value in secrets_raw.items()}


def _write_secrets_atomic(path: Path, mapping: dict[str, str]) -> None:
    _reject_symlink(path)
    _ensure_writable(path)
    _ensure_parent_safe(path)
    try:
        stat_result = path.stat()
    except FileNotFoundError:
        raise _die(f"static secrets file not found: {path}") from None
    except OSError as exc:
        raise _die(f"could not stat static secrets file {path}: {type(exc).__name__}") from None

    payload = yaml.safe_dump({"secrets": mapping}, sort_keys=True)
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.tmp-",
            delete=False,
        ) as handle:
            tmp_name = handle.name
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        if os.geteuid() == 0 or stat_result.st_uid == os.geteuid():
            os.chown(tmp_name, stat_result.st_uid, stat_result.st_gid)
        os.replace(tmp_name, path)
    except OSError as exc:
        if tmp_name is not None:
            try:
                Path(tmp_name).unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        raise _die(f"could not update static secrets file {path}: {type(exc).__name__}") from None


def _prompt_value() -> str:
    value = getpass.getpass("Value: ")
    if value == "":
        raise _die("secret value must not be empty")
    return value


def _read_stdin_value() -> str:
    # rstrip("\r\n") so CRLF-piped input (Windows shells, some CI runners)
    # doesn't leave a trailing \r baked into the secret value.
    value = sys.stdin.readline().rstrip("\r\n")
    if value == "":
        raise _die("secret value must not be empty")
    return value


def _read_stdin_raw_value() -> str:
    """Everything on stdin, to EOF, byte for byte.

    ``--stdin`` reads ONE line and strips its terminator, which is right for an
    API key and silently destructive for a PEM: only the ``-----BEGIN`` line
    would be stored, the backend's read-back would confirm that truncated value,
    and the operator would be told the write succeeded. So this is a separate
    flag rather than a change to the existing one — ``--stdin``'s stripping is
    load-bearing for every single-line secret already scripted against it.

    Nothing is stripped here, including the trailing newline, because a PEM has
    one and it is part of the file.
    """
    value = sys.stdin.read()
    if value == "":
        raise _die("secret value must not be empty")
    return value


@contextmanager
def _backend_errors(doing: str):
    """Turn backend exceptions into a one-line CLI death.

    The backend's own messages are already operator-readable and carry no secret
    bytes (that is a backend invariant, asserted in its tests), so they are
    surfaced verbatim rather than replaced with a generic failure.
    """
    from kow.backends import BackendUnavailableError, SecretNotFoundError

    try:
        yield
    except SecretNotFoundError as exc:
        raise _die(f"{doing}: {exc}") from None
    except BackendUnavailableError as exc:
        raise _die(f"{doing}: {exc}") from None


def run_secret_add(
    name: str, config_path: str, from_stdin: bool, *, raw_stdin: bool = False
) -> int:
    name = _validate_name(name)
    block = _load_backend_block(config_path)

    def read_value() -> str:
        if raw_stdin:
            return _read_stdin_raw_value()
        return _read_stdin_value() if from_stdin else _prompt_value()

    # Every check that can fail runs BEFORE the value is read, so an operator
    # never types a credential into a session that was going to die anyway.
    if block.type == "keychain":
        backend = _load_keychain_backend(config_path)
        value = read_value()
        with _backend_errors(f"could not add {name!r}"):
            backend.update(name, value)
    else:
        path = _load_static_path(config_path)
        secrets = _read_secrets(path, for_write=True)
        secrets[name] = read_value()
        _write_secrets_atomic(path, secrets)
    print(f"✓ added secret {name!r}", file=sys.stderr)
    print("  next: run `kow env` to refresh ~/.config/kow/env", file=sys.stderr)
    return 0


def run_secret_list(config_path: str) -> int:
    block = _load_backend_block(config_path)
    if block.type == "keychain":
        backend = _load_keychain_backend(config_path)
        with _backend_errors("could not list secrets"):
            names = backend.list_secret_names()
    else:
        names = sorted(_read_secrets(_load_static_path(config_path)))
    for name in names:
        print(name)
    return 0


def run_secret_remove(name: str, config_path: str) -> int:
    name = _validate_name(name)
    block = _load_backend_block(config_path)
    if block.type == "keychain":
        backend = _load_keychain_backend(config_path)
        # delete is idempotent in the backend, so "not present" is not an error
        # here either — same contract as the static path below.
        with _backend_errors(f"could not remove {name!r}"):
            backend.delete(name)
    else:
        path = _load_static_path(config_path)
        secrets = _read_secrets(path, for_write=True)
        if name not in secrets:
            print(f"secret {name!r} not present; nothing to do", file=sys.stderr)
            return 0
        del secrets[name]
        _write_secrets_atomic(path, secrets)
    print(f"✓ removed secret {name!r}", file=sys.stderr)
    return 0


def run_secret_rotate(name: str, config_path: str) -> int:
    name = _validate_name(name)
    block = _load_backend_block(config_path)
    if block.type == "keychain":
        from kow.backends import SecretNotFoundError

        backend = _load_keychain_backend(config_path)
        # Prompt only after confirming the name exists: rotate is not a
        # create verb, and an operator who mistyped should learn that before
        # they type a credential.
        with _backend_errors(f"could not rotate {name!r}"):
            try:
                backend.fetch(name)
            except SecretNotFoundError:
                raise _die(
                    f"cannot rotate {name!r}: not present (use `kow secret add` instead)"
                ) from None
            backend.update(name, _prompt_value())
    else:
        path = _load_static_path(config_path)
        secrets = _read_secrets(path, for_write=True)
        if name not in secrets:
            raise _die(f"cannot rotate {name!r}: not present (use `kow secret add` instead)")
        del secrets[name]
        secrets[name] = _prompt_value()
        _write_secrets_atomic(path, secrets)
    print(f"✓ rotated secret {name!r}", file=sys.stderr)
    print("  next: run `kow env` to refresh ~/.config/kow/env", file=sys.stderr)
    return 0


def register_secret_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--config",
        default=str(_default_config_path()),
        help="Path to bindings.yaml.",
    )

    secret_p = parent_subparsers.add_parser(
        "secret",
        help="Manage locally-stored secrets (static file, macOS keychain) without showing <value>.",
        description=(
            "Manage secrets held by a local backend — the static YAML file or a "
            "macOS keychain. This CLI never displays <value>; it can add, list "
            "names, remove, and rotate entries."
        ),
    )
    secret_p.set_defaults(_secret_parser=secret_p)
    secret_sub = secret_p.add_subparsers(dest="secret_command")

    add_p = secret_sub.add_parser(
        "add",
        parents=[common],
        help="Store NAME and prompt for <value> with no echo.",
        description="Add NAME to the static secrets file and read <value> securely.",
    )
    add_p.add_argument("name", metavar="NAME", help="Secret name to add.")
    add_input = add_p.add_mutually_exclusive_group()
    add_input.add_argument(
        "--stdin",
        action="store_true",
        help="Read one line of <value> from stdin instead of prompting with no echo.",
    )
    add_input.add_argument(
        "--stdin-raw",
        action="store_true",
        help=(
            "Read <value> from stdin to EOF, byte for byte. Use for multi-line "
            "credentials such as a PEM key; --stdin would store only the first line."
        ),
    )

    list_p = secret_sub.add_parser(
        "list",
        parents=[common],
        help="Print sorted secret names only; values are never shown.",
        description="List sorted secret names from the static secrets file.",
    )
    del list_p

    remove_p = secret_sub.add_parser(
        "remove",
        parents=[common],
        help="Delete NAME from the static secrets file.",
        description="Remove NAME from the static secrets file if it is present.",
    )
    remove_p.add_argument("name", metavar="NAME", help="Secret name to remove.")

    rotate_p = secret_sub.add_parser(
        "rotate",
        parents=[common],
        help="Replace NAME with a newly prompted <value>.",
        description="Rotate NAME by securely prompting for a new <value>.",
    )
    rotate_p.add_argument("name", metavar="NAME", help="Secret name to rotate.")


def run_secret(args: argparse.Namespace) -> int:
    dispatch = {
        "add": lambda: run_secret_add(
            # getattr: callers build this Namespace by hand too, and a missing
            # optional flag should not be an AttributeError deep in dispatch.
            args.name,
            args.config,
            args.stdin,
            raw_stdin=getattr(args, "stdin_raw", False),
        ),
        "list": lambda: run_secret_list(args.config),
        "remove": lambda: run_secret_remove(args.name, args.config),
        "rotate": lambda: run_secret_rotate(args.name, args.config),
    }
    if args.secret_command is None:
        parser = getattr(args, "_secret_parser", None)
        if parser is not None:
            parser.print_help(sys.stderr)
        return 2
    return dispatch[args.secret_command]()
