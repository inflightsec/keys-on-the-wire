"""macOS Keychain secrets backend (ADR-0046).

Reads and writes generic-password items in a **file-based** macOS keychain —
the login keychain by default — through ``/usr/bin/security``. Zero third-party
dependencies: the tool ships with the OS.

What this buys, stated plainly:

    * no plaintext secret on disk (the keychain is encrypted with a key derived
      from the account's login password),
    * a GUI view: Keychain Access, filtered on the configured ``service``,
    * no vault account, no token, no network round trip.

What it does **not** buy: access scoping to kow alone. **The access boundary is
the macOS user account**, and it stays that way whichever transmit path is in
use. Run kow as a LaunchAgent in the operator's account and keep agent workloads
in a *separate* macOS account; per-user keychain encryption is the wall that
actually holds.

That is worth stating precisely, because the signed ``kow-keyd`` helper looks
like it changes it and does not. An item written by the helper carries an ACL
naming the helper's code identity — but *anyone who can run the helper satisfies
that ACL*, and it is a world-executable CLI with no caller authentication, so a
same-UID process runs ``kow-keyd get`` and is handed the secret. Nor is the
default self-signed identity exclusive: its private key sits in the operator's
own login keychain with ``codesign`` authorised against it. And ACL denial is
only categorical for a caller that suppresses user interaction, as the helper
does; a caller that does not gets a *prompt*, and "Always Allow" writes it into
the ACL for good. See ADR-0051 § "What the helper is not".

Two transmit paths (ADR-0051)
-----------------------------

``use_helper: off`` (default) shells out to ``/usr/bin/security``. Simple, no
build step, and structurally unable to carry a value containing a newline: the
``security -i`` line protocol ends the command there, so such a value is refused
at the API boundary rather than silently truncated.

``use_helper: require`` routes every operation through ``kow-keyd``, which
passes the value on stdin as raw bytes. This is the only way to store a
multi-line credential such as a service-account PEM (ADR-0050's impersonation
seat). It buys transport, not access control.

The two paths are not interchangeable over stored data: items carry the ACL of
whichever wrote them, so switching modes means re-adding every secret. There is
deliberately no auto-detect mode — picking the semantics of persisted data from
the presence of a file on disk is how an upgrade strands a keychain.

Two more consequences of the file-based keychain, both deliberate:

    * items here can never appear in the macOS **Passwords** app, and Passwords
      items can never be read from here — Passwords speaks only to the
      data-protection keychain, and there is no command-line access to that one.
    * the login keychain never syncs between Macs. For a fleet, use a networked
      backend (bws, gsm, aws-secrets-manager).

Config::

    backend:
      type: keychain
      config:
        type: keychain
        service: kow                     # the generic-password "service" attr
        keychain: ~/Library/Keychains/login.keychain-db   # optional; default keychain when unset
        secret_prefix: null              # optional namespace bound
        self_check: deny                 # deny | warn | off
        timeout_seconds: 10.0
        use_helper: off                  # off | require  (ADR-0051)
"""

from __future__ import annotations

import logging
import os
import re
import stat
import subprocess  # noqa: S404 — the whole backend is a wrapper around /usr/bin/security
import sys
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from kow.backends._scope import assert_in_scope, refuse_or_warn
from kow.secret import Secret

_log = logging.getLogger("kow.backends.keychain")

# Absolute, never resolved through PATH: a backend that finds its
# security-critical binary by searching $PATH is one writable directory away
# from executing somebody else's "security". Module-level so tests can
# monkeypatch it with a stub; deliberately NOT a config field or an env var,
# which would put the same hijack back in the hands of anything that can edit
# config or environment.
SECURITY_BIN = "/usr/bin/security"

# Where `kow-keyd` may live, in preference order. Same reasoning as
# SECURITY_BIN: a *settable* path to a security-critical binary is a hijack
# surface handed to anything that can edit config or environment, so
# `use_helper` chooses WHETHER to look, never WHERE.
#
# Root-owned system locations only. Homebrew prefixes are deliberately absent:
# /opt/homebrew belongs to the installing user on Apple Silicon, so a candidate
# there is writable by exactly the attacker _keyd_trust_error exists to exclude.
KEYD_CANDIDATES: tuple[str, ...] = (
    "/usr/local/libexec/kow-keyd",
    "/usr/libexec/kow-keyd",
)

# kow-keyd's exit-code contract (its header is the source of truth).
_KEYD_EXIT_USAGE = 2
_KEYD_EXIT_MISSING_ENTITLEMENT = 34
_KEYD_EXIT_INTERACTION = 51

# `security dump-keychain` prints one `"attr"<blob>="value"` line per attribute.
# Non-representable values come out as `<blob>=0x68656C6C6F  "hello"`, which this
# pattern deliberately does not match — see _parse_dump.
_ATTR_RE = re.compile(r'^\s*"(?P<key>[a-zA-Z0-9_]{4})"<blob>="(?P<value>.*)"\s*$')
_ITEM_BOUNDARY_RE = re.compile(r"^keychain: ")

# `service` is constrained at config-load to this set so it survives both the
# interactive command line and the dump-keychain text format unambiguously.
_SAFE_SERVICE_RE = re.compile(r"[A-Za-z0-9._-]+")

# errSecItemNotFound. `security` surfaces the OSStatus as its exit code for the
# find/delete verbs, so 44 is "the keychain answered: no such item" — a
# different fact from "the keychain would not answer", and the protocol demands
# they raise different exceptions.
_EXIT_ITEM_NOT_FOUND = 44

_NOT_FOUND_MARKERS = ("could not be found", "The specified item could not be found")
_LOCKED_MARKERS = (
    "User interaction is not allowed",
    "interaction is not allowed",
    "The user name or passphrase you entered is not correct",
    "is locked",
)


class KeychainConfig(BaseModel):
    """``backend.config`` schema for ``type: keychain``."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["keychain"] = "keychain"

    # The generic-password `service` attribute every kow item carries. Also the
    # string to type into Keychain Access's search box to see them all.
    service: str = "kow"

    # Which keychain file. Unset = the user's default (login) keychain, which is
    # what an operator wants. Setting it is how CI, the VM e2e leg, and anyone
    # who wants a dedicated kow keychain stay out of the login keychain.
    keychain: str | None = None

    # Defence-in-depth namespace bound, identical in meaning to the aws/gsm
    # field of the same name.
    secret_prefix: str | None = None

    # Startup reachability check: platform, binary, keychain openable.
    self_check: Literal["deny", "warn", "off"] = "deny"

    timeout_seconds: float = 10.0

    # ADR-0051. `off` is today's `security(1)` path and is the default because
    # the two transmit paths are not interchangeable over stored data. There is
    # no `auto`: see the module docstring.
    use_helper: Literal["off", "require"] = "off"

    @field_validator("service")
    @classmethod
    def _service_is_safe(cls, v: str) -> str:
        # `service` travels twice: quoted into the `security -i` command line
        # (where a newline truncates the command), and back out through
        # `dump-keychain`'s text format (where a quote or backslash would need
        # unescaping to match). A conservative charset removes both problems at
        # the config boundary instead of defending them at two runtime sites.
        if not v.strip():
            raise ValueError("service must not be empty")
        if not _SAFE_SERVICE_RE.fullmatch(v):
            raise ValueError(
                "service must match ^[A-Za-z0-9._-]+$ (it is quoted into a "
                "command line and parsed back out of dump-keychain text)"
            )
        return v

    @field_validator("keychain")
    @classmethod
    def _keychain_path_is_transmittable(cls, v: str | None) -> str | None:
        # The keychain path is appended to the SAME interactive command line as
        # the value, and is quoted by the same helper. It was the one input not
        # checked for line-protocol-hostile bytes — a newline in it would split
        # the command stream and the write would land somewhere unintended.
        if v is not None and any(c in v for c in ("\n", "\r", "\0")):
            raise ValueError("keychain path must not contain a newline or NUL byte")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def _timeout_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return v


class KeychainError(Exception):
    """Internal: a non-zero ``security`` exit. Carries the exit code and the
    child's stderr — never its stdout, which on the read path IS the secret."""

    def __init__(self, code: int, stderr: str) -> None:
        super().__init__(f"security exited {code}")
        self.code = code
        self.stderr = stderr


class KeydError(Exception):
    """Internal: a non-zero ``kow-keyd`` exit. Separate from KeychainError
    because the two tools' exit codes mean different things — 51 is a real
    status here and is not one for ``security``."""

    def __init__(self, code: int, stderr: str) -> None:
        super().__init__(f"kow-keyd exited {code}")
        self.code = code
        self.stderr = stderr


class KeychainBackend:
    """``SecretsBackend`` over ``/usr/bin/security``.

    Thread-safety: every operation is a self-contained subprocess call with no
    shared mutable state beyond the one-shot ``_checked`` flag, so concurrent
    fetches are safe.
    """

    def __init__(self, config: KeychainConfig | None = None) -> None:
        self._config = config or KeychainConfig()
        # No I/O in __init__ (protocol contract). The first fetch/update/list
        # runs the self-check — and, in `require` mode, helper discovery.
        self._checked = False
        self._keyd: str | None = None
        self._keyd_error: str | None = None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} service={self._config.service!r}>"

    # ------------------------------------------------------------------ reads

    def fetch(self, name: str, ctx: Any = None) -> Secret:  # noqa: ARG002 — ctx unused
        from kow.backends import SecretNotFoundError

        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()
        # Not only on the write path: a NUL here reaches subprocess as an
        # embedded-null ValueError, which is outside the backend's exception
        # taxonomy and reaches the caller as an unhandled crash.
        _reject_untransmittable(name, "name", name)

        if self._keyd is not None:
            try:
                raw = self._keyd_run("get", name)
            except KeydError as e:
                if e.code == _EXIT_ITEM_NOT_FOUND:
                    raise SecretNotFoundError(
                        f"secret {name!r} not in keychain (service {self._config.service!r})"
                    ) from None
                raise self._keyd_unavailable(e, f"reading {name!r}") from None
            return self._keyd_decode(raw, name)

        try:
            out = self._run(["find-generic-password", "-a", name, "-s", self._config.service, "-w"])
        except KeychainError as e:
            if _is_not_found(e):
                raise SecretNotFoundError(
                    f"secret {name!r} not in keychain (service {self._config.service!r})"
                ) from None
            raise self._unavailable(e, f"reading {name!r}") from None
        # `security -w` writes the password followed by exactly one newline.
        # Strip that one and nothing else: trailing whitespace can be part of a
        # secret, and .strip() would silently corrupt it.
        return Secret(out[:-1] if out.endswith("\n") else out)

    def list_secret_names(self) -> list[str]:
        """Every ``acct`` whose ``svce`` matches the configured service.

        Attribute-only dump: ``dump-keychain`` without ``-d`` never reads
        password data, so this neither prompts nor decrypts anything.
        """
        self._ensure_ready()
        prefix = self._config.secret_prefix

        if self._keyd is not None:
            try:
                names: list[str] = list(dict.fromkeys(self._keyd_accounts()))
            except KeydError as e:
                raise self._keyd_unavailable(e, "enumerating the keychain") from None
            return sorted(n for n in names if not prefix or n.startswith(prefix))

        try:
            out = self._run(["dump-keychain"])
        except KeychainError as e:
            raise self._unavailable(e, "enumerating the keychain") from None
        names = _parse_dump(out, self._config.service)
        return sorted(n for n in names if not prefix or n.startswith(prefix))

    # ----------------------------------------------------------------- writes

    def update(
        self,
        name: str,
        value: str,
        ctx: Any = None,  # noqa: ARG002 — ctx unused
        *,
        expected_current_value: str | None = None,
    ) -> None:
        """Store ``value`` under ``name``, replacing any existing item.

        The value is handed to ``security`` over **stdin** (`security -i`
        interactive mode), never as an argv element: argv is world-readable
        through the process table on macOS, so ``-w <value>`` on a command line
        publishes the credential to every local user for the life of the call.
        """
        from kow.backends import BackendUnavailableError, BackendWriteConflictError

        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()

        _reject_untransmittable(name, "name", name)
        if self._keyd is None:
            _reject_untransmittable(value, "value", name)
        else:
            # ADR-0051 §7. On this path the duplicate check has to happen BEFORE
            # the write and has to fail closed. The helper's `set` matches on
            # (service, account), so a write collapses every duplicate into one
            # item — counting afterwards always reports one and the check could
            # never fire, while two prior values were silently destroyed. The
            # security(1) path below keeps its post-write check, which is sound
            # there because `add -U` touches a single unspecified match.
            self._keyd_refuse_duplicates(name)

        # Whether the item already exists decides what a failed write is allowed
        # to do about it: a botched CREATE can be cleaned up, a botched UPDATE
        # cannot (the prior value is already gone, and deleting would take the
        # consumer from "wrong credential" to "no credential").
        current = self._current_or_none(name)
        existed = current is not None

        if expected_current_value is not None and (
            current is None or current.reveal() != expected_current_value
        ):
            raise BackendWriteConflictError(
                f"secret {name!r} changed in the keychain since it was read; "
                "refusing to overwrite (operator rotation in flight?)"
            )

        # The invocation's own report is NOT evidence either way, in either
        # direction: `security -i` exits 0 even when a command inside the session
        # failed, and it can emit stderr on a write that landed perfectly well.
        # So the error is recorded and verification runs REGARDLESS — otherwise a
        # noisy-but-successful write is reported as a failure with no read-back,
        # and a failed write that already created an item skips its own cleanup.
        # The keychain is the authority; the subprocess is only a messenger.
        write_error = self._perform_write(name, value)

        if self._keyd is None:
            # `add -U`, `find` and `delete` all act on the FIRST match, in an
            # order `security` does not specify. With a duplicate (service,
            # account) pair — created out of band, or by an earlier partial
            # write — the read-back below can read a different item than the one
            # just written, and then pass or fail for the wrong reason. Refuse to
            # reason about it. The helper path checked this before writing.
            duplicates = self._count_items(name)
            if duplicates > 1:
                raise BackendUnavailableError(
                    f"keychain holds {duplicates} items for ({self._config.service!r}, "
                    f"{name!r}); `security` operates on an unspecified first match, so "
                    "the write cannot be verified. Remove the duplicates in Keychain "
                    "Access and retry."
                )

        # Read back and compare. The interactive protocol requires quoting the
        # value, and a quoting bug is exactly the class of failure that stores a
        # mangled credential while looking like success.
        stored = self._current_or_none(name)
        if stored is None or stored != Secret(value):
            # Log the ONE bit that distinguishes tokenizer truncation from every
            # other cause. Never the values, and never a hash of them: a hash of
            # a low-entropy secret in a log file is a cracking target.
            truncated = stored is not None and value.startswith(stored.reveal())
            _log.error(
                "keychain write of %r did not round-trip (stored %s bytes, wrote %s, "
                "stored-is-prefix=%s)",
                name,
                len(stored) if stored is not None else "none",
                len(value),
                truncated,
            )
            detail = ""
            if not existed:
                # We created this item, so nobody depended on it: removing the
                # mangled value is strictly better than leaving it readable. The
                # compensating action is itself verified, and its own failure is
                # reported ALONGSIDE the mismatch rather than replacing it.
                try:
                    self.delete(name)
                    detail = " The partial item was removed."
                except Exception as cleanup_exc:  # noqa: BLE001 — reported, never swallowed
                    detail = f" Removing the partial item ALSO failed: {cleanup_exc}"
            else:
                detail = (
                    " The previous value is gone and the item now holds untrusted "
                    "bytes — re-set it with `kow secret add`."
                )
            cause = f" `security` also reported: {write_error}" if write_error else ""
            raise BackendUnavailableError(
                f"keychain write of {name!r} did not round-trip; the stored value "
                f"differs from what was written (value withheld).{detail}{cause}"
            )

        if write_error is not None:
            # Verified good despite the noise. Say so rather than either failing a
            # correct write or hiding that the tool complained.
            _log.warning(
                "`security` reported an error writing %r but the stored value "
                "verifies; treating the write as successful. Reported: %s",
                name,
                write_error,
            )

    def _perform_write(self, name: str, value: str) -> Exception | None:
        """Store the value on whichever transmit path is active.

        Returns the error instead of raising it, because :meth:`update` verifies
        by read-back regardless of what the child process claimed.
        """
        if self._keyd is not None:
            from kow.backends import BackendUnavailableError

            try:
                payload = value.encode("utf-8")
            except UnicodeEncodeError:
                # A lone surrogate, i.e. a str that came from a surrogateescape
                # decode somewhere upstream. Raising the raw codec error here
                # would escape the backend taxonomy and could carry a fragment
                # of the value in its message.
                raise BackendUnavailableError(
                    f"secret {name!r} contains characters that are not encodable as UTF-8; "
                    "this backend stores UTF-8 text (value withheld)"
                ) from None
            try:
                self._keyd_run("set", name, stdin=payload)
            except KeydError as e:
                return self._keyd_unavailable(e, f"writing {name!r}")
            return None

        cmd = [
            "add-generic-password",
            "-a",
            name,
            "-s",
            self._config.service,
            "-U",
            "-w",
            value,
        ]
        try:
            self._run_interactive(cmd)
        except KeychainError as e:
            return self._unavailable(e, f"writing {name!r}")
        return None

    def _keyd_refuse_duplicates(self, name: str) -> None:
        """Fail closed. Unlike :meth:`_count_items`, which fails open because its
        caller's read-back is a genuine backstop, an unanswered enumeration here
        means the write cannot be shown to be unambiguous, so it does not happen.
        """
        from kow.backends import BackendUnavailableError

        try:
            count = self._keyd_accounts().count(name)
        except KeydError as e:
            raise self._keyd_unavailable(
                e, f"checking for duplicate items before writing {name!r}"
            ) from None
        if count > 1:
            raise BackendUnavailableError(
                f"keychain holds {count} items for ({self._config.service!r}, {name!r}); a write "
                "would collapse them into one and destroy the others, so it is refused. Remove "
                "the duplicates in Keychain Access and retry."
            )

    def _count_items(self, name: str) -> int:
        """How many items carry this (service, account) pair. Duplicates make
        every first-match verb ambiguous."""
        try:
            out = self._run(["dump-keychain"])
        except KeychainError:
            # Fails OPEN, deliberately, and it is worth being precise about why:
            # the read-back that follows is the actual guarantee. If duplicates
            # exist and the read lands on a different item than the write, the
            # values differ and the read-back rejects the write anyway; the only
            # case this misses is a duplicate whose value already equals what we
            # wrote, which is indistinguishable from success. Failing the write
            # here would trade that non-problem for an outage whenever
            # enumeration is unavailable. Logged so it is never silent.
            _log.warning(
                "could not enumerate the keychain to check for duplicate items; "
                "the write is verified by read-back alone"
            )
            return 1
        return _parse_dump(out, self._config.service, dedupe=False).count(name)

    def delete(self, name: str) -> None:
        """Remove ``name``. Absent item is a no-op, so delete is idempotent."""
        assert_in_scope(name, self._config.secret_prefix)
        self._ensure_ready()
        _reject_untransmittable(name, "name", name)

        if self._keyd is not None:
            try:
                self._keyd_run("delete", name)
            except KeydError as e:
                if e.code == _EXIT_ITEM_NOT_FOUND:
                    return
                raise self._keyd_unavailable(e, f"deleting {name!r}") from None
            return

        try:
            self._run(["delete-generic-password", "-a", name, "-s", self._config.service])
        except KeychainError as e:
            if _is_not_found(e):
                return
            raise self._unavailable(e, f"deleting {name!r}") from None

    # ------------------------------------------------------------- internals

    def _current_or_none(self, name: str) -> Secret | None:
        from kow.backends import SecretNotFoundError

        try:
            return self.fetch(name)
        except SecretNotFoundError:
            return None

    def _keychain_arg(self) -> list[str]:
        """The trailing ``[keychain]`` positional, expanded. Empty when unset,
        which lets ``security`` use the default (login) keychain."""
        raw = self._config.keychain
        if not raw:
            return []
        return [str(Path(raw).expanduser())]

    def _ensure_ready(self) -> None:
        if not self._checked:
            # Set first: a `warn`-mode failure must not re-run the probe on every
            # single fetch.
            self._checked = True
            if self._config.use_helper == "require":
                self._keyd, self._keyd_error = _discover_keyd()
                if self._keyd is not None:
                    self._probe_keyd()
            self._self_check()
        # Re-raised on EVERY call, not just the first. Discovery failure is not
        # a warning that can be logged once and walked past: `require` means the
        # security(1) path is not an acceptable substitute, so silently falling
        # through to it would be the exact downgrade this mode exists to refuse.
        if self._config.use_helper == "require" and self._keyd is None:
            from kow.backends import BackendUnavailableError

            raise BackendUnavailableError(self._keyd_error or "kow-keyd is unavailable")

    def _self_check(self) -> None:
        mode = self._config.self_check
        if mode == "off":
            return

        if self._config.use_helper == "require" and self._keyd is None:
            # Discovery already failed and _ensure_ready is about to say so with
            # the real reason. Probing security(1) here would raise first and
            # report a missing binary this mode does not even use — an accurate
            # error replaced by an irrelevant one.
            return

        if not _is_macos():
            refuse_or_warn(
                mode,
                f"the keychain backend needs macOS; this host is {sys.platform!r}",
                _log,
            )
            return

        if self._keyd is not None:
            # The helper already answered its probe in _ensure_ready. Nothing
            # here applies to it: security(1) is not on this transmit path, so
            # probing it would refuse startup over a binary this mode never runs.
            return

        if not os.access(SECURITY_BIN, os.X_OK):
            refuse_or_warn(mode, f"{SECURITY_BIN} is missing or not executable", _log)
            return
        try:
            self._run(["show-keychain-info"])
        except KeychainError as e:
            target = self._config.keychain or "the default (login) keychain"
            hint = (
                f"unlock it with `security unlock-keychain {self._config.keychain or ''}`".rstrip()
                if _is_locked(e)
                else f"security said: {_sanitise(e.stderr)}"
            )
            refuse_or_warn(mode, f"cannot open {target}: {hint}", _log)

    # ------------------------------------------------------------- the helper

    def _probe_keyd(self) -> None:
        """ADR-0051 §12. Catch a missing, non-executable or wrong-protocol helper
        at configuration time rather than at the first credential fetch.

        Deliberately NOT routed through ``self_check``. That knob decides how
        loudly to complain about a *reachability* problem, and `require` is not
        a preference about loudness — it says the security(1) path is not an
        acceptable substitute. So a failed probe clears ``_keyd``, which makes
        every later call refuse with this reason rather than silently taking the
        other transport, and it does so at `self_check: off` and `warn` too.

        It cannot verify the binary is the RIGHT one. That would need a pinned
        code requirement, which the self-signed path cannot meaningfully supply.
        """
        try:
            self._keyd_run("list")
        except Exception as e:  # noqa: BLE001 — recorded, never swallowed
            detail = _sanitise(e.stderr) if isinstance(e, KeydError) else str(e)
            self._keyd_error = f"kow-keyd at {self._keyd} did not answer a probe: {detail}"
            self._keyd = None

    def _keyd_argv(self, verb: str, name: str | None) -> list[str]:
        argv = [str(self._keyd), verb, "--service", self._config.service]
        if name is not None:
            argv += ["--account", name]
        keychain = self._keychain_arg()
        if keychain:
            argv += ["--keychain", keychain[0]]
        return argv

    def _keyd_run(self, verb: str, name: str | None = None, *, stdin: bytes | None = None) -> bytes:
        """Run one ``kow-keyd`` operation and return its raw stdout.

        Binary in and binary out: the value is bytes on stdin and bytes on
        stdout, with no text decoding at the process boundary. That is the whole
        reason this path exists, and a ``text=True`` here would quietly
        reintroduce the newline handling it was built to avoid.
        """
        from kow.backends import BackendUnavailableError

        argv = self._keyd_argv(verb, name)
        try:
            proc = subprocess.run(  # noqa: S603 — vetted absolute path, list argv, no shell
                argv,
                input=stdin,
                capture_output=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise BackendUnavailableError(
                f"`kow-keyd {verb}` timed out after {self._config.timeout_seconds}s "
                f"(a locked keychain with nobody to unlock it looks like this); unlock it "
                f"with `security unlock-keychain {self._config.keychain or ''}`".rstrip()
                + " and retry"
            ) from None
        except OSError as e:
            raise BackendUnavailableError(
                f"could not execute {self._keyd}: {type(e).__name__}"
            ) from None
        if proc.returncode != 0:
            raise KeydError(proc.returncode, proc.stderr.decode("utf-8", "replace"))
        return proc.stdout

    def _keyd_unavailable(self, e: KeydError, doing: str) -> Exception:
        """Map the helper's exit-code contract onto the backend taxonomy.

        Every message stays on ONE line: these reach the audit log and an
        operator's terminal, and a multi-line backend error wrecks both.
        """
        from kow.backends import BackendUnavailableError

        if e.code == _KEYD_EXIT_INTERACTION:
            # The remedy has to be the sequence that actually works. "re-add it"
            # alone does not: update() pre-reads, the pre-read is refused by the
            # same ACL, and the operator loops. The old transport has to delete
            # the item, because its ACL is the one that permits that.
            return BackendUnavailableError(
                f"kow-keyd was refused while {doing}: the keychain is locked, or this item's ACL "
                "does not list the helper (what an item written before `use_helper: require` "
                "looks like). If it is locked, unlock it with `security unlock-keychain "
                f"{self._config.keychain or ''}`".rstrip()
                + ". If it is the ACL, migrate the "
                "item: set `use_helper: off`, `kow secret remove <NAME>`, set `use_helper: "
                "require` again, then `kow secret add <NAME> --stdin-raw`. See "
                "docs/keychain-helper.md"
            )
        if e.code == _KEYD_EXIT_MISSING_ENTITLEMENT:
            return BackendUnavailableError(
                f"kow-keyd reported errSecMissingEntitlement while {doing}: the helper is not "
                "signed with an identity carrying the keychain access group it asked for"
            )
        if e.code == _KEYD_EXIT_USAGE:
            return BackendUnavailableError(
                f"kow-keyd rejected its own arguments while {doing} — that is a kow bug, not a "
                f"configuration error: {_sanitise(e.stderr)}"
            )
        return BackendUnavailableError(
            f"kow-keyd failed while {doing} (exit {e.code}): {_sanitise(e.stderr)}"
        )

    def _keyd_decode(self, raw: bytes, name: str) -> Secret:
        from kow.backends import BackendUnavailableError

        try:
            return Secret(raw.decode("utf-8"))
        except UnicodeDecodeError:
            raise BackendUnavailableError(
                f"secret {name!r} in the keychain is not valid UTF-8 ({len(raw)} bytes). This "
                "backend is multi-line and NUL-safe over UTF-8, not arbitrary-binary-safe; the "
                "value is withheld rather than mangled with replacement characters"
            ) from None

    def _keyd_accounts(self) -> list[str]:
        """Every account under this service, in the helper's order, NOT
        deduplicated — the duplicate check counts these."""
        raw = self._keyd_run("list")
        return [line for line in raw.decode("utf-8", "replace").split("\n") if line]

    def _argv(self, cmd: list[str]) -> list[str]:
        return [SECURITY_BIN, *cmd, *self._keychain_arg()]

    def _run(self, cmd: list[str]) -> str:
        """Run ``security <cmd> [keychain]`` and return stdout.

        No shell. Callers must never put a secret in ``cmd`` — use
        :meth:`_run_interactive` for that.
        """
        from kow.backends import BackendUnavailableError

        argv = self._argv(cmd)
        try:
            proc = subprocess.run(  # noqa: S603 — absolute binary, list argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise BackendUnavailableError(
                f"`security {cmd[0]}` timed out after {self._config.timeout_seconds}s "
                "(a GUI unlock prompt with nobody to answer it looks exactly like this); "
                f"unlock it with `security unlock-keychain {self._config.keychain or ''}`".rstrip()
                + " and retry"
            ) from None
        except OSError as e:
            raise BackendUnavailableError(
                f"could not execute {SECURITY_BIN}: {type(e).__name__}"
            ) from None
        if proc.returncode != 0:
            raise KeychainError(proc.returncode, proc.stderr or "")
        return proc.stdout

    def _run_interactive(self, cmd: list[str]) -> str:
        """Run one command through ``security -i``, so the command line — and
        therefore any secret in it — reaches the child on stdin instead of argv.

        Only the interactive line is built here; the argv is the constant
        ``[security, -i]``.
        """
        from kow.backends import BackendUnavailableError

        line = " ".join(_quote(a) for a in [*cmd, *self._keychain_arg()]) + "\n"
        try:
            proc = subprocess.run(  # noqa: S603 — absolute binary, list argv, no shell
                [SECURITY_BIN, "-i"],
                input=line,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise BackendUnavailableError(
                f"`security {cmd[0]}` timed out after {self._config.timeout_seconds}s "
                "(most likely a GUI unlock prompt with nobody to answer it); "
                f"unlock it with `security unlock-keychain {self._config.keychain or ''}`".rstrip()
                + " and retry"
            ) from None
        except OSError as e:
            raise BackendUnavailableError(
                f"could not execute {SECURITY_BIN}: {type(e).__name__}"
            ) from None
        # `security -i` exits 0 even when a command inside the session failed,
        # so the exit code alone is not evidence of success. The write path does
        # not rely on it: update() re-reads and compares. stderr is still
        # surfaced when it is non-empty so the failure has a cause attached.
        if proc.returncode != 0 or proc.stderr.strip():
            raise KeychainError(proc.returncode, proc.stderr or "")
        return proc.stdout

    def _unavailable(self, e: KeychainError, doing: str) -> Exception:
        from kow.backends import BackendUnavailableError

        if _is_locked(e):
            kc = self._config.keychain or ""
            return BackendUnavailableError(
                f"keychain is locked or needs interaction while {doing}; unlock it "
                f"with `security unlock-keychain {kc}`".rstrip()
                + " and retry"
            )
        return BackendUnavailableError(
            f"`security` failed while {doing} (exit {e.code}): {_sanitise(e.stderr)}"
        )


# ------------------------------------------------------------------ helpers


_NAME_REMEDY = (
    "secret names must be single-line and NUL-free on both transmit paths: the helper's "
    "`list` output is newline-delimited, and argv cannot carry a NUL"
)
_VALUE_REMEDY = (
    "the `security(1)` transmit path stores single-line, NUL-free values only. To store a "
    "multi-line credential such as a PEM key, set `use_helper: require` (ADR-0051) or use a "
    "networked backend"
)


def _reject_untransmittable(text: str, what: str, name: str) -> None:
    """Refuse bytes the transmit path cannot carry intact.

    On the ``security -i`` path a newline ends the command line, so it would
    truncate the write and store a prefix of the credential, and a NUL
    terminates the C string on the far side of the pipe with the same result.
    Both are refused at the API boundary, before a child is ever spawned —
    storing a silently-shortened credential is the worst outcome available here,
    because everything downstream looks fine.

    On the helper path the *value* is exempt (it travels as raw bytes on stdin)
    but the *name* is not: it rides argv, and it comes back out through
    newline-delimited ``list`` output.
    """
    from kow.backends import BackendUnavailableError

    for bad, label in (("\n", "newline"), ("\r", "carriage return"), ("\0", "NUL byte")):
        if bad in text:
            remedy = _NAME_REMEDY if what == "name" else _VALUE_REMEDY
            raise BackendUnavailableError(f"secret {name!r} has a {label} in its {what}; {remedy}")


def _stat_is_root_locked(st: os.stat_result) -> bool:
    """Owned by root and not writable by group or other — i.e. only root can
    replace it."""
    return st.st_uid == 0 and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def _acl_error(paths: list[Path]) -> str | None:
    """Refuse any path carrying an extended ACL that *grants* access.

    macOS ACLs supplement the BSD mode bits rather than being reflected in them,
    so a root-owned 0755 binary can still carry an ACE handing the operator
    `write` or its directory `delete_child`. Checking `st_mode` alone would call
    that safe. Deny entries only ever subtract, so only `allow` is rejected.

    Fails closed: if the ACLs cannot be read, the candidate is not accepted.
    """
    if not _is_macos():
        return None
    try:
        proc = subprocess.run(  # noqa: S603 — absolute binary, list argv, no shell
            ["/bin/ls", "-lde", *[str(p) for p in paths]],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "could not read the extended ACLs of the helper's path"
    if proc.returncode != 0:
        return "could not read the extended ACLs of the helper's path"
    # ACE lines look like ` 1: user:someone allow write,delete`.
    for line in proc.stdout.splitlines():
        if " allow " in line:
            return (
                f"an extended ACL grants access beyond the file mode ({line.strip()}); "
                "remove it with `chmod -N` on the helper and its parent directories"
            )
    return None


def _keyd_trust_error(path: Path) -> str | None:
    """``None`` if ``path`` is safe to exec as the helper, else why it is not.

    This defends the WRITE path. A substituted binary at this path would be
    handed the credential on stdin, which is the one thing an attacker gains
    that they could not get otherwise — reads need no substitution at all,
    because the legitimate helper answers anyone who runs it (module docstring).

    A check-to-exec race remains and is not closed here. It is narrowed to an
    attacker who can already write into a root-owned directory chain, which is
    a much smaller set than "any process running as the operator", and pretending
    otherwise would be the kind of claim ADR-0051 exists to stop making.
    """
    try:
        st = path.lstat()
    except OSError:
        return f"{path} does not exist"
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a symlink; the helper must be a regular file at a fixed path"
    if not stat.S_ISREG(st.st_mode):
        return f"{path} is not a regular file"
    if not st.st_mode & stat.S_IXUSR:
        return f"{path} is not executable"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} is group- or other-writable"
    if not _stat_is_root_locked(st):
        return f"{path} is not owned by root"
    # A root-owned binary inside a user-writable directory can simply be
    # renamed out of the way, so the whole chain has to hold, not just the leaf.
    for parent in path.parents:
        try:
            pst = parent.stat()
        except OSError:
            return f"the directory {parent} cannot be inspected"
        if not _stat_is_root_locked(pst):
            return f"the directory {parent} is not owned by root or is group- or other-writable"
    return _acl_error([path, *path.parents])


def _discover_keyd() -> tuple[str | None, str | None]:
    """First trustworthy candidate, or ``(None, why-not)`` naming every
    rejection so the operator can see which path was looked at and what was
    wrong with it."""
    reasons: list[str] = []
    for candidate in KEYD_CANDIDATES:
        error = _keyd_trust_error(Path(candidate))
        if error is None:
            return candidate, None
        reasons.append(error)
    return None, (
        "use_helper=require, but no usable kow-keyd was found — build and install it with "
        "`sh helper/build.sh` (see docs/keychain-helper.md). Rejected: " + "; ".join(reasons)
    )


def _unescape_blob(value: str) -> str:
    """Undo `dump-keychain`'s backslash escaping of a quoted blob value.

    Without this a stored name containing a quote or backslash comes back with
    the escapes still in it and silently fails to match the name it was written
    under, so enumeration and the duplicate check would both miss a real item."""
    return value.replace('\\"', '"').replace("\\\\", "\\")


def _is_macos() -> bool:
    """Platform seam. A function rather than an inline comparison so the test
    suite can exercise the macOS paths against a fake ``security`` on Linux CI —
    the alternative is macOS-only tests, i.e. no coverage on the machine where
    the code is actually written."""
    return sys.platform == "darwin"


def _quote(arg: str) -> str:
    """Quote one token for ``security -i``'s line parser.

    The parser understands double quotes and backslash escapes, so escaping
    backslash and double-quote and wrapping in quotes covers every byte a
    single-line value can hold. Correctness here is not taken on faith:
    :meth:`KeychainBackend.update` reads the value back and refuses the write if
    it does not match.
    """
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sanitise(stderr: str) -> str:
    """One line of the child's stderr, bounded. ``security`` never echoes the
    password on stderr; the bound is belt-and-braces against a future verb that
    does, and against a multi-megabyte error flooding the audit log."""
    first = stderr.strip().splitlines()[0] if stderr.strip() else "no error output"
    return first[:200]


def _is_not_found(e: KeychainError) -> bool:
    return e.code == _EXIT_ITEM_NOT_FOUND or any(m in e.stderr for m in _NOT_FOUND_MARKERS)


def _is_locked(e: KeychainError) -> bool:
    return any(m in e.stderr for m in _LOCKED_MARKERS)


def _parse_dump(text: str, service: str, *, dedupe: bool = True) -> list[str]:
    """Extract account names for ``service`` from ``security dump-keychain``.

    Output is a run of per-item blocks, each opening with a ``keychain: "..."``
    line and carrying ``"attr"<blob>="value"`` lines. Attributes whose bytes are
    not printable come out in a hex form this parser does not match — such an
    entry is skipped rather than guessed at, which is safe because kow secret
    names are ``^[A-Z][A-Z0-9_]*$``.
    """
    names: list[str] = []
    acct: str | None = None
    svce: str | None = None

    def flush() -> None:
        if acct and svce == service:
            names.append(acct)

    for line in text.splitlines():
        if _ITEM_BOUNDARY_RE.match(line):
            flush()
            acct = svce = None
            continue
        m = _ATTR_RE.match(line)
        if not m:
            continue
        key, value = m.group("key"), _unescape_blob(m.group("value"))
        if key == "acct":
            acct = value
        elif key == "svce":
            svce = value
    flush()
    # Enumeration wants a name list; the write path's duplicate check wants a
    # tally, and passes dedupe=False to get one.
    return list(dict.fromkeys(names)) if dedupe else names


def _register() -> None:
    from kow.backends import register_backend

    register_backend("keychain", KeychainBackend, KeychainConfig)


_register()
