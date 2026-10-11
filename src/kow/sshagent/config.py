"""Config models for the ``ssh:`` top-level section (ADR-0053 decision 1).

A listener is not a request, so — like ``credential_endpoint:`` (ADR-0050)
and the proposed ``postgres:`` section — SSH bindings live outside the
``secrets:`` map. ``extra="forbid"`` everywhere, per the house rule: a
``host_key:`` typo for ``host_keys:`` must fail the load, not silently
weaken a destination check.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_STRICT_MODEL = ConfigDict(extra="forbid")

# Modest by design: an operator with more concurrent Ansible forks than this
# should raise it consciously, not discover an unbounded thread pool.
_DEFAULT_MAX_CONNECTIONS = 64


class SshBindingSpec(BaseModel):
    """One brokered SSH identity: a vault-held private key plus the
    destinations (pinned host public keys) it may authenticate to."""

    model_config = _STRICT_MODEL

    # Backend secret holding the private key (OpenSSH/PEM text, unencrypted —
    # the vault is the encryption at rest).
    key_secret: str = Field(min_length=1)
    # OpenSSH public key lines ("ssh-ed25519 AAAA... [comment]") for every
    # permitted destination host. The session-bind host key must match one
    # byte-for-byte. Empty only alongside allow_unbound_sessions — a binding
    # that pins nothing and requires binding could never sign.
    host_keys: list[str] = Field(default_factory=list)
    # Optional username pin (the ssh-add -h "user@host" semantics). None
    # means any username; an empty list is rejected — deny-all must be
    # deletion of the binding, not an ambiguous [].
    users: list[str] | None = None
    # The loud opt-out (ADR-0053 decision 3): permit signing for clients that
    # never sent session-bind (non-OpenSSH implementations, OpenSSH < 8.9).
    # With it, this binding has NO destination check at all; every such
    # signature is audited with the distinct reason
    # `sign_allowed_unbound_session`.
    allow_unbound_sessions: bool = False

    @field_validator("host_keys")
    @classmethod
    def _host_keys_parse(cls, v: list[str]) -> list[str]:
        """Fail the CONFIG LOAD on a malformed host key line — a typo'd pin
        must be a startup error, not a runtime 'binding silently omitted'."""
        from kow.sshagent.keys import UnusableKeyError, parse_public_key_line

        for line in v:
            try:
                parse_public_key_line(line)
            except UnusableKeyError as exc:
                raise ValueError(
                    f"host_keys entry is not a valid OpenSSH public key line: {exc}"
                ) from exc
        return v

    @field_validator("users")
    @classmethod
    def _users_not_empty(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError(
                "users: [] is ambiguous — omit the field for any-user, or "
                "delete the binding to deny it entirely"
            )
        return v

    @model_validator(mode="after")
    def _reachable(self) -> SshBindingSpec:
        if not self.host_keys and not self.allow_unbound_sessions:
            raise ValueError(
                "binding pins no host_keys and does not allow_unbound_sessions; "
                "it could never sign anything. Pin the destination host keys."
            )
        return self


class SshSpec(BaseModel):
    """The ``ssh:`` section: one Unix-socket agent listener."""

    model_config = _STRICT_MODEL

    enabled: bool = True
    # Unix socket path the agent listens on; SSH_AUTH_SOCK for callers.
    # Created 0666 inside a 0755-parented dir — filesystem perms are the
    # defense-in-depth layer; allowed_uids (SO_PEERCRED) is the control.
    socket_path: str = Field(min_length=1)
    # MANDATORY uid allowlist, checked via SO_PEERCRED on every accept. There
    # is no "any uid" value on purpose: a world-usable signing oracle must be
    # impossible to configure by omission.
    allowed_uids: list[int] = Field(min_length=1)
    max_connections: int = Field(default=_DEFAULT_MAX_CONNECTIONS, ge=1, le=1024)
    bindings: dict[str, SshBindingSpec]

    @field_validator("socket_path")
    @classmethod
    def _socket_path_shell_safe(cls, v: str) -> str:
        # The path is projected into the single-quoted `kow env` export line;
        # a quote or newline in it would be a shell-injection seam.
        if "'" in v or "\n" in v or "\r" in v:
            raise ValueError("socket_path must not contain quotes or newlines")
        return v

    @model_validator(mode="after")
    def _has_bindings(self) -> SshSpec:
        if self.enabled and not self.bindings:
            raise ValueError("ssh: is enabled with no bindings; delete the section or add one")
        return self
