"""Pure sign-request policy (ADR-0053 decisions 3-4), mirroring ``decide()``.

``decide_sign`` takes the resolved bindings plus the request facts and
returns a verdict; it does no I/O, fetches nothing, and signs nothing. The
server EXECUTES the verdict (fetch, sign, and the G6-ordered audit). Every
deny reason below reaches the client as the same generic agent failure —
the reasons exist for the audit stream only.
"""

from __future__ import annotations

from dataclasses import dataclass

from kow.sshagent.sessionbind import SessionBinding
from kow.sshagent.userauth import METHOD_HOSTBOUND, UserauthRequest

REASON_SIGN_ALLOWED = "sign_allowed"
REASON_SIGN_ALLOWED_UNBOUND = "sign_allowed_unbound_session"
REASON_UNKNOWN_KEY = "unknown_key"
REASON_NOT_USERAUTH = "not_userauth"
REASON_KEY_MISMATCH = "userauth_key_mismatch"
REASON_USER_NOT_PERMITTED = "user_not_permitted"
REASON_NO_SESSION_BIND = "no_session_bind"
REASON_HOST_NOT_PINNED = "host_key_not_pinned"
REASON_HOSTBOUND_MISMATCH = "hostbound_host_key_mismatch"
REASON_SERVICE_NOT_PERMITTED = "userauth_service_not_permitted"
REASON_DUPLICATE_KEY = "duplicate_public_key_binding"

# RFC 4252 §7: the service a publickey userauth request starts after auth.
# `ssh-connection` is the only one an SSH login uses. The field was parsed and
# never checked, which left this oracle willing to endorse authentication for
# any service name a pinned server happens to accept — a broader capability
# than "may log in to these hosts". (Oracle review, 2026-09-23.)
PERMITTED_SERVICE = "ssh-connection"


@dataclass(frozen=True, slots=True)
class ResolvedSshBinding:
    """One config binding, resolved to wire-comparable form."""

    name: str
    key_secret: str
    public_key_blob: bytes
    pinned_host_key_blobs: tuple[bytes, ...]
    users: tuple[str, ...] | None
    allow_unbound_sessions: bool


@dataclass(frozen=True, slots=True)
class SignDecision:
    allowed: bool
    reason: str
    binding: ResolvedSshBinding | None
    # The session binding the verdict matched, when one did — carried so the
    # audit event can name the destination host key without re-deriving it.
    matched_bind: SessionBinding | None


def _deny(reason: str, binding: ResolvedSshBinding | None = None) -> SignDecision:
    return SignDecision(allowed=False, reason=reason, binding=binding, matched_bind=None)


def _check_identity(
    binding: ResolvedSshBinding,
    requested_key_blob: bytes,
    userauth: UserauthRequest,
) -> SignDecision | None:
    """The WHO half: is this signed blob a request we are willing to endorse
    at all? Returns a deny, or None to continue to the destination checks.
    Split out from ``decide_sign`` to keep each half under the complexity gate
    and to keep the two question types separately readable."""
    # The key inside the signed blob must be the key being signed with —
    # otherwise the signature endorses an authentication by a different key.
    if userauth.pubkey_blob != requested_key_blob:
        return _deny(REASON_KEY_MISMATCH, binding)
    if binding.users is not None and userauth.username not in binding.users:
        return _deny(REASON_USER_NOT_PERMITTED, binding)
    if userauth.service != PERMITTED_SERVICE:
        return _deny(REASON_SERVICE_NOT_PERMITTED, binding)
    return None


def decide_sign(
    bindings: tuple[ResolvedSshBinding, ...],
    requested_key_blob: bytes,
    userauth: UserauthRequest | None,
    session_bindings: tuple[SessionBinding, ...],
) -> SignDecision:
    """Verdict for one SIGN_REQUEST.

    ``userauth`` is None when the data blob failed to parse as an RFC 4252
    publickey request — already a terminal deny, but routed through here so
    the verdict taxonomy lives in exactly one place."""
    matches = [b for b in bindings if b.public_key_blob == requested_key_blob]
    if not matches:
        return _deny(REASON_UNKNOWN_KEY)
    if len(matches) > 1:
        # Two bindings resolving to the same public key have, in general,
        # DIFFERENT users / pins / unbound settings, so `next()` would let
        # declaration order decide which policy applies — silently, and in the
        # permissive direction if the looser one happens to be first. Fail
        # closed and make the operator disambiguate. (Oracle review, 2026-09-23.)
        return _deny(REASON_DUPLICATE_KEY, None)
    binding = matches[0]
    if userauth is None:
        return _deny(REASON_NOT_USERAUTH, binding)
    identity_deny = _check_identity(binding, requested_key_blob, userauth)
    if identity_deny is not None:
        return identity_deny

    matched = next((sb for sb in session_bindings if sb.session_id == userauth.session_id), None)
    if matched is None:
        if binding.allow_unbound_sessions:
            # The loud opt-out (ADR-0053 decision 3): no destination check at
            # all for this signature. Allowed, but never silently — the
            # distinct reason keeps it separable in the audit stream.
            return SignDecision(
                allowed=True,
                reason=REASON_SIGN_ALLOWED_UNBOUND,
                binding=binding,
                matched_bind=None,
            )
        return _deny(REASON_NO_SESSION_BIND, binding)
    if matched.host_key_blob not in binding.pinned_host_key_blobs:
        return _deny(REASON_HOST_NOT_PINNED, binding)
    # Hostbound userauth embeds the destination host key in the signed bytes
    # themselves; it must be the host key the session was bound to.
    if userauth.method == METHOD_HOSTBOUND and userauth.host_key_blob != matched.host_key_blob:
        return _deny(REASON_HOSTBOUND_MISMATCH, binding)
    return SignDecision(
        allowed=True, reason=REASON_SIGN_ALLOWED, binding=binding, matched_bind=matched
    )
