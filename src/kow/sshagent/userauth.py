"""Parse the to-be-signed userauth blob (RFC 4252 §7; ADR-0053 decision 3).

A SIGN_REQUEST's ``data`` must be an SSH_MSG_USERAUTH_REQUEST for the
``publickey`` method (or OpenSSH's ``publickey-hostbound-v00@openssh.com``
variant, which appends the destination server's host key to the signed
bytes). Anything else is refused: kow is an SSH *authentication* oracle,
not a general signing service — a blob that doesn't parse as userauth never
reaches a private key.
"""

from __future__ import annotations

from dataclasses import dataclass

from kow.sshagent.wire import Reader, WireError

SSH_MSG_USERAUTH_REQUEST = 50

METHOD_PUBLICKEY = b"publickey"
METHOD_HOSTBOUND = b"publickey-hostbound-v00@openssh.com"


@dataclass(frozen=True, slots=True)
class UserauthRequest:
    """The fields kow's policy needs from the signed blob. ``host_key_blob``
    is present only for the hostbound method."""

    session_id: bytes
    username: str
    service: str
    method: bytes
    pubkey_alg: bytes
    pubkey_blob: bytes
    host_key_blob: bytes | None


def parse_userauth(data: bytes) -> UserauthRequest:
    """Parse ``data`` or raise ``WireError``. The parse must consume the
    buffer exactly — trailing bytes mean a blob kow does not understand,
    and signing bytes it does not understand is the one unforgivable move
    for a signing oracle."""
    r = Reader(data)
    session_id = r.string()
    if r.byte() != SSH_MSG_USERAUTH_REQUEST:
        raise WireError("not a userauth request")
    username_raw = r.string()
    service = r.string()
    method = r.string()
    if method not in (METHOD_PUBLICKEY, METHOD_HOSTBOUND):
        raise WireError("not a publickey userauth method")
    if not r.boolean():
        # FALSE marks the try-before-you-sign probe, which is never signed.
        raise WireError("userauth signature flag is FALSE")
    pubkey_alg = r.string()
    pubkey_blob = r.string()
    host_key_blob = r.string() if method == METHOD_HOSTBOUND else None
    r.expect_end()
    try:
        username = username_raw.decode("utf-8")
        service_s = service.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WireError("undecodable username/service") from exc
    return UserauthRequest(
        session_id=session_id,
        username=username,
        service=service_s,
        method=method,
        pubkey_alg=pubkey_alg,
        pubkey_blob=pubkey_blob,
        host_key_blob=host_key_blob,
    )
