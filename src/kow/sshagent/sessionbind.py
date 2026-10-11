"""The ``session-bind@openssh.com`` extension (ADR-0053 decision 3).

Before using an agent, an OpenSSH 8.9+ client sends, per SSH session, the
server's host key, the session identifier, and the server's own signature
over that identifier. Verifying the signature proves the far end *possesses*
the host key — which is what turns kow's binding check from string matching
into cryptography. One record is kept per (connection, session id); a
duplicate session id with a different host key is the documented smuggling
attempt and poisons the session id for the rest of the connection.
"""

from __future__ import annotations

from dataclasses import dataclass

from kow.sshagent.keys import verify_signature
from kow.sshagent.wire import Reader, WireError

SESSION_BIND = b"session-bind@openssh.com"

# Bound per ADR-0049's "bounds on every per-connection structure": an agent
# connection normally sees one bind (one ssh session); nested ProxyJump hops
# re-use the connection, so allow a small multiple, never unbounded growth.
MAX_BINDINGS_PER_CONNECTION = 16


@dataclass(frozen=True, slots=True)
class SessionBinding:
    host_key_blob: bytes
    session_id: bytes
    is_forwarding: bool


def parse_and_verify(payload: bytes) -> SessionBinding:
    """Parse the extension payload and verify the host key's signature over
    the session identifier. Raises ``WireError`` on any failure — malformed,
    unverifiable, and wrong-key are deliberately indistinguishable to the
    client (the server replies a bare failure either way, G5)."""
    r = Reader(payload)
    host_key_blob = r.string()
    session_id = r.string()
    signature_blob = r.string()
    is_forwarding = r.boolean()
    r.expect_end()
    if not session_id:
        raise WireError("empty session id")
    if not verify_signature(host_key_blob, signature_blob, session_id):
        raise WireError("session-bind signature does not verify")
    return SessionBinding(
        host_key_blob=host_key_blob,
        session_id=session_id,
        is_forwarding=is_forwarding,
    )
