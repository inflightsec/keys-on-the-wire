"""The agent-protocol listener (ADR-0053 decisions 1, 4, 5).

Shape mirrors ``credential_endpoint.CredentialEndpoint``: a threaded server
owned by the addon, started on configure and stopped on reload/shutdown.
One thread per connection — agent connections are short (list, bind, sign,
close), and Ansible's ``forks`` gives the concurrency ceiling, bounded by
``max_connections``.

Refusal discipline (G5, agent dialect): every deny — unknown key, unpinned
host, missing session-bind, vault down, malformed anything — answers with
the protocol's own generic ``SSH_AGENT_FAILURE``, indistinguishable from an
ordinary agent with no usable key. Reasons exist only in the audit stream.

G6 ordering: the ``ssh_sign_allowed`` audit record is fsynced BEFORE the
signature bytes are written to the client socket — the signature is the
injection. Do not reorder.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
import threading
import uuid
from pathlib import Path

from kow.backends import BackendUnavailableError, SecretNotFoundError
from kow.sshagent import keys as sshkeys
from kow.sshagent.config import SshSpec
from kow.sshagent.policy import (
    REASON_SIGN_ALLOWED_UNBOUND,
    ResolvedSshBinding,
    decide_sign,
)
from kow.sshagent.sessionbind import (
    MAX_BINDINGS_PER_CONNECTION,
    SESSION_BIND,
    SessionBinding,
    parse_and_verify,
)
from kow.sshagent.userauth import UserauthRequest, parse_userauth
from kow.sshagent.wire import (
    MAX_AGENT_MESSAGE,
    Reader,
    WireError,
    frame,
    put_string,
    put_uint32,
)

_log = logging.getLogger(__name__)

# RFC 9987 message numbers — the subset kow serves. Everything else answers
# SSH_AGENT_FAILURE: kow's key set is operator config, not client state, so
# ADD/REMOVE/LOCK are refused rather than half-implemented.
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_EXTENSION = 27

_FAILURE = frame(bytes([SSH_AGENT_FAILURE]))
_SUCCESS = frame(bytes([SSH_AGENT_SUCCESS]))

# Idle client timeout. An ssh client does its agent round-trips in
# milliseconds; a connection idling longer is holding a thread hostage.
_RECV_TIMEOUT_S = 30.0


class SshAgentServer:
    """Owns the Unix socket, the accept loop, and per-connection threads."""

    def __init__(self, spec: SshSpec, secrets_client, audit) -> None:
        self._spec = spec
        self._client = secrets_client  # CachingSecretsClient
        self._audit = audit  # AuditWriter
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._conn_slots = threading.BoundedSemaphore(spec.max_connections)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._sock is not None:
            raise RuntimeError("SshAgentServer already started")
        # The 0o666 socket mode below is justified ONLY by the SO_PEERCRED
        # uid check on every accept. On platforms without it (macOS uses
        # LOCAL_PEERCRED, unimplemented here) every connection would fail
        # with a logged AttributeError behind a world-connectable socket —
        # a broken service that looks like a crashed agent. Refuse to start
        # instead; an operator who enabled `ssh:` deserves one clear error,
        # not per-connection log spam. (Oracle review, 2026-10-11.)
        if not hasattr(socket, "SO_PEERCRED"):
            raise RuntimeError(
                "the ssh-agent listener requires SO_PEERCRED peer "
                "authentication, which this platform does not provide; "
                "`ssh:` is Linux-only until a LOCAL_PEERCRED path exists"
            )
        path = Path(self._spec.socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            # A stale socket from a previous run; a *live* second instance
            # would have the path bound and bind() below raises EADDRINUSE.
            path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        # World-connectable file mode: SO_PEERCRED against allowed_uids is
        # the access control (mandatory in SshSpec); file perms would only
        # duplicate it less precisely across platforms.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(path, 0o666)  # noqa: S103 # nosec B103 — SO_PEERCRED allowlist is the control
        sock.listen(self._spec.max_connections)
        sock.settimeout(1.0)  # lets the accept loop notice stop()
        self._sock = sock
        self._stopping.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="kow-ssh-agent", daemon=True)
        self._thread.start()
        _log.info("ssh-agent listening on %s", path)

    def stop(self) -> None:
        self._stopping.set()
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        try:
            Path(self._spec.socket_path).unlink(missing_ok=True)
        except OSError:
            _log.warning("could not remove ssh-agent socket on stop", exc_info=True)

    # -- accept / connection ----------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            sock = self._sock
            if sock is None:
                return
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return  # closed by stop()
            if not self._conn_slots.acquire(blocking=False):
                conn.close()  # over max_connections: shed, don't queue
                continue
            threading.Thread(
                target=self._serve_connection_guarded, args=(conn,), daemon=True
            ).start()

    def _serve_connection_guarded(self, conn: socket.socket) -> None:
        try:
            self._serve_connection(conn)
        except Exception:
            # Connection threads must never take the server down; the
            # failure is logged (never with payload bytes) and the client
            # simply loses its connection — which is also what a crashed
            # stock agent looks like.
            _log.exception("ssh-agent connection handler failed")
        finally:
            try:
                conn.close()
            finally:
                self._conn_slots.release()

    def _peer_uid(self, conn: socket.socket) -> int:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        # Same reason as wire.uint32: this value gates the allowed-uid check,
        # so it must not enter that comparison as an untyped Any.
        return int(uid)

    def _serve_connection(self, conn: socket.socket) -> None:
        uid = self._peer_uid(conn)
        if uid not in self._spec.allowed_uids:
            _log.warning("ssh-agent connection from disallowed uid %d refused", uid)
            return  # close without a protocol reply
        conn.settimeout(_RECV_TIMEOUT_S)
        session_bindings: list[SessionBinding] = []
        poisoned_session_ids: set[bytes] = set()
        while not self._stopping.is_set():
            msg = self._recv_message(conn)
            if msg is None:
                return
            conn.sendall(self._dispatch(msg, uid, session_bindings, poisoned_session_ids))

    def _recv_message(self, conn: socket.socket) -> bytes | None:
        """One length-prefixed agent message, or None on EOF/timeout/overrun."""
        header = self._recv_exact(conn, 4)
        if header is None:
            return None
        (length,) = struct.unpack(">I", header)
        if length == 0 or length > MAX_AGENT_MESSAGE:
            return None  # protocol violation: drop the connection
        return self._recv_exact(conn, length)

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except (TimeoutError, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    # -- dispatch ----------------------------------------------------------

    def _dispatch(
        self,
        msg: bytes,
        uid: int,
        session_bindings: list[SessionBinding],
        poisoned_session_ids: set[bytes],
    ) -> bytes:
        try:
            r = Reader(msg)
            msg_type = r.byte()
            if msg_type == SSH_AGENTC_REQUEST_IDENTITIES:
                r.expect_end()
                return self._identities_answer()
            if msg_type == SSH_AGENTC_SIGN_REQUEST:
                key_blob = r.string()
                data = r.string()
                flags = r.uint32()
                r.expect_end()
                return self._handle_sign(
                    key_blob, data, flags, uid, session_bindings, poisoned_session_ids
                )
            if msg_type == SSH_AGENTC_EXTENSION:
                name = r.string()
                if name == SESSION_BIND:
                    return self._handle_session_bind(
                        r.take(r.remaining), uid, session_bindings, poisoned_session_ids
                    )
                return _FAILURE  # unknown extension
            return _FAILURE  # ADD/REMOVE/LOCK/anything else: refused
        except WireError:
            return _FAILURE

    # -- bindings ----------------------------------------------------------

    def _resolve_bindings(self) -> tuple[ResolvedSshBinding, ...]:
        """Resolve config bindings to wire-comparable form. Key fetches go
        through the TTL cache, so this is cheap on the hot path; a binding
        whose key can't be fetched or parsed right now is simply absent from
        the resolved set (it will deny as ``unknown_key``, which is the
        correct fail-closed shape for a vault outage)."""
        out: list[ResolvedSshBinding] = []
        for name, spec in self._spec.bindings.items():
            try:
                key = sshkeys.load_private_key(self._client.get(spec.key_secret))
                pub = sshkeys.public_blob(key)
                # host_keys lines are already validated at config load
                # (SshBindingSpec); the parse here is re-derivation, kept
                # inside the guard so a future format drift degrades to an
                # omitted binding, never an unhandled connection error.
                pinned = tuple(sshkeys.parse_public_key_line(line) for line in spec.host_keys)
            except (
                BackendUnavailableError,
                SecretNotFoundError,
                sshkeys.UnusableKeyError,
            ):
                _log.warning("ssh binding %r unresolvable; omitting", name)
                continue
            out.append(
                ResolvedSshBinding(
                    name=name,
                    key_secret=spec.key_secret,
                    public_key_blob=pub,
                    pinned_host_key_blobs=pinned,
                    users=tuple(spec.users) if spec.users is not None else None,
                    allow_unbound_sessions=spec.allow_unbound_sessions,
                )
            )
        return tuple(out)

    def _identities_answer(self) -> bytes:
        bindings = self._resolve_bindings()
        payload = bytes([SSH_AGENT_IDENTITIES_ANSWER]) + put_uint32(len(bindings))
        for b in bindings:
            payload += put_string(b.public_key_blob) + put_string(b.name.encode())
        return frame(payload)

    # -- session-bind ------------------------------------------------------

    def _handle_session_bind(
        self,
        payload: bytes,
        uid: int,
        session_bindings: list[SessionBinding],
        poisoned_session_ids: set[bytes],
    ) -> bytes:
        try:
            binding = parse_and_verify(payload)
        except WireError:
            return _FAILURE
        if binding.session_id in poisoned_session_ids:
            return _FAILURE
        existing = next(
            (sb for sb in session_bindings if sb.session_id == binding.session_id),
            None,
        )
        if existing is not None:
            if existing.host_key_blob == binding.host_key_blob:
                return _SUCCESS  # idempotent re-bind
            # Same session id, different host key: the documented smuggling
            # shape. Poison the id for the life of the connection so neither
            # record can ever match a sign request.
            session_bindings.remove(existing)
            poisoned_session_ids.add(binding.session_id)
            return _FAILURE
        if len(session_bindings) >= MAX_BINDINGS_PER_CONNECTION:
            return _FAILURE
        session_bindings.append(binding)
        self._audit.emit(
            {
                "type": "ssh_session_bound",
                "request_id": str(uuid.uuid4()),
                "peer_uid": uid,
                "host_key_fpr": sshkeys.fingerprint(binding.host_key_blob),
                "forwarding": binding.is_forwarding,
            }
        )
        return _SUCCESS

    # -- signing -----------------------------------------------------------

    def _handle_sign(
        self,
        key_blob: bytes,
        data: bytes,
        flags: int,
        uid: int,
        session_bindings: list[SessionBinding],
        poisoned_session_ids: set[bytes],
    ) -> bytes:
        request_id = str(uuid.uuid4())
        userauth: UserauthRequest | None
        try:
            userauth = parse_userauth(data)
        except WireError:
            userauth = None
        live = [sb for sb in session_bindings if sb.session_id not in poisoned_session_ids]
        decision = decide_sign(self._resolve_bindings(), key_blob, userauth, tuple(live))
        event = {
            "request_id": request_id,
            "peer_uid": uid,
            "key_fpr": sshkeys.fingerprint(key_blob),
            "binding_name": decision.binding.name if decision.binding else None,
            "reason": decision.reason,
            "user": userauth.username if userauth else None,
            "dest_host_key_fpr": (
                sshkeys.fingerprint(decision.matched_bind.host_key_blob)
                if decision.matched_bind
                else None
            ),
            "session_bound": decision.matched_bind is not None,
        }
        if not decision.allowed:
            self._audit.emit({"type": "ssh_sign_denied", **event})
            return _FAILURE
        assert decision.binding is not None
        try:
            key = sshkeys.load_private_key(self._client.get(decision.binding.key_secret))
            if sshkeys.public_blob(key) != key_blob:
                # The vault value rotated between resolve and fetch; signing
                # with a different key than the client asked for is refused.
                raise sshkeys.UnusableKeyError("key rotated mid-request")
            signature = sshkeys.sign(key, data, flags)
        except (BackendUnavailableError, SecretNotFoundError) as exc:
            self._audit.emit(
                {
                    "type": "ssh_sign_denied",
                    **event,
                    "reason": f"secret_unavailable:{type(exc).__name__}",
                }
            )
            return _FAILURE
        except sshkeys.UnusableKeyError as exc:
            # Covers the SHA-1 refusal and unusable key material. The exact
            # class name is audit detail; the client sees generic failure.
            self._audit.emit(
                {
                    "type": "ssh_sign_denied",
                    **event,
                    "reason": f"unusable_key:{type(exc).__name__}",
                }
            )
            return _FAILURE
        # G6: the allowed record — including the loud unbound-session
        # variant — is fsynced before the signature bytes go anywhere.
        self._audit.emit({"type": "ssh_sign_allowed", **event})
        if decision.reason == REASON_SIGN_ALLOWED_UNBOUND:
            _log.warning(
                "ssh binding %r signed WITHOUT a session-bind destination "
                "check (allow_unbound_sessions)",
                decision.binding.name,
            )
        return frame(bytes([SSH_AGENT_SIGN_RESPONSE]) + put_string(signature))
