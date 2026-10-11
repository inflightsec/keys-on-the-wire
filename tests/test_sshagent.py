"""ADR-0053 ssh-agent signing oracle — protocol, policy, and e2e socket tests.

The e2e cases speak the real agent protocol over a real Unix socket against a
running SshAgentServer, with keys generated in-test and a stub secrets client
(the server's only demand of it is ``.get(name) -> Secret``). Every G-mapped
property from the ADR gets an explicit case:

  G1  — no test ever needs the private key on the client side of the socket
  G4  — backend outage answers generic failure
  G5  — every deny is byte-identical generic SSH_AGENT_FAILURE
  G6  — the allowed audit record is on disk before the signature arrives
  G3' — signing requires a verified session-bind to a pinned host key
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from kow.audit import AuditWriter
from kow.backends import BackendUnavailableError
from kow.secret import Secret
from kow.sshagent import keys as sshkeys
from kow.sshagent.config import SshBindingSpec, SshSpec
from kow.sshagent.policy import (
    REASON_HOST_NOT_PINNED,
    REASON_HOSTBOUND_MISMATCH,
    REASON_KEY_MISMATCH,
    REASON_NO_SESSION_BIND,
    REASON_NOT_USERAUTH,
    REASON_SIGN_ALLOWED,
    REASON_SIGN_ALLOWED_UNBOUND,
    REASON_UNKNOWN_KEY,
    REASON_USER_NOT_PERMITTED,
    ResolvedSshBinding,
    decide_sign,
)
from kow.sshagent.server import (
    SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
    SSH_AGENT_SUCCESS,
    SSH_AGENTC_EXTENSION,
    SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST,
    SshAgentServer,
)
from kow.sshagent.sessionbind import SessionBinding, parse_and_verify
from kow.sshagent.userauth import (
    METHOD_HOSTBOUND,
    METHOD_PUBLICKEY,
    SSH_MSG_USERAUTH_REQUEST,
    parse_userauth,
)
from kow.sshagent.wire import Reader, WireError, put_string, put_uint32

# ---------------------------------------------------------------- fixtures


def _ed25519_pem() -> tuple[str, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    return pem, key


def _openssh_pub_line(key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )


class StubClient:
    """The .get(name) surface of CachingSecretsClient."""

    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def get(self, name: str, ctx: object | None = None) -> Secret:
        if name not in self.values:
            raise BackendUnavailableError(f"no secret {name}")
        return Secret(self.values[name])


def _userauth_blob(
    session_id: bytes,
    pubkey_blob: bytes,
    *,
    username: bytes = b"ansible",
    method: bytes = METHOD_PUBLICKEY,
    host_key_blob: bytes | None = None,
    sig_flag: bool = True,
) -> bytes:
    blob = (
        put_string(session_id)
        + bytes([SSH_MSG_USERAUTH_REQUEST])
        + put_string(username)
        + put_string(b"ssh-connection")
        + put_string(method)
        + (b"\x01" if sig_flag else b"\x00")
        + put_string(b"ssh-ed25519")
        + put_string(pubkey_blob)
    )
    if method == METHOD_HOSTBOUND:
        assert host_key_blob is not None
        blob += put_string(host_key_blob)
    return blob


def _session_bind_payload(
    host_key: ed25519.Ed25519PrivateKey,
    session_id: bytes,
    *,
    forwarding: bool = False,
    corrupt_sig: bool = False,
) -> bytes:
    host_blob = sshkeys.public_blob(host_key)
    sig = sshkeys.sign(host_key, session_id, 0)
    if corrupt_sig:
        sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    return (
        put_string(host_blob)
        + put_string(session_id)
        + put_string(sig)
        + (b"\x01" if forwarding else b"\x00")
    )


# ---------------------------------------------------------------- wire


def test_reader_bounds_and_trailing() -> None:
    r = Reader(put_string(b"abc"))
    assert r.string() == b"abc"
    r.expect_end()
    with pytest.raises(WireError):
        Reader(put_uint32(10) + b"short").string()
    with pytest.raises(WireError):
        r2 = Reader(put_string(b"x") + b"junk")
        r2.string()
        r2.expect_end()


# ---------------------------------------------------------------- keys


def test_private_key_roundtrip_and_pub_line_parity() -> None:
    pem, key = _ed25519_pem()
    loaded = sshkeys.load_private_key(Secret(pem))
    blob = sshkeys.public_blob(loaded)
    assert blob == sshkeys.parse_public_key_line(_openssh_pub_line(key))
    sig = sshkeys.sign(loaded, b"data", 0)
    assert sshkeys.verify_signature(blob, sig, b"data")
    assert not sshkeys.verify_signature(blob, sig, b"other-data")


def test_rsa_sha1_refused_sha2_signs() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(sshkeys.UnusableKeyError):
        sshkeys.sign(key, b"data", 0)  # no SHA-2 flag -> legacy SHA-1 -> refuse
    blob = sshkeys.public_blob(key)
    sig = sshkeys.sign(key, b"data", sshkeys.SSH_AGENT_RSA_SHA2_256)
    assert sshkeys.verify_signature(blob, sig, b"data")


# ---------------------------------------------------------------- userauth


def test_userauth_parse_happy_and_hostbound() -> None:
    _, key = _ed25519_pem()
    pub = sshkeys.public_blob(key)
    ua = parse_userauth(_userauth_blob(b"S" * 32, pub))
    assert (ua.username, ua.service, ua.method) == ("ansible", "ssh-connection", METHOD_PUBLICKEY)
    host_blob = sshkeys.public_blob(ed25519.Ed25519PrivateKey.generate())
    ua2 = parse_userauth(
        _userauth_blob(b"S" * 32, pub, method=METHOD_HOSTBOUND, host_key_blob=host_blob)
    )
    assert ua2.host_key_blob == host_blob


@pytest.mark.parametrize(
    "mutator",
    [
        lambda b: b + b"trailing",  # trailing bytes
        lambda b: b[:-1],  # truncated
        lambda b: b.replace(bytes([SSH_MSG_USERAUTH_REQUEST]), b"\x33", 1),  # not userauth
    ],
)
def test_userauth_rejects_malformed(mutator) -> None:
    _, key = _ed25519_pem()
    blob = _userauth_blob(b"S" * 32, sshkeys.public_blob(key))
    with pytest.raises(WireError):
        parse_userauth(mutator(blob))


def test_userauth_rejects_probe_flag_false() -> None:
    _, key = _ed25519_pem()
    blob = _userauth_blob(b"S" * 32, sshkeys.public_blob(key), sig_flag=False)
    with pytest.raises(WireError):
        parse_userauth(blob)


# ---------------------------------------------------------------- session-bind


def test_session_bind_verifies_and_rejects_tamper() -> None:
    host = ed25519.Ed25519PrivateKey.generate()
    sb = parse_and_verify(_session_bind_payload(host, b"S" * 32))
    assert sb.host_key_blob == sshkeys.public_blob(host)
    with pytest.raises(WireError):
        parse_and_verify(_session_bind_payload(host, b"S" * 32, corrupt_sig=True))


# ---------------------------------------------------------------- policy


def _binding(**over) -> ResolvedSshBinding:
    defaults = {
        "name": "B",
        "key_secret": "KEY",
        "public_key_blob": b"pub",
        "pinned_host_key_blobs": (b"host1",),
        "users": None,
        "allow_unbound_sessions": False,
    }
    return ResolvedSshBinding(**{**defaults, **over})


def _ua(session_id: bytes = b"sid", pubkey: bytes = b"pub", **over):
    from kow.sshagent.userauth import UserauthRequest

    defaults = {
        "session_id": session_id,
        "username": "ansible",
        "service": "ssh-connection",
        "method": METHOD_PUBLICKEY,
        "pubkey_alg": b"ssh-ed25519",
        "pubkey_blob": pubkey,
        "host_key_blob": None,
    }
    return UserauthRequest(**{**defaults, **over})


_BOUND = SessionBinding(host_key_blob=b"host1", session_id=b"sid", is_forwarding=False)


@pytest.mark.parametrize(
    ("bindings", "key", "ua", "binds", "allowed", "reason"),
    [
        ((), b"pub", _ua(), (), False, REASON_UNKNOWN_KEY),
        ((_binding(),), b"pub", None, (), False, REASON_NOT_USERAUTH),
        ((_binding(),), b"pub", _ua(pubkey=b"other"), (), False, REASON_KEY_MISMATCH),
        (
            (_binding(users=("root",)),),
            b"pub",
            _ua(),
            (_BOUND,),
            False,
            REASON_USER_NOT_PERMITTED,
        ),
        ((_binding(),), b"pub", _ua(), (), False, REASON_NO_SESSION_BIND),
        (
            (_binding(pinned_host_key_blobs=(b"otherhost",)),),
            b"pub",
            _ua(),
            (_BOUND,),
            False,
            REASON_HOST_NOT_PINNED,
        ),
        (
            (_binding(),),
            b"pub",
            _ua(method=METHOD_HOSTBOUND, host_key_blob=b"evilhost"),
            (_BOUND,),
            False,
            REASON_HOSTBOUND_MISMATCH,
        ),
        ((_binding(),), b"pub", _ua(), (_BOUND,), True, REASON_SIGN_ALLOWED),
        (
            (_binding(allow_unbound_sessions=True, pinned_host_key_blobs=()),),
            b"pub",
            _ua(),
            (),
            True,
            REASON_SIGN_ALLOWED_UNBOUND,
        ),
        (
            (_binding(),),
            b"pub",
            _ua(method=METHOD_HOSTBOUND, host_key_blob=b"host1"),
            (_BOUND,),
            True,
            REASON_SIGN_ALLOWED,
        ),
    ],
)
def test_decide_sign_taxonomy(bindings, key, ua, binds, allowed, reason) -> None:
    d = decide_sign(bindings, key, ua, binds)
    assert (d.allowed, d.reason) == (allowed, reason)


# ---------------------------------------------------------------- e2e socket


class AgentConn:
    """Minimal agent-protocol client for the tests."""

    def __init__(self, path: str) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect(path)

    def rpc(self, payload: bytes) -> bytes:
        self.sock.sendall(put_uint32(len(payload)) + payload)
        header = self._exact(4)
        (n,) = struct.unpack(">I", header)
        return self._exact(n)

    def _exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            assert chunk, "server closed mid-message"
            buf += chunk
        return buf

    def close(self) -> None:
        self.sock.close()


@pytest.fixture()
def running_server(tmp_path: Path):
    """A live server: one ed25519 binding pinned to one host key."""
    pem, client_key = _ed25519_pem()
    host_key = ed25519.Ed25519PrivateKey.generate()
    other_host_key = ed25519.Ed25519PrivateKey.generate()
    spec = SshSpec(
        socket_path=str(tmp_path / "agent.sock"),
        allowed_uids=[os.getuid()],
        bindings={
            "MAINFRAME": SshBindingSpec(
                key_secret="SSH_KEY_MAINFRAME",
                host_keys=[_openssh_pub_line(host_key)],
                users=["ansible"],
            )
        },
    )
    audit_path = tmp_path / "audit.jsonl"
    server = SshAgentServer(
        spec,
        StubClient({"SSH_KEY_MAINFRAME": pem}),
        AuditWriter(str(audit_path)),
    )
    server.start()
    try:
        yield {
            "spec": spec,
            "client_key": client_key,
            "host_key": host_key,
            "other_host_key": other_host_key,
            "audit_path": audit_path,
        }
    finally:
        server.stop()


def _audit_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_e2e_identities_bind_sign(running_server) -> None:
    env = running_server
    conn = AgentConn(env["spec"].socket_path)
    try:
        # identities: exactly the one bound public key
        ans = conn.rpc(bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
        r = Reader(ans)
        assert r.byte() == SSH_AGENT_IDENTITIES_ANSWER
        assert r.uint32() == 1
        pub_blob = r.string()
        assert r.string() == b"MAINFRAME"
        assert pub_blob == sshkeys.public_blob(env["client_key"])

        # session-bind to the pinned host
        session_id = os.urandom(32)
        bind = conn.rpc(
            bytes([SSH_AGENTC_EXTENSION])
            + put_string(b"session-bind@openssh.com")
            + _session_bind_payload(env["host_key"], session_id)
        )
        assert bind == bytes([SSH_AGENT_SUCCESS])

        # sign the matching userauth blob
        data = _userauth_blob(session_id, pub_blob)
        resp = conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(data)
            + put_uint32(0)
        )
        r = Reader(resp)
        assert r.byte() == SSH_AGENT_SIGN_RESPONSE
        signature = r.string()
        r.expect_end()
        assert sshkeys.verify_signature(pub_blob, signature, data)
    finally:
        conn.close()

    events = _audit_events(env["audit_path"])
    types = [e["type"] for e in events]
    assert types == ["ssh_session_bound", "ssh_sign_allowed"]
    allowed = events[-1]
    assert allowed["reason"] == REASON_SIGN_ALLOWED
    assert allowed["binding_name"] == "MAINFRAME"
    assert allowed["user"] == "ansible"
    assert allowed["session_bound"] is True
    # minimization: no raw key material anywhere in the stream — neither the
    # private key nor the base64 of any public blob (fingerprints only)
    import base64 as _b64

    raw = env["audit_path"].read_text()
    assert "PRIVATE KEY" not in raw
    assert _b64.b64encode(pub_blob).decode()[:24] not in raw
    assert _b64.b64encode(sshkeys.public_blob(env["host_key"])).decode()[:24] not in raw


def _deny_cases(env, conn, pub_blob):
    """Each returns (label, response_bytes) — all must be generic FAILURE."""
    session_id = os.urandom(32)
    unbound_data = _userauth_blob(session_id, pub_blob)
    yield (
        "no_session_bind",
        conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(unbound_data)
            + put_uint32(0)
        ),
    )
    yield (
        "unknown_key",
        conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(b"not-a-known-key")
            + put_string(unbound_data)
            + put_uint32(0)
        ),
    )
    yield (
        "not_userauth",
        conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(b"arbitrary bytes are never signed")
            + put_uint32(0)
        ),
    )
    # bind to an UNPINNED host, then try to sign toward it
    sid2 = os.urandom(32)
    assert conn.rpc(
        bytes([SSH_AGENTC_EXTENSION])
        + put_string(b"session-bind@openssh.com")
        + _session_bind_payload(env["other_host_key"], sid2)
    ) == bytes([SSH_AGENT_SUCCESS])
    yield (
        "host_key_not_pinned",
        conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(_userauth_blob(sid2, pub_blob))
            + put_uint32(0)
        ),
    )
    # wrong username against the users: pin
    sid3 = os.urandom(32)
    assert conn.rpc(
        bytes([SSH_AGENTC_EXTENSION])
        + put_string(b"session-bind@openssh.com")
        + _session_bind_payload(env["host_key"], sid3)
    ) == bytes([SSH_AGENT_SUCCESS])
    yield (
        "user_not_permitted",
        conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(_userauth_blob(sid3, pub_blob, username=b"root"))
            + put_uint32(0)
        ),
    )
    # mutating agent operations are refused
    yield ("add_identity_refused", conn.rpc(bytes([17]) + b"\x00" * 8))
    yield ("lock_refused", conn.rpc(bytes([22]) + put_string(b"pw")))
    yield (
        "unknown_extension_refused",
        conn.rpc(bytes([SSH_AGENTC_EXTENSION]) + put_string(b"nope@example.com")),
    )


def test_e2e_all_denials_are_generic_failure(running_server) -> None:
    """G5: every refusal is the identical single-byte SSH_AGENT_FAILURE."""
    env = running_server
    conn = AgentConn(env["spec"].socket_path)
    try:
        pub_blob = sshkeys.public_blob(env["client_key"])
        for label, resp in _deny_cases(env, conn, pub_blob):
            assert resp == bytes([SSH_AGENT_FAILURE]), label
    finally:
        conn.close()
    reasons = {
        e["reason"] for e in _audit_events(env["audit_path"]) if e["type"] == "ssh_sign_denied"
    }
    assert {
        REASON_NO_SESSION_BIND,
        REASON_UNKNOWN_KEY,
        REASON_NOT_USERAUTH,
        REASON_HOST_NOT_PINNED,
        REASON_USER_NOT_PERMITTED,
    } <= reasons


def test_e2e_backend_outage_fails_closed(tmp_path: Path) -> None:
    """G4: vault down -> identities empty, sign denies generic."""
    host_key = ed25519.Ed25519PrivateKey.generate()
    spec = SshSpec(
        socket_path=str(tmp_path / "agent.sock"),
        allowed_uids=[os.getuid()],
        bindings={
            "B": SshBindingSpec(key_secret="MISSING", host_keys=[_openssh_pub_line(host_key)])
        },
    )
    server = SshAgentServer(spec, StubClient({}), AuditWriter(str(tmp_path / "a.jsonl")))
    server.start()
    try:
        conn = AgentConn(spec.socket_path)
        try:
            ans = conn.rpc(bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
            r = Reader(ans)
            assert r.byte() == SSH_AGENT_IDENTITIES_ANSWER
            assert r.uint32() == 0
            resp = conn.rpc(
                bytes([SSH_AGENTC_SIGN_REQUEST])
                + put_string(b"whatever")
                + put_string(b"data")
                + put_uint32(0)
            )
            assert resp == bytes([SSH_AGENT_FAILURE])
        finally:
            conn.close()
    finally:
        server.stop()


def test_e2e_disallowed_uid_gets_closed(tmp_path: Path) -> None:
    """A peer uid outside allowed_uids is dropped without a protocol reply."""
    pem, _ = _ed25519_pem()
    host_key = ed25519.Ed25519PrivateKey.generate()
    spec = SshSpec(
        socket_path=str(tmp_path / "agent.sock"),
        allowed_uids=[0],  # never the test uid
        bindings={"B": SshBindingSpec(key_secret="K", host_keys=[_openssh_pub_line(host_key)])},
    )
    server = SshAgentServer(spec, StubClient({"K": pem}), AuditWriter(str(tmp_path / "a.jsonl")))
    server.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(spec.socket_path)
        sock.sendall(put_uint32(1) + bytes([SSH_AGENTC_REQUEST_IDENTITIES]))
        # Clean EOF or RST are both "dropped, nothing served" — the assertion
        # is that no protocol byte ever comes back.
        with contextlib.suppress(ConnectionResetError):
            assert sock.recv(1) == b""
        sock.close()
    finally:
        server.stop()


def test_e2e_duplicate_session_id_different_host_poisons(running_server) -> None:
    env = running_server
    conn = AgentConn(env["spec"].socket_path)
    try:
        pub_blob = sshkeys.public_blob(env["client_key"])
        session_id = os.urandom(32)
        ext = bytes([SSH_AGENTC_EXTENSION]) + put_string(b"session-bind@openssh.com")
        assert conn.rpc(ext + _session_bind_payload(env["host_key"], session_id)) == bytes(
            [SSH_AGENT_SUCCESS]
        )
        # same session id re-bound to a DIFFERENT (even pinned-elsewhere) key
        assert conn.rpc(ext + _session_bind_payload(env["other_host_key"], session_id)) == bytes(
            [SSH_AGENT_FAILURE]
        )
        # the poisoned session id can no longer authorize anything
        resp = conn.rpc(
            bytes([SSH_AGENTC_SIGN_REQUEST])
            + put_string(pub_blob)
            + put_string(_userauth_blob(session_id, pub_blob))
            + put_uint32(0)
        )
        assert resp == bytes([SSH_AGENT_FAILURE])
    finally:
        conn.close()


# ---------------------------------------------------------------- config


def test_config_rejects_unreachable_binding() -> None:
    with pytest.raises(ValueError, match="never sign"):
        SshBindingSpec(key_secret="K", host_keys=[])


def test_config_requires_allowed_uids() -> None:
    with pytest.raises(ValueError):
        SshSpec(socket_path="/tmp/x", allowed_uids=[], bindings={})


def test_config_rejects_malformed_host_key_line() -> None:
    with pytest.raises(ValueError, match="OpenSSH public key line"):
        SshBindingSpec(key_secret="K", host_keys=["not a key line"])


# ── Oracle review 2026-09-23: two gaps in decide_sign ────────────────────────


def test_sign_denied_when_service_is_not_ssh_connection() -> None:
    """RFC 4252 §7's service field was parsed and never checked, so the oracle
    would endorse authentication for any service a pinned server accepts —
    broader than the "may log in to these hosts" capability it advertises."""
    from kow.sshagent.policy import REASON_SERVICE_NOT_PERMITTED, decide_sign

    d = decide_sign((_binding(),), b"pub", _ua(service="some-other-service"), (_BOUND,))
    assert d.allowed is False
    assert d.reason == REASON_SERVICE_NOT_PERMITTED


def test_sign_allowed_for_ssh_connection() -> None:
    """Control for the check above: the ordinary service still signs."""
    from kow.sshagent.policy import REASON_SIGN_ALLOWED, decide_sign

    d = decide_sign((_binding(),), b"pub", _ua(service="ssh-connection"), (_BOUND,))
    assert d.allowed is True
    assert d.reason == REASON_SIGN_ALLOWED


def test_duplicate_public_key_bindings_fail_closed() -> None:
    """Two bindings resolving to the same public key carry different policies,
    so first-match would let declaration order silently decide which applies —
    permissively, if the looser one happens to be first. Refuse instead."""
    from kow.sshagent.policy import REASON_DUPLICATE_KEY, decide_sign

    strict = _binding(name="strict", users=("ansible",))
    loose = _binding(name="loose", users=None, allow_unbound_sessions=True)
    d = decide_sign((strict, loose), b"pub", _ua(), (_BOUND,))
    assert d.allowed is False
    assert d.reason == REASON_DUPLICATE_KEY
    # And it must not leak which of the two it nearly picked.
    assert d.binding is None


# ── loop #05: the sign-execution fail-closed paths and their audit records ───


class _RotatingClient:
    """Returns a different secret on the Nth call. Models a vault value that
    rotates between `_resolve_bindings()` and the fetch that precedes signing —
    the window in which the authorized key and the signing key can diverge."""

    def __init__(self, values: list[str | Exception]) -> None:
        self._values = values
        self.calls = 0

    def get(self, name: str, ctx: object | None = None) -> Secret:
        v = self._values[min(self.calls, len(self._values) - 1)]
        self.calls += 1
        if isinstance(v, Exception):
            raise v
        return Secret(v)


def _sign_rpc(conn: AgentConn, pub_blob: bytes, data: bytes, flags: int = 0) -> bytes:
    return conn.rpc(
        bytes([SSH_AGENTC_SIGN_REQUEST])
        + put_string(pub_blob)
        + put_string(data)
        + put_uint32(flags)
    )


def _server_with(
    tmp_path: Path, client, binding: SshBindingSpec
) -> tuple[SshAgentServer, SshSpec, Path]:
    spec = SshSpec(
        socket_path=str(tmp_path / "agent.sock"),
        allowed_uids=[os.getuid()],
        bindings={"B": binding},
    )
    audit_path = tmp_path / "audit.jsonl"
    return SshAgentServer(spec, client, AuditWriter(str(audit_path))), spec, audit_path


def test_key_rotated_between_authorize_and_sign_is_refused(tmp_path: Path) -> None:
    """The verdict authorizes a specific public key. If the vault value changes
    before the fetch, signing would use a key the policy never approved."""
    pem_a, key_a = _ed25519_pem()
    pem_b, _ = _ed25519_pem()
    host_key = ed25519.Ed25519PrivateKey.generate()
    client = _RotatingClient([pem_a, pem_b])  # call 1 = resolve, call 2 = pre-sign fetch
    server, spec, audit_path = _server_with(
        tmp_path,
        client,
        SshBindingSpec(key_secret="K", host_keys=[_openssh_pub_line(host_key)]),
    )
    server.start()
    try:
        conn = AgentConn(spec.socket_path)
        try:
            pub_blob = sshkeys.public_blob(key_a)
            sid = os.urandom(32)
            ext = bytes([SSH_AGENTC_EXTENSION]) + put_string(b"session-bind@openssh.com")
            conn.rpc(ext + _session_bind_payload(host_key, sid))
            resp = _sign_rpc(conn, pub_blob, _userauth_blob(sid, pub_blob))
            assert resp == bytes([SSH_AGENT_FAILURE])
        finally:
            conn.close()
    finally:
        server.stop()
    reasons = [e.get("reason") for e in _audit_events(audit_path)]
    assert any(r and r.startswith("unusable_key:") for r in reasons), reasons
    # And no allowed record was written for it.
    assert not any(e.get("type") == "ssh_sign_allowed" for e in _audit_events(audit_path))


def test_vault_outage_at_sign_time_denies_and_audits(tmp_path: Path) -> None:
    """Resolve succeeded, then the backend went away before the fetch. That is
    a deny with its own audit reason, never a signature."""
    pem, key = _ed25519_pem()
    host_key = ed25519.Ed25519PrivateKey.generate()
    client = _RotatingClient([pem, BackendUnavailableError("vault down")])
    server, spec, audit_path = _server_with(
        tmp_path,
        client,
        SshBindingSpec(key_secret="K", host_keys=[_openssh_pub_line(host_key)]),
    )
    server.start()
    try:
        conn = AgentConn(spec.socket_path)
        try:
            pub_blob = sshkeys.public_blob(key)
            sid = os.urandom(32)
            ext = bytes([SSH_AGENTC_EXTENSION]) + put_string(b"session-bind@openssh.com")
            conn.rpc(ext + _session_bind_payload(host_key, sid))
            assert _sign_rpc(conn, pub_blob, _userauth_blob(sid, pub_blob)) == bytes(
                [SSH_AGENT_FAILURE]
            )
        finally:
            conn.close()
    finally:
        server.stop()
    reasons = [e.get("reason") for e in _audit_events(audit_path)]
    assert any(r and r.startswith("secret_unavailable:") for r in reasons), reasons


# ── Oracle review 2026-10-11: platform gate for the peer-credential check ────


def test_server_refuses_to_start_without_so_peercred(tmp_path: Path, monkeypatch) -> None:
    """The 0o666 socket mode is justified only by SO_PEERCRED on every accept.
    A platform without it (macOS) must get one clear startup error, not a
    world-connectable socket whose every connection dies in the log."""
    monkeypatch.delattr(socket, "SO_PEERCRED")
    pem, _ = _ed25519_pem()
    host_key = ed25519.Ed25519PrivateKey.generate()
    spec = SshSpec(
        socket_path=str(tmp_path / "agent.sock"),
        allowed_uids=[os.getuid()],
        bindings={"B": SshBindingSpec(key_secret="K", host_keys=[_openssh_pub_line(host_key)])},
    )
    server = SshAgentServer(spec, StubClient({"K": pem}), AuditWriter(str(tmp_path / "a.jsonl")))
    with pytest.raises(RuntimeError, match="SO_PEERCRED"):
        server.start()
    assert not (tmp_path / "agent.sock").exists()
