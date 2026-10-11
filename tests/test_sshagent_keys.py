"""Key parsing, signing and signature verification (ADR-0053).

Loop #05 (coverage), 2026-09-24. `keys.py` sat at 71% with the ENTIRE ECDSA
verification branch uncovered — and that branch verifies an attacker-supplied
`session-bind@openssh.com` proof, which is the one thing standing between a
pinned-destination policy and a signature for anywhere. Untested crypto
verification in a security boundary is the gap worth closing first.

Every signature here is produced with the real `cryptography` primitives and
then re-encoded into SSH wire format, so a change to either the encoder or the
verifier breaks these rather than passing vacuously.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from kow.secret import Secret
from kow.sshagent import keys as k
from kow.sshagent.wire import put_mpint, put_string

_DATA = b"session-identifier-bytes"


# ── helpers: build SSH wire-format public keys and signatures ────────────────


def _ed25519_pair() -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, put_string(b"ssh-ed25519") + put_string(raw)


def _rsa_pair() -> tuple[rsa.RSAPrivateKey, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    return priv, put_string(b"ssh-rsa") + put_mpint(nums.e) + put_mpint(nums.n)


def _ecdsa_pair(curve_name: bytes) -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    priv = ec.generate_private_key(k._ECDSA_CURVES[curve_name]())
    point = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    ktype = b"ecdsa-sha2-" + curve_name
    return priv, put_string(ktype) + put_string(curve_name) + put_string(point)


def _ecdsa_sig(priv: ec.EllipticCurvePrivateKey, curve_name: bytes, data: bytes) -> bytes:
    der = priv.sign(data, ec.ECDSA(k._ECDSA_HASHES[curve_name]()))
    r, s = utils.decode_dss_signature(der)
    ktype = b"ecdsa-sha2-" + curve_name
    return put_string(ktype) + put_string(put_mpint(r) + put_mpint(s))


# ── load_private_key ─────────────────────────────────────────────────────────


def test_load_private_key_accepts_pkcs8_pem_fallback() -> None:
    """The OpenSSH loader is tried first; a PKCS#8 PEM must fall through to the
    second loader rather than being rejected."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    loaded = k.load_private_key(Secret(pem))
    assert isinstance(loaded, ed25519.Ed25519PrivateKey)


def test_load_private_key_rejects_unsupported_key_type() -> None:
    """An EC private key parses fine but is not a type this oracle signs with."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with pytest.raises(k.UnusableKeyError, match="unsupported private key type"):
        k.load_private_key(Secret(pem))


def test_load_private_key_rejects_garbage_without_quoting_it() -> None:
    """The parser's own message can quote input fragments and this string may
    reach logs, so the raised message must be our own fixed text."""
    with pytest.raises(k.UnusableKeyError) as exc:
        k.load_private_key(Secret("-----BEGIN NONSENSE-----\nnot-a-key\n"))
    assert "not-a-key" not in str(exc.value)


# ── sign ─────────────────────────────────────────────────────────────────────


def test_rsa_signing_refuses_sha1() -> None:
    """flags=0 means legacy ssh-rsa/SHA-1. Refused, not silently downgraded."""
    priv, _ = _rsa_pair()
    with pytest.raises(k.UnusableKeyError, match="rsa-sha2"):
        k.sign(priv, _DATA, flags=0)


@pytest.mark.parametrize(
    ("flag", "alg"),
    [(k.SSH_AGENT_RSA_SHA2_256, b"rsa-sha2-256"), (k.SSH_AGENT_RSA_SHA2_512, b"rsa-sha2-512")],
)
def test_rsa_signing_honours_the_sha2_flag(flag: int, alg: bytes) -> None:
    priv, blob = _rsa_pair()
    sig = k.sign(priv, _DATA, flags=flag)
    assert sig.startswith(put_string(alg))
    assert k.verify_signature(blob, sig, _DATA) is True


def test_ed25519_signing_round_trips() -> None:
    priv, blob = _ed25519_pair()
    assert k.verify_signature(blob, k.sign(priv, _DATA, flags=0), _DATA) is True


# ── verify_signature: the ECDSA branch, previously 0% covered ────────────────


@pytest.mark.parametrize("curve", [b"nistp256", b"nistp384", b"nistp521"])
def test_ecdsa_session_bind_proof_verifies(curve: bytes) -> None:
    priv, blob = _ecdsa_pair(curve)
    assert k.verify_signature(blob, _ecdsa_sig(priv, curve, _DATA), _DATA) is True


@pytest.mark.parametrize("curve", [b"nistp256", b"nistp384", b"nistp521"])
def test_ecdsa_proof_over_different_data_is_refused(curve: bytes) -> None:
    """The whole point of the proof: it must bind to THIS session id."""
    priv, blob = _ecdsa_pair(curve)
    sig = _ecdsa_sig(priv, curve, b"a-different-session-id")
    assert k.verify_signature(blob, sig, _DATA) is False


def test_ecdsa_proof_from_a_different_key_is_refused() -> None:
    _, blob = _ecdsa_pair(b"nistp256")
    other, _ = _ecdsa_pair(b"nistp256")
    assert k.verify_signature(blob, _ecdsa_sig(other, b"nistp256", _DATA), _DATA) is False


def test_ecdsa_curve_mismatch_between_key_and_signature_is_refused() -> None:
    """A p256 key with a p384-labelled signature must not verify — otherwise the
    hash the proof was made under is not the one the key type implies."""
    priv, blob = _ecdsa_pair(b"nistp256")
    sig = _ecdsa_sig(priv, b"nistp256", _DATA).replace(b"nistp256", b"nistp384")
    assert k.verify_signature(blob, sig, _DATA) is False


def test_ecdsa_unknown_curve_is_refused() -> None:
    priv, _ = _ecdsa_pair(b"nistp256")
    blob = put_string(b"ecdsa-sha2-nistp999") + put_string(b"nistp999") + put_string(b"\x04" * 65)
    sig = _ecdsa_sig(priv, b"nistp256", _DATA).replace(b"nistp256", b"nistp999")
    assert k.verify_signature(blob, sig, _DATA) is False


def test_ecdsa_inner_curve_name_must_match_the_key_type() -> None:
    """The curve appears twice in the blob; disagreement is malformed."""
    priv, _ = _ecdsa_pair(b"nistp256")
    point = priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    blob = put_string(b"ecdsa-sha2-nistp256") + put_string(b"nistp384") + put_string(point)
    assert k.verify_signature(blob, _ecdsa_sig(priv, b"nistp256", _DATA), _DATA) is False


# ── verify_signature: refusals on the other algorithms ───────────────────────


def test_rsa_sha1_proof_is_refused_even_for_verification() -> None:
    """Accepting one would let a downgraded server key pass the destination
    check on a weaker hash than any binding intends."""
    priv, blob = _rsa_pair()
    raw = priv.sign(_DATA, padding.PKCS1v15(), hashes.SHA1())  # noqa: S303
    assert k.verify_signature(blob, put_string(b"ssh-rsa") + put_string(raw), _DATA) is False


def test_ed25519_algorithm_confusion_is_refused() -> None:
    """An ed25519 key blob paired with a signature claiming another algorithm."""
    priv, blob = _ed25519_pair()
    sig = put_string(b"rsa-sha2-256") + put_string(priv.sign(_DATA))
    assert k.verify_signature(blob, sig, _DATA) is False


def test_unknown_key_type_verifies_false_rather_than_raising() -> None:
    blob = put_string(b"ssh-dss") + put_string(b"whatever")
    assert k.verify_signature(blob, put_string(b"ssh-dss") + put_string(b"sig"), _DATA) is False


@pytest.mark.parametrize("bad", [b"", b"\x00", b"\xff\xff\xff\xff", put_string(b"ssh-ed25519")])
def test_malformed_blobs_fail_closed_rather_than_raising(bad: bytes) -> None:
    """Malformed, unverifiable and wrong-key are deliberately indistinguishable
    to the caller, and none of them may escape as an exception."""
    assert k.verify_signature(bad, bad, _DATA) is False


# ── remaining wire / parse / config error paths (loop #05, round 2) ──────────


def test_parse_public_key_line_rejects_a_bare_word() -> None:
    with pytest.raises(k.UnusableKeyError, match="not '<type> <base64>"):
        k.parse_public_key_line("ssh-ed25519")


def test_parse_public_key_line_rejects_bad_base64() -> None:
    with pytest.raises(k.UnusableKeyError, match="base64 is invalid"):
        k.parse_public_key_line("ssh-ed25519 !!!not-base64!!!")


def test_parse_public_key_line_rejects_type_word_blob_mismatch() -> None:
    """The outer word and the blob's own declared type must agree, or a pin
    could name one algorithm while pinning a key of another."""
    import base64 as _b64

    _, blob = _ed25519_pair()
    line = "ssh-rsa " + _b64.b64encode(blob).decode()
    with pytest.raises(k.UnusableKeyError, match="does not match key blob"):
        k.parse_public_key_line(line)


def test_parse_public_key_line_accepts_a_trailing_comment() -> None:
    import base64 as _b64

    _, blob = _ed25519_pair()
    line = "ssh-ed25519 " + _b64.b64encode(blob).decode() + " radek@framework"
    assert k.parse_public_key_line(line) == blob


def test_read_mpint_refuses_a_negative_value() -> None:
    """A high bit set means a negative SSH mpint; none occur in this package,
    so accepting one would mean parsing something we never emit."""
    from kow.sshagent.wire import Reader, WireError, read_mpint

    with pytest.raises(WireError, match="negative mpint"):
        read_mpint(Reader(put_string(b"\x80\x01")))


def test_put_mpint_round_trips_zero_and_high_bit() -> None:
    from kow.sshagent.wire import Reader, read_mpint

    for n in (0, 1, 127, 128, 255, 65537, 2**2047 + 1):
        assert read_mpint(Reader(put_mpint(n))) == n


def test_session_bind_refuses_an_empty_session_id() -> None:
    from kow.sshagent.sessionbind import parse_and_verify
    from kow.sshagent.wire import WireError

    priv, blob = _ed25519_pair()
    payload = put_string(blob) + put_string(b"") + put_string(priv.sign(b"")) + b"\x00"
    with pytest.raises(WireError, match="empty session id"):
        parse_and_verify(payload)


def test_session_bind_refuses_an_unverifiable_proof() -> None:
    """A host key blob with someone else's signature over the session id — the
    exact shape of a smuggled destination."""
    from kow.sshagent.sessionbind import parse_and_verify
    from kow.sshagent.wire import WireError

    _, blob = _ed25519_pair()
    other, _ = _ed25519_pair()
    payload = put_string(blob) + put_string(b"sid") + put_string(other.sign(b"sid")) + b"\x00"
    with pytest.raises(WireError, match="does not verify"):
        parse_and_verify(payload)


def test_userauth_refuses_a_non_publickey_method() -> None:
    from kow.sshagent.userauth import SSH_MSG_USERAUTH_REQUEST, parse_userauth
    from kow.sshagent.wire import WireError

    data = (
        put_string(b"sid")
        + bytes([SSH_MSG_USERAUTH_REQUEST])
        + put_string(b"radek")
        + put_string(b"ssh-connection")
        + put_string(b"password")
    )
    with pytest.raises(WireError, match="not a publickey userauth method"):
        parse_userauth(data)


def test_userauth_refuses_an_undecodable_username() -> None:
    from kow.sshagent.userauth import METHOD_PUBLICKEY, SSH_MSG_USERAUTH_REQUEST, parse_userauth
    from kow.sshagent.wire import WireError

    data = (
        put_string(b"sid")
        + bytes([SSH_MSG_USERAUTH_REQUEST])
        + put_string(b"\xff\xfe")
        + put_string(b"ssh-connection")
        + put_string(METHOD_PUBLICKEY)
        + b"\x01"
        + put_string(b"ssh-ed25519")
        + put_string(b"pub")
    )
    with pytest.raises(WireError, match="undecodable"):
        parse_userauth(data)


def test_ssh_config_rejects_an_empty_users_list() -> None:
    """`users: []` is ambiguous — deny-all must be deleting the binding."""
    from kow.sshagent.config import SshBindingSpec

    with pytest.raises(ValueError, match="ambiguous"):
        SshBindingSpec(key_secret="K", users=[], allow_unbound_sessions=True)


def test_ssh_config_rejects_a_shell_unsafe_socket_path() -> None:
    from kow.sshagent.config import SshSpec

    with pytest.raises(ValueError, match="quotes or newlines"):
        SshSpec(socket_path="/tmp/a'b", allowed_uids=[1000], bindings={})


def test_ssh_config_rejects_enabled_with_no_bindings() -> None:
    """A signing oracle that is on but pins nothing must not be configurable."""
    from kow.sshagent.config import SshSpec

    with pytest.raises(ValueError, match="no bindings"):
        SshSpec(socket_path="/tmp/kow.sock", allowed_uids=[1000], bindings={})
