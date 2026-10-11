"""Key handling for the SSH signing oracle (ADR-0053 decision 2).

Private keys arrive as ``Secret``-wrapped PEM text fetched from the backend;
they are parsed per call and never cached here (the value cache upstream is
the only holder). Public blobs and signatures are built from the RFC 4253 §6.6
wire formats. v1 signs with Ed25519 and RSA (rsa-sha2-256/512 only — SHA-1 is
refused, see server.py); host-key *verification* additionally accepts ECDSA,
because verifying a server's key implies no weakness budget of ours.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from kow.secret import Secret
from kow.sshagent.wire import Reader, WireError, put_mpint, put_string, read_mpint

# SIGN_REQUEST flags (RFC 9987 §4.5.1).
SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4

_ECDSA_CURVES: dict[bytes, type[ec.EllipticCurve]] = {
    b"nistp256": ec.SECP256R1,
    b"nistp384": ec.SECP384R1,
    b"nistp521": ec.SECP521R1,
}
_ECDSA_HASHES: dict[bytes, type[hashes.HashAlgorithm]] = {
    b"nistp256": hashes.SHA256,
    b"nistp384": hashes.SHA384,
    b"nistp521": hashes.SHA512,
}


class UnusableKeyError(WireError):
    """Unusable key material or unsupported algorithm."""


def load_private_key(
    secret: Secret,
) -> ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey:
    """Parse a vault-held private key (OpenSSH or PKCS#8/PKCS#1 PEM,
    unencrypted — the vault is the encryption at rest, ADR-0053)."""
    raw = secret.reveal().encode()
    # Annotated broadly on purpose: the two loaders return different unions, and
    # the isinstance gate below — not the annotation — is what enforces which
    # key types this oracle will actually sign with.
    key: object
    try:
        key = serialization.load_ssh_private_key(raw, password=None)
    except (ValueError, TypeError):
        try:
            key = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, TypeError) as exc:
            # Deliberately does not chain the parser's message: it can quote
            # input fragments, and this string may reach logs.
            raise UnusableKeyError("private key is not parseable OpenSSH/PEM") from exc
    if isinstance(key, ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey):
        return key
    raise UnusableKeyError(f"unsupported private key type {type(key).__name__}")


def public_blob(key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey) -> bytes:
    """RFC 4253 §6.6 public key blob for the private key."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return put_string(b"ssh-ed25519") + put_string(raw)
    numbers = key.public_key().public_numbers()
    return put_string(b"ssh-rsa") + put_mpint(numbers.e) + put_mpint(numbers.n)


def fingerprint(blob: bytes) -> str:
    """OpenSSH-style SHA256 fingerprint (unpadded base64) — the audit-safe
    name for any key blob; never the blob itself."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def parse_public_key_line(line: str) -> bytes:
    """Parse one ``host_keys:`` config entry — an OpenSSH public key line
    (``<type> <base64> [comment]``) — to its wire blob, validating that the
    base64 payload's declared inner type matches the outer word."""
    parts = line.split()
    if len(parts) < 2:
        raise UnusableKeyError("host key entry is not '<type> <base64> [comment]'")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise UnusableKeyError("host key base64 is invalid") from exc
    r = Reader(blob)
    inner = r.string()
    if inner != parts[0].encode():
        raise UnusableKeyError("host key type word does not match key blob")
    return blob


def sign(key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey, data: bytes, flags: int) -> bytes:
    """Produce the RFC 4253 §6.6 signature blob for ``data``.

    RSA requires an explicit SHA-2 flag; a flags=0 RSA request would mean
    legacy ssh-rsa/SHA-1, which this oracle refuses (raises ``UnusableKeyError`` —
    the server maps it to a generic failure, G5)."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return put_string(b"ssh-ed25519") + put_string(key.sign(data))
    alg: bytes
    digest: hashes.HashAlgorithm
    if flags & SSH_AGENT_RSA_SHA2_512:
        alg, digest = b"rsa-sha2-512", hashes.SHA512()
    elif flags & SSH_AGENT_RSA_SHA2_256:
        alg, digest = b"rsa-sha2-256", hashes.SHA256()
    else:
        raise UnusableKeyError("RSA signing requires an rsa-sha2 flag; SHA-1 is refused")
    sig = key.sign(data, padding.PKCS1v15(), digest)
    return put_string(alg) + put_string(sig)


def verify_signature(pubkey_blob: bytes, signature_blob: bytes, data: bytes) -> bool:
    """Verify a wire-format signature against a wire-format public key.

    Used on the *server's* session-bind proof (ADR-0053 decision 3). Accepts
    ssh-ed25519, rsa-sha2-256/512 over ssh-rsa keys, and ecdsa-sha2-nistp*.
    Returns False for anything malformed, unknown, or cryptographically
    invalid — the caller treats all three identically (fail closed)."""
    try:
        kr = Reader(pubkey_blob)
        ktype = kr.string()
        sr = Reader(signature_blob)
        sig_alg = sr.string()
        sig = sr.string()
        sr.expect_end()
        if ktype == b"ssh-ed25519":
            if sig_alg != b"ssh-ed25519":
                return False
            pub = ed25519.Ed25519PublicKey.from_public_bytes(kr.string())
            kr.expect_end()
            pub.verify(sig, data)
            return True
        if ktype == b"ssh-rsa":
            e = read_mpint(kr)
            n = read_mpint(kr)
            kr.expect_end()
            if sig_alg == b"rsa-sha2-256":
                digest: hashes.HashAlgorithm = hashes.SHA256()
            elif sig_alg == b"rsa-sha2-512":
                digest = hashes.SHA512()
            else:
                # ssh-rsa (SHA-1) proofs are refused even for verification:
                # accepting one would let a downgraded server key pass the
                # destination check on a weaker hash than any binding intends.
                return False
            rsa.RSAPublicNumbers(e, n).public_key().verify(sig, data, padding.PKCS1v15(), digest)
            return True
        if ktype.startswith(b"ecdsa-sha2-"):
            curve_name = ktype[len(b"ecdsa-sha2-") :]
            if sig_alg != ktype or curve_name not in _ECDSA_CURVES:
                return False
            if kr.string() != curve_name:
                return False
            point = kr.string()
            kr.expect_end()
            ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                _ECDSA_CURVES[curve_name](), point
            )
            rs = Reader(sig)
            r_int = read_mpint(rs)
            s_int = read_mpint(rs)
            rs.expect_end()
            der = utils.encode_dss_signature(r_int, s_int)
            ec_pub.verify(der, data, ec.ECDSA(_ECDSA_HASHES[curve_name]()))
            return True
        return False
    except (WireError, ValueError, InvalidSignature):
        return False
