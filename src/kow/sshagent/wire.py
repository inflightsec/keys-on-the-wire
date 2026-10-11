"""Bounded SSH wire primitives (RFC 4251 §5) for the agent protocol.

Every read here parses attacker-influenced bytes, so the discipline is the
ADR-0039 one: every length is checked against what remains BEFORE any
allocation, and a parse either consumes exactly what it claims or raises
``WireError``. No parser in this package touches the network — framing I/O
lives in ``server.py``; these operate on already-received ``bytes``.
"""

from __future__ import annotations

import struct

# One agent message, framed by a u32 length prefix. OpenSSH's own limit
# (MAX_AGENT_MESSAGE) is 256 KiB; matching it keeps interop while bounding
# the allocation a hostile client can force per message.
MAX_AGENT_MESSAGE = 256 * 1024


class WireError(ValueError):
    """Malformed or out-of-bounds wire data. Never carries payload bytes."""


class Reader:
    """Sequential bounded reader over one message's bytes."""

    __slots__ = ("_buf", "_off")

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._off = 0

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._off

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.remaining:
            raise WireError("truncated field")
        out = self._buf[self._off : self._off + n]
        self._off += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def boolean(self) -> bool:
        return self.byte() != 0

    def uint32(self) -> int:
        # struct.unpack is typed as returning Any; make the narrowing explicit
        # rather than letting an untyped value escape into length arithmetic.
        return int(struct.unpack(">I", self.take(4))[0])

    def string(self) -> bytes:
        n = self.uint32()
        if n > self.remaining:
            raise WireError("string length exceeds message")
        return self.take(n)

    def expect_end(self) -> None:
        """Trailing bytes after a complete parse are a malformed message,
        not padding — refuse rather than ignore."""
        if self.remaining != 0:
            raise WireError("trailing bytes after message")


def put_uint32(n: int) -> bytes:
    return struct.pack(">I", n)


def put_string(b: bytes) -> bytes:
    return put_uint32(len(b)) + b


def put_mpint(n: int) -> bytes:
    """RFC 4251 mpint: minimal big-endian, leading 0x00 if the high bit is
    set. Only non-negative values occur in this package (RSA e, n)."""
    if n == 0:
        return put_string(b"")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return put_string(raw)


def read_mpint(r: Reader) -> int:
    raw = r.string()
    if raw and raw[0] & 0x80:
        raise WireError("negative mpint")
    return int.from_bytes(raw, "big")


def frame(payload: bytes) -> bytes:
    """Length-prefix one outbound agent message."""
    if len(payload) > MAX_AGENT_MESSAGE:
        raise WireError("outbound message exceeds MAX_AGENT_MESSAGE")
    return put_uint32(len(payload)) + payload
