"""Reject Unicode control/format/separator characters in note-settable text.

A binding's ``header`` and ``format`` are settable from vault metadata, so the
lower-trust notes author (GSM ``secretmanager.secrets.update`` without
``versions.access``; see ADR-0024) chooses bytes that become an HTTP header
field. ``Headers.__bytes__`` joins fields with CRLF and mitmproxy validates
header NAMES only, inbound only, so a break character inside a value is a
request-splitting primitive against an operator-approved destination.

``kow mcp`` already refuses this class when WRITING a note (cli/mcp.py); this
module is the same guard on the READ side, where the daemon consumes notes any
vault writer may have authored without that CLI. PyYAML also honours NEL
(U+0085), LS (U+2028) and PS (U+2029) as line breaks, so the whole Cc/Cf/Zl/Zp
space is refused rather than ASCII CR/LF alone. Legitimate header names, header
values and format strings are printable and never fall in these categories.
"""

from __future__ import annotations

import unicodedata

FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def has_forbidden_char(value: str) -> bool:
    """True if ``value`` holds any Unicode control, format or line/paragraph
    separator character."""
    return any(unicodedata.category(ch) in FORBIDDEN_CATEGORIES for ch in value)


def assert_no_forbidden_chars(value: str, *, label: str) -> None:
    """Raise ``ValueError`` naming the offending code point. The message never
    echoes the full value: a rendered header value carries the real secret."""
    for index, ch in enumerate(value):
        if unicodedata.category(ch) in FORBIDDEN_CATEGORIES:
            raise ValueError(
                f"{label} must not contain control or line-separator characters "
                f"(found U+{ord(ch):04X} at position {index})"
            )
