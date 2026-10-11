"""THREAT: T-1.5  (a notes author smuggling HTTP framing past per-binding scope)

A vault-notes author must not be able to inject request structure into the
requests kow authenticates.

``header`` and ``format`` are note-settable (ADR-0021), and the notes author is
a lower-trust principal who cannot read the secret (ADR-0024). Both fields
become header bytes: ``Headers.__bytes__`` joins fields with CRLF, and
mitmproxy validates header NAMES only, inbound only. ``kow mcp`` refuses the
Cc/Cf/Zl/Zp class when WRITING a note; these tests pin the same refusal on the
READ side, for notes written by any other vault client (found 2026-09-17,
source audit run-1, ``notes-header-crlf-unfiltered-to-request-header-sink``).

The sink guard additionally covers what config cannot see: a secret VALUE that
itself carries a break character.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from kow._textguard import has_forbidden_char
from kow.config_models import HeaderInjector
from kow.notes_binding import InvalidBinding, parse_notes_binding
from tests.attacks import _harness as h

SPLIT_FORMATS = [
    pytest.param("Bearer {OPENAI_API_KEY}\r\nX-Injected: 1", id="crlf"),
    pytest.param("Bearer {OPENAI_API_KEY}\nX-Injected: 1", id="lf"),
    pytest.param("Bearer {OPENAI_API_KEY}X-Injected: 1", id="nel"),
    pytest.param("Bearer {OPENAI_API_KEY} X-Injected: 1", id="line-separator"),
    pytest.param("Bearer {OPENAI_API_KEY} X-Injected: 1", id="paragraph-separator"),
    pytest.param("Bearer {OPENAI_API_KEY}\x00", id="nul"),
]


@pytest.mark.parametrize("fmt", SPLIT_FORMATS)
def test_injector_rejects_break_characters_in_format(fmt: str) -> None:
    with pytest.raises(ValidationError):
        HeaderInjector(header="Authorization", format=fmt)


def test_injector_rejects_break_characters_in_header_name() -> None:
    with pytest.raises(ValidationError):
        HeaderInjector(header="Authorization\r\nX-Injected: 1", format="Bearer {X}")


def test_ordinary_values_still_accepted() -> None:
    """Control: the guard must not reject legitimate configurations."""
    inj = HeaderInjector(header="Authorization", format="Bearer {OPENAI_API_KEY}")
    assert inj.header == "Authorization"


def test_poisoned_note_fails_per_secret_not_globally() -> None:
    """A rejected note must yield InvalidBinding for that ONE secret, keeping
    the per-secret fail-closed commitment in runtime_bindings."""
    note = (
        "# kow-binding\n"
        "host: api.openai.com\n"
        'format: "Bearer {OPENAI_API_KEY}\\r\\nX-Injected: 1"\n'
    )
    result = parse_notes_binding(
        secret_name="OPENAI_API_KEY",
        placeholder=h.PLACEHOLDER,
        note=note,
    )
    assert isinstance(result, InvalidBinding)


def test_secret_value_carrying_crlf_is_not_written_to_the_wire(tmp_path: Path) -> None:
    """Sink guard: backends round-trip values verbatim, so a secret whose VALUE
    holds a break character must fail closed rather than split the request."""

    class _CrlfBackend:
        def fetch(self, name, ctx=None):
            from kow.secret import Secret

            return Secret("sk-REAL\r\nX-Injected: 1")

    addon, _audit = h.build_addon(tmp_path)
    from kow.caching import CachingSecretsClient

    addon.client = CachingSecretsClient(
        _CrlfBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=10
    )
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    assert not has_forbidden_char(flow.request.headers.get("Authorization", ""))
    assert flow.response is not None and flow.response.status_code == 503
