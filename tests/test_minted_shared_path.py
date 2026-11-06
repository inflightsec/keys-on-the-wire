"""Regression gate: the token-minting resolvers must stay on the shared path.

Their header writes, audit events and 503s go through injectors/_minted.py and
kow/_fail_closed.py. Per-resolver copies drifted apart one at a time (Oracle C1,
C9). A new minting resolver belongs in RESOLVERS.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_INJECTORS = Path(__file__).resolve().parent.parent / "src" / "kow" / "injectors"
RESOLVERS = ["github_app.py", "oauth2_client_credentials.py", "gcp_service_account.py"]
_DIRECT = re.compile(
    r"\.headers\[|\.headers\.(set|add|insert)\(|audit\.emit\(|Response\.make\(|emit_allowed\("
)


@pytest.mark.parametrize("module", RESOLVERS)
def test_resolver_has_no_direct_header_audit_or_response_writes(module: str) -> None:
    hits = [
        f"{module}:{n}: {line.strip()}"
        for n, line in enumerate((_INJECTORS / module).read_text().splitlines(), 1)
        if _DIRECT.search(line)
    ]
    assert not hits, "use injectors/_minted.py / emit_denial_and_503:\n" + "\n".join(hits)


_OWN_VERDICT = re.compile(r'Response\.make\(|"decision": ')


@pytest.mark.parametrize(
    "module", sorted(p.name for p in _INJECTORS.glob("*.py") if p.name != "body.py")
)
def test_no_injector_builds_its_own_verdict(module: str) -> None:
    """Allow/deny records and 503s come from emit_allowed / emit_denial_and_503
    (kow/_fail_closed.py), so the audit shape and fail-closed order live in one
    place. body.py is exempt: its streaming allow is a different record."""
    hits = [
        f"{module}:{n}: {line.strip()}"
        for n, line in enumerate((_INJECTORS / module).read_text().splitlines(), 1)
        if _OWN_VERDICT.search(line)
    ]
    assert not hits, "use kow/_fail_closed.py:\n" + "\n".join(hits)
