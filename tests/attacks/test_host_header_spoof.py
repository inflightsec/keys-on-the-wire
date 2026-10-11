"""THREAT: T-1.5  (laundering a credential to a destination no binding authorizes)

The policy gate must authorize on the address the proxy DIALS, never on the
authority the client merely claims.

``flow.request.pretty_host`` prefers the Host / ``:authority`` header, which a
lower-trust loopback client controls independently of ``flow.request.host`` —
the address mitmproxy actually connects to. Authorizing on the former let a
plain-HTTP absolute-form request carry a real credential to an attacker's host
while the audit trail recorded the claimed one (found 2026-09-17, source audit
run-1, fingerprint ``policy-binds-to-host-header-not-connection-destination``).

The same comparison revives G3 for tunnelled traffic: in transparent mode
``request.host`` is the CONNECT-established address, which ``flow.metadata``
could never carry across the CONNECT boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.attacks import _harness as h

ATTACKER_HOST = "attacker.example"


def _auth(flow) -> str:
    return flow.request.headers.get("Authorization", "")


def test_honest_request_to_bound_host_still_injects(tmp_path: Path) -> None:
    """Control: the fix must not break the normal path."""
    addon, _audit = h.build_addon(tmp_path)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)
    assert h.REAL in _auth(flow)


def test_unbound_host_without_spoof_is_denied(tmp_path: Path) -> None:
    """Control: the destination gate works when the client does not lie."""
    addon, _audit = h.build_addon(tmp_path)
    flow = h.make_flow(
        ATTACKER_HOST,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)
    assert h.REAL not in _auth(flow)


def test_spoofed_host_header_cannot_route_secret_to_attacker(tmp_path: Path) -> None:
    """EXPLOIT: dialed to the attacker, Host header claims the bound host."""
    addon, audit = h.build_addon(tmp_path)
    flow = h.make_flow(
        ATTACKER_HOST,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}", "Host": h.BOUND_HOST},
    )
    assert flow.request.pretty_host == h.BOUND_HOST  # the claim
    assert flow.request.host == ATTACKER_HOST  # the destination

    h.drive_outbound(addon, flow)

    assert h.REAL not in _auth(flow), "real secret injected into a request dialed elsewhere"
    assert h.PLACEHOLDER in _auth(flow)

    # The audit must name the host that was actually dialed, never the claim.
    records = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
    hosts = {r.get("destination", {}).get("host") for r in records if "destination" in r}
    assert h.BOUND_HOST not in hosts, "audit recorded the spoofed host as the destination"
    assert ATTACKER_HOST in hosts


def test_spoofed_host_header_cannot_cross_bindings(tmp_path: Path) -> None:
    """EXPLOIT: dialed to one bound host, Host header names the OTHER one."""
    addon, _audit = h.build_addon_two_secrets(tmp_path)
    flow = h.make_flow(
        h.BOUND_HOST_B,
        "POST",
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}", "Host": h.BOUND_HOST},
    )
    h.drive_outbound(addon, flow)
    assert h.REAL not in _auth(flow), "secret A delivered to host B via a spoofed authority"
