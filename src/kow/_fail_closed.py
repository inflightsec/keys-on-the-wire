"""Shared fail-closed denial: audit the denied inject_decision, then 503.

G6 ordering (audit-before-response) lives in exactly one place so no deny
path — header, composite, or body — can reorder it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mitmproxy import http

from kow.audit import AuditWriter


def emit_denial_and_503(
    *,
    audit: AuditWriter,
    flow: http.HTTPFlow,
    request_id: str,
    reason: str,
    secret_name: str,
    message: bytes,
    target_host: str,
    extra: Mapping[str, Any] | None = None,
) -> None:
    """Emit a denied ``inject_decision`` audit record, then set a 503 response.

    ``extra`` fields (e.g. ``compose``) land between ``secret_name`` and
    ``destination`` to preserve the established audit field order.
    """
    event: dict[str, Any] = {
        "type": "inject_decision",
        "request_id": request_id,
        "decision": "denied",
        "reason": reason,
        "secret_name": secret_name,
        **(dict(extra) if extra else {}),
        "destination": {"host": target_host, "port": flow.request.port},
    }
    audit.emit(event)
    flow.response = http.Response.make(
        503,
        message,
        {"Content-Type": "text/plain"},
    )


def emit_allowed(
    *,
    audit: AuditWriter,
    flow: http.HTTPFlow,
    request_id: str,
    secret_name: str,
    binding_source: str,
    target_host: str,
) -> None:
    """Emit the allowed ``inject_decision`` audit record. Call it AFTER the
    in-memory header write and BEFORE the hook returns: emit() fsyncs, and no
    bytes leave the proxy until the hook returns (G6)."""
    audit.emit(
        {
            "type": "inject_decision",
            "request_id": request_id,
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": secret_name,
            "binding_source": binding_source,
            "destination": {
                "host": target_host,
                "port": flow.request.port,
                "path_prefix": flow.request.path.split("?", 1)[0][:64],
            },
        }
    )
