"""client_message is a wire contract — pinned byte-for-byte.

Agents and operators grep these strings. Changing one is a compatibility change
and must be a deliberate edit to this table, not a side effect of a refactor.
"""

from __future__ import annotations

import pathlib

import pytest

from kow import denials as d

# EVERY denial, pinned literally. Do not derive this from the classes — a
# generated table would pin nothing.
PINNED: list[tuple[type[d.DenialError], bytes]] = [
    (d.AmbiguousPlaceholderError, b"kow: ambiguous placeholder match\n"),
    (d.CompositeFetchFailedError, b"kow: composite secret fetch failed\n"),
    (d.CompositeRenderFailedError, b"kow: composite render failed\n"),
    (d.CompositeRenderUnexpectedError, b"kow: composite render failed unexpectedly\n"),
    (d.CompositeUnavailableError, b"kow: composite secret unavailable\n"),
    (d.DestinationNotBoundError, b"kow: destination not in any binding\n"),
    (d.ExchangeFailedError, b"kow: request denied\n"),
    (d.GcpKeyUnavailableError, b"kow: gcp service-account key unavailable\n"),
    (d.GcpMintFailedError, b"kow: gcp service-account token mint failed\n"),
    (d.GithubAppExchangeFailedError, b"kow: github app token exchange failed\n"),
    (d.GithubAppKeyUnavailableError, b"kow: github app private key unavailable\n"),
    (d.HeaderControlCharactersError, b"kow: header value contains control characters\n"),
    (d.OauthCcExchangeFailedError, b"kow: oauth2 client-credentials exchange failed\n"),
    (d.OauthCcSecretUnavailableError, b"kow: oauth2 client-credentials secret unavailable\n"),
    (d.OauthExchangeFailedError, b"kow: oauth2 token exchange failed\n"),
    (d.OauthInputFetchFailedError, b"kow: oauth2 input secret fetch failed\n"),
    (d.OauthInputUnavailableError, b"kow: oauth2 input secret unavailable\n"),
    (d.SecretFetchFailedError, b"kow: secret fetch failed\n"),
    (d.SecretUnavailableError, b"kow: secret unavailable\n"),
    (d.SigningKeyUnavailableError, b"kow: signing key unavailable\n"),
    (d.SigningStateUnavailableError, b"kow: signing state unavailable\n"),
    (d.Sigv4CredentialUnavailableError, b"kow: sigv4 credential unavailable\n"),
    (d.SniHostMismatchError, b"kow: CONNECT host and request host disagree\n"),
    (d.UnrecognizedSigningInjectorError, b"kow: unrecognized signing injector\n"),
]


def _all_subclasses(cls: type) -> set[type]:
    out: set[type] = set()
    for sub in cls.__subclasses__():
        out.add(sub)
        out |= _all_subclasses(sub)
    return out


@pytest.mark.parametrize("cls,message", PINNED, ids=[c.__name__ for c, _ in PINNED])
def test_client_message_is_pinned(cls: type[d.DenialError], message: bytes) -> None:
    assert cls.client_message == message


def test_every_denial_is_pinned() -> None:
    """A new denial without a pinned message fails here, not in production."""
    pinned = {c for c, _ in PINNED}
    assert _all_subclasses(d.DenialError) == pinned


@pytest.mark.parametrize("cls,message", PINNED, ids=[c.__name__ for c, _ in PINNED])
def test_wire_shape(cls: type[d.DenialError], message: bytes) -> None:
    """Every message names the product and ends with a newline."""
    assert message.startswith(b"kow: ")
    assert message.endswith(b"\n")
    assert b"agent-vault-proxy" not in message


def test_base_default_is_generic() -> None:
    assert d.DenialError.client_message == b"kow: request denied\n"


def test_operator_detail_stays_local() -> None:
    """The detail is for the operator; it never reaches the wire message."""
    exc = d.SecretUnavailableError("bws timeout after 3 retries on FOO")
    assert exc.operator_detail == "bws timeout after 3 retries on FOO"
    assert b"bws timeout" not in exc.client_message
    assert exc.client_message == b"kow: secret unavailable\n"


def test_exchange_failures_share_a_base_and_carry_the_result() -> None:
    """The three folded sentinels keep the `.result` the audit path reads."""
    for cls in (
        d.OauthExchangeFailedError,
        d.OauthCcExchangeFailedError,
        d.GithubAppExchangeFailedError,
        d.GcpMintFailedError,
    ):
        exc = cls(result="sentinel")
        assert isinstance(exc, d.ExchangeFailedError)
        assert isinstance(exc, d.DenialError)
        assert exc.result == "sentinel"


def test_no_legacy_wire_literal_remains_in_source() -> None:
    """The old product name must not reappear in a wire message."""
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "kow"
    offenders = [
        str(p.relative_to(src))
        for p in src.rglob("*.py")
        if b'b"agent-vault-proxy' in p.read_bytes()
    ]
    assert offenders == []


def test_denial_bytes_reach_the_wire(tmp_path) -> None:
    """End-to-end: the constant is what an agent actually receives.

    Pinning the class attribute proves the table; this proves the plumbing.
    """
    from mitmproxy.test import tflow

    from kow.addon import AgentVaultProxyAddon
    from kow.audit import AuditWriter
    from kow.config import load_config

    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "b.yaml"
    cfg.write_text(f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "api.openai.com"
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
""")
    addon = AgentVaultProxyAddon()
    addon.audit = AuditWriter(str(audit))
    addon.config = load_config(cfg)

    flow = tflow.tflow()
    flow.request.host = "evil.example.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    addon.http_connect(flow)

    assert flow.response is not None
    assert flow.response.content == d.DestinationNotBoundError.client_message
    assert flow.response.content == b"kow: destination not in any binding\n"


def test_healthz_answers_both_sentinel_hosts() -> None:
    """The pre-rename probe host stays answered so an in-flight container or
    orchestrator healthcheck does not start failing across the upgrade."""
    from mitmproxy.test import tflow

    from kow._healthz import HEALTHZ_HOST, LEGACY_HEALTHZ_HOST, is_healthz_request

    assert HEALTHZ_HOST == "healthz.kow.invalid"
    assert LEGACY_HEALTHZ_HOST == "healthz.agent-vault-proxy.invalid"
    for host in (HEALTHZ_HOST, LEGACY_HEALTHZ_HOST):
        flow = tflow.tflow()
        flow.request.host = host
        flow.request.path = "/healthz"
        assert is_healthz_request(flow) is True
    # A bound host must never be swallowed by the probe gate.
    other = tflow.tflow()
    other.request.host = "api.openai.com"
    other.request.path = "/healthz"
    assert is_healthz_request(other) is False
