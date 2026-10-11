"""ADR-0050 — gcp_service_account injector end to end through the addon.

Covers all three modes with a real RS256 key: the self-signed assertion (no
egress at all), the RFC 7523 exchange, and IAM impersonation from both source
identities. Proves the agent-visible placeholder is replaced, that no key or
minted token reaches the audit log, that every failure leg fails closed with 503
and leaves the placeholder intact, and that the cache key covers the mint inputs.
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kow.addon import AgentVaultProxyAddon
from tests import _oauth_helpers as oh
from tests._oauth_helpers import FakeBackend, FakeResp, make_request

_PH = "gcp-PLACEHOLDER-01HXY1234567890ABCD"
_HOST = "bigquery.googleapis.com"
_TRANSPORT = "kow.injectors._token_transport.transport_open"
_ADC = "kow.injectors.gcp_service_account.adc_access_token"
_TARGET = "agent-runner@my-project.iam.gserviceaccount.com"
_SEAT = "kow-seat@my-project.iam.gserviceaccount.com"


@pytest.fixture(autouse=True)
def _ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    oh.apply_public_ssrf_stub(monkeypatch)


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _addon(tmp_path: Path, backend: FakeBackend, inject_yaml: str) -> tuple[Any, Path]:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {audit}
secrets:
  GCP:
    placeholder: "{_PH}"
    inject:
{inject_yaml}
    bindings:
      - host: {_HOST}
"""
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, audit


_IMPERSONATE_ADC = f"""      type: gcp_service_account
      mode: impersonate
      source: adc
      service_account_email: {_TARGET}
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
"""

_IMPERSONATE_SEAT = f"""      type: gcp_service_account
      mode: impersonate
      source: seat_key
      service_account_email: {_TARGET}
      source_service_account_email: {_SEAT}
      private_key_secret: GCP_SEAT_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
"""

_JWT_GRANT = f"""      type: gcp_service_account
      mode: jwt_bearer_grant
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
"""

_SELF_SIGNED = f"""      type: gcp_service_account
      mode: self_signed_jwt
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      audience: "https://bigquery.googleapis.com/"
"""


def _iam_body(token: str = "ya29.impersonated", expire: str = "2099-01-01T00:00:00Z") -> bytes:
    return json.dumps({"accessToken": token, "expireTime": expire}).encode()


def _oauth_body(token: str = "ya29.exchanged", expires_in: int = 3600) -> bytes:
    return json.dumps(
        {"access_token": token, "expires_in": expires_in, "token_type": "Bearer"}
    ).encode()


def _claims(jwt: str) -> dict[str, Any]:
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# --- mode 3: impersonation (the documented default) -------------------------


def test_impersonate_adc_mints_and_injects(tmp_path: Path) -> None:
    addon, audit_path = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH}, path="/bigquery/v2/projects/p/datasets")
    addon.http_connect(flow)
    with (
        patch(_ADC, return_value="src-token"),
        patch(_TRANSPORT, return_value=FakeResp(_iam_body())),
    ):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer ya29.impersonated"
    assert _PH not in flow.request.headers["Authorization"]
    log = audit_path.read_text()
    assert "ya29.impersonated" not in log  # minted token is never audited
    assert "src-token" not in log
    events = [json.loads(ln) for ln in log.splitlines() if ln.strip()]
    assert any(e.get("type") == "token_exchange" and e.get("outcome") == "success" for e in events)
    assert any(
        e.get("type") == "token_exchange"
        and e.get("token_url_host") == "iamcredentials.googleapis.com"
        for e in events
    )
    # The mint MODE must be auditable. The three modes are materially different
    # trust paths — a keyless network mint, a vault-held private key, and an
    # assertion with no network call — and without this field they all read as
    # an identical `token_exchange` to anyone reading the log.
    assert any(e.get("type") == "token_exchange" and e.get("mode") == "impersonate" for e in events)
    assert any(e.get("decision") == "allowed" and e.get("secret_name") == "GCP" for e in events)


def test_impersonate_adc_posts_scopes_and_lifetime(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    seen: list[Any] = []

    def _side(req: Any, timeout: float | None = None) -> FakeResp:
        seen.append(req)
        return FakeResp(_iam_body())

    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, side_effect=_side):
        addon.requestheaders(flow)

    assert len(seen) == 1
    req = seen[0]
    assert req.full_url.endswith(
        f"/v1/projects/-/serviceAccounts/{_TARGET.replace('@', '%40')}:generateAccessToken"
    )
    assert req.headers["Authorization"] == "Bearer src-token"
    body = json.loads(req.data)
    assert body["scope"] == ["https://www.googleapis.com/auth/bigquery.readonly"]
    assert body["lifetime"] == "3600s"


def test_impersonate_no_adc_fails_closed(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_ADC, side_effect=RuntimeError("no ADC")), patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()  # no egress once the source identity is unavailable


def test_impersonate_denied_by_iam_fails_closed(tmp_path: Path) -> None:
    addon, audit_path = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    err = HTTPError(
        "https://iamcredentials.googleapis.com/v1/x:generateAccessToken",
        403,
        "Forbidden",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"error":{"message":"caller lacks tokenCreator"}}'),
    )
    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, side_effect=err):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any(e.get("decision") == "denied" for e in events)


def test_impersonate_seat_key_does_two_legs(tmp_path: Path) -> None:
    pem = _rsa_pem()
    addon, audit_path = _addon(tmp_path, FakeBackend({"GCP_SEAT_KEY": pem}), _IMPERSONATE_SEAT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    seen: list[Any] = []

    def _side(req: Any, timeout: float | None = None) -> FakeResp:
        seen.append(req)
        if "oauth2" in req.full_url:
            return FakeResp(_oauth_body("ya29.seat"))
        return FakeResp(_iam_body())

    with patch(_TRANSPORT, side_effect=_side):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer ya29.impersonated"
    assert len(seen) == 2
    # Leg 1: the seat authenticates as itself, requesting only cloud-platform.
    assertion = dict(p.split("=", 1) for p in seen[0].data.decode().split("&"))["assertion"]
    from urllib.parse import unquote

    claims = _claims(unquote(assertion))
    assert claims["iss"] == _SEAT
    assert "sub" not in claims  # an exchange, not a delegation
    assert claims["scope"] == "https://www.googleapis.com/auth/cloud-platform"
    # Leg 2: the seat's token authorizes minting for the target.
    assert seen[1].headers["Authorization"] == "Bearer ya29.seat"
    log = audit_path.read_text()
    assert pem not in log
    assert "ya29.seat" not in log


def test_impersonate_seat_leg_failure_fails_closed(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_SEAT_KEY": _rsa_pem()}), _IMPERSONATE_SEAT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    err = HTTPError(
        "https://oauth2.googleapis.com/token",
        400,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"error":"invalid_grant"}'),
    )
    with patch(_TRANSPORT, side_effect=err):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH


# --- mode 2: RFC 7523 exchange ----------------------------------------------


def test_jwt_bearer_grant_exchanges_and_injects(tmp_path: Path) -> None:
    pem = _rsa_pem()
    addon, audit_path = _addon(tmp_path, FakeBackend({"GCP_KEY": pem}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    seen: list[Any] = []

    def _side(req: Any, timeout: float | None = None) -> FakeResp:
        seen.append(req)
        return FakeResp(_oauth_body())

    with patch(_TRANSPORT, side_effect=_side):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer ya29.exchanged"
    from urllib.parse import unquote

    form = dict(p.split("=", 1) for p in seen[0].data.decode().split("&"))
    assert unquote(form["grant_type"]) == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    claims = _claims(unquote(form["assertion"]))
    assert claims["iss"] == _TARGET
    # NO `sub` on an ordinary exchange: Google reads it as "act as this user" and
    # rejects an assertion whose sub is the service account itself. google-auth
    # omits it here too. (Oracle review 2026-09-11 caught this the wrong way round.)
    assert "sub" not in claims
    assert claims["aud"] == "https://oauth2.googleapis.com/token"
    assert claims["exp"] - claims["iat"] <= 3600  # Google's ceiling
    assert claims["scope"] == "https://www.googleapis.com/auth/bigquery.readonly"
    assert pem not in audit_path.read_text()


def test_jwt_bearer_grant_malformed_key_fails_closed(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_KEY": "-----NOT A PEM-----"}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()  # signing failed before any egress


def test_missing_key_secret_fails_closed(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({}), _JWT_GRANT)  # vault has no GCP_KEY
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()


# --- mode 1: self-signed assertion (no egress) ------------------------------


def test_self_signed_jwt_injects_without_network(tmp_path: Path) -> None:
    pem = _rsa_pem()
    addon, audit_path = _addon(tmp_path, FakeBackend({"GCP_KEY": pem}), _SELF_SIGNED)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)

    value = flow.request.headers["Authorization"]
    assert value.startswith("Bearer eyJ")
    m.assert_not_called()  # the assertion IS the credential
    claims = _claims(value.removeprefix("Bearer "))
    assert claims["iss"] == _TARGET
    assert claims["sub"] == _TARGET  # the self-signed form DOES set sub == iss
    assert claims["aud"] == "https://bigquery.googleapis.com/"
    assert claims["exp"] > claims["iat"]
    assert claims["exp"] - claims["iat"] <= 3600
    assert pem not in audit_path.read_text()


# --- cache + destination behaviour ------------------------------------------


def test_cache_hit_skips_second_mint(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    calls = 0

    def _side(req: Any, timeout: float | None = None) -> FakeResp:
        nonlocal calls
        calls += 1
        return FakeResp(_iam_body())

    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, side_effect=_side):
        for _ in range(2):
            flow = make_request(_HOST, {"Authorization": _PH})
            addon.http_connect(flow)
            addon.requestheaders(flow)
            assert flow.request.headers["Authorization"] == "Bearer ya29.impersonated"
    assert calls == 1


def test_rotated_seat_key_invalidates_cached_token(tmp_path: Path) -> None:
    """The key material's hash is in the cache key, so rotating the seat key
    forces a fresh mint rather than serving a token the old key bought."""
    backend = FakeBackend({"GCP_SEAT_KEY": _rsa_pem()})
    addon, _ = _addon(tmp_path, backend, _IMPERSONATE_SEAT)
    calls = 0

    def _side(req: Any, timeout: float | None = None) -> FakeResp:
        nonlocal calls
        calls += 1
        if "oauth2" in req.full_url:
            return FakeResp(_oauth_body("ya29.seat"))
        return FakeResp(_iam_body())

    with patch(_TRANSPORT, side_effect=_side):
        flow = make_request(_HOST, {"Authorization": _PH})
        addon.http_connect(flow)
        addon.requestheaders(flow)
        assert calls == 2
        backend.values["GCP_SEAT_KEY"] = _rsa_pem()  # rotation
        addon.client.flush()
        flow = make_request(_HOST, {"Authorization": _PH})
        addon.http_connect(flow)
        addon.requestheaders(flow)
    assert calls == 4  # not served from cache


# --- config validation ------------------------------------------------------


def _cfg(tmp_path: Path, inject_yaml: str) -> None:
    """Load a config with this inject block; raises on an invalid one."""
    _addon(tmp_path, FakeBackend({}), inject_yaml)


def test_delegation_requires_explicit_optin(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="allow_domain_wide_delegation"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: jwt_bearer_grant
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/drive.readonly"
      subject: user@example.com
""",
        )


def test_impersonate_rejects_a_bound_key(tmp_path: Path) -> None:
    """source: adc means the daemon's own identity mints; a key here would be
    silently ignored, which is exactly the config an operator would misread."""
    with pytest.raises(Exception, match="private_key_secret is meaningless"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: impersonate
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
""",
        )


def test_seat_key_requires_its_own_email(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="source_service_account_email"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: impersonate
      source: seat_key
      service_account_email: {_TARGET}
      private_key_secret: GCP_SEAT_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
""",
        )


def test_impersonate_rejects_delegation_subject(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="not supported in impersonate mode"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: impersonate
      service_account_email: {_TARGET}
      scopes: "https://www.googleapis.com/auth/drive.readonly"
      subject: user@example.com
      allow_domain_wide_delegation: true
""",
        )


def test_self_signed_requires_audience_or_scopes(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="requires audience"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: self_signed_jwt
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
""",
        )


def test_token_url_must_be_https(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="https"):
        _cfg(
            tmp_path,
            f"""      type: gcp_service_account
      mode: jwt_bearer_grant
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
      token_url: "http://oauth2.googleapis.com/token"
""",
        )


def test_unbound_destination_forwards_placeholder_verbatim(tmp_path: Path) -> None:
    """G5 by omission: an unbound host gets the placeholder, not an error and
    not a token."""
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request("storage.googleapis.com", {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()


# --- error legs (the fail-closed surface) -----------------------------------


def test_self_signed_malformed_key_fails_closed(tmp_path: Path) -> None:
    """Mode 1 has no network leg, so its only failure is signing itself."""
    addon, audit_path = _addon(
        tmp_path, FakeBackend({"GCP_KEY": "-----NOT A PEM-----"}), _SELF_SIGNED
    )
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any("assertion_error" in str(e.get("outcome", "")) for e in events)


@pytest.mark.parametrize(
    "body",
    [
        b"not json at all",
        b'{"no_access_token": true}',
        b'{"access_token": ""}',
    ],
    ids=["malformed", "missing_field", "empty_token"],
)
def test_oauth_response_garbage_fails_closed(tmp_path: Path, body: bytes) -> None:
    """A token endpoint that answers 200 with nonsense must not produce an
    injection. Parsing is the last gate before a credential goes on the wire."""
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_KEY": _rsa_pem()}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(body)):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH


@pytest.mark.parametrize(
    "body",
    [
        b"}{",
        b'{"no_token": 1}',
        b'{"accessToken": ""}',
    ],
    ids=["malformed", "missing_field", "empty_token"],
)
def test_iam_response_garbage_fails_closed(tmp_path: Path, body: bytes) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, return_value=FakeResp(body)):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH


def test_iam_unparseable_expiry_falls_back_to_configured_lifetime(tmp_path: Path) -> None:
    """A token with an expiry we cannot read is still usable; what must not
    happen is caching it forever."""
    addon, audit_path = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    body = json.dumps({"accessToken": "ya29.x", "expireTime": "not-a-timestamp"}).encode()
    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, return_value=FakeResp(body)):
        addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "Bearer ya29.x"
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    ttl = next(
        e["cache_ttl_effective_seconds"] for e in events if "cache_ttl_effective_seconds" in e
    )
    assert 0 < ttl <= 3600


def test_seat_key_malformed_fails_closed_before_egress(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_SEAT_KEY": "not-a-pem"}), _IMPERSONATE_SEAT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()


def test_vault_backend_exploding_fails_closed(tmp_path: Path) -> None:
    """Not a missing secret — a backend that raises something unexpected. The
    generic except exists so an unknown backend failure cannot inject."""

    class ExplodingBackend(FakeBackend):
        def fetch(self, name: str, ctx: object = None) -> object:
            raise RuntimeError("backend on fire")

    addon, _ = _addon(tmp_path, ExplodingBackend({"GCP_KEY": "x"}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()


def test_adc_without_google_auth_installed_fails_closed(tmp_path: Path) -> None:
    """The real adc_access_token path, unpatched. google-auth is an optional
    extra; when it is absent the daemon must deny, not traceback."""
    addon, _ = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT) as m:
        addon.requestheaders(flow)  # no _ADC patch: exercises the real function
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()


def test_ssrf_blocked_token_endpoint_fails_closed(tmp_path: Path) -> None:
    """ADR-0035: an operator-supplied endpoint resolving to an internal address
    is refused at request time, not just at config load."""
    from kow._ssrf_guard import SsrfBlockedError

    addon, audit_path = _addon(tmp_path, FakeBackend({"GCP_KEY": _rsa_pem()}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(
        "kow.injectors._token_transport.check_url_not_internal",
        side_effect=SsrfBlockedError("internal"),
    ):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any(e.get("outcome") == "ssrf_blocked" for e in events)


# --- protocol shape + response hardening (Oracle review 2026-09-11) ---------

_DELEGATED = f"""      type: gcp_service_account
      mode: jwt_bearer_grant
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/drive.readonly"
      subject: user@example.com
      allow_domain_wide_delegation: true
"""

_SELF_SIGNED_SCOPED = f"""      type: gcp_service_account
      mode: self_signed_jwt
      service_account_email: {_TARGET}
      private_key_secret: GCP_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
"""


def test_delegation_sets_sub_to_the_delegated_user(tmp_path: Path) -> None:
    """The one case where `sub` belongs on an exchange assertion."""
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_KEY": _rsa_pem()}), _DELEGATED)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    seen: list[Any] = []
    with patch(
        _TRANSPORT, side_effect=lambda r, timeout=None: (seen.append(r), FakeResp(_oauth_body()))[1]
    ):
        addon.requestheaders(flow)
    from urllib.parse import unquote

    form = dict(p.split("=", 1) for p in seen[0].data.decode().split("&"))
    claims = _claims(unquote(form["assertion"]))
    assert claims["sub"] == "user@example.com"
    assert claims["iss"] == _TARGET


def test_scopes_only_self_signed_omits_audience(tmp_path: Path) -> None:
    """Google's scope-based self-signed form carries no `aud`; sending the token
    endpoint there (the first draft's behaviour) is neither documented form."""
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_KEY": _rsa_pem()}), _SELF_SIGNED_SCOPED)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT):
        addon.requestheaders(flow)
    claims = _claims(flow.request.headers["Authorization"].removeprefix("Bearer "))
    assert "aud" not in claims
    assert claims["scope"] == "https://www.googleapis.com/auth/bigquery.readonly"


@pytest.mark.parametrize(
    "payload",
    [
        {"access_token": "ya29.x", "expires_in": 3600},  # no token_type
        {"access_token": "ya29.x", "token_type": "mac", "expires_in": 3600},
        {"access_token": "ya29.x", "token_type": "Bearer"},  # no expiry
        {"access_token": "ya29.x", "token_type": "Bearer", "expires_in": 0},
        {"access_token": 12345, "token_type": "Bearer", "expires_in": 3600},
    ],
    ids=["no_type", "wrong_type", "no_expiry", "zero_expiry", "non_string_token"],
)
def test_oauth_success_body_must_be_well_formed(tmp_path: Path, payload: dict[str, Any]) -> None:
    """A 200 carrying a malformed body is a failure, not a credential."""
    addon, _ = _addon(tmp_path, FakeBackend({"GCP_KEY": _rsa_pem()}), _JWT_GRANT)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(json.dumps(payload).encode())):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH


def test_iam_expiry_is_clamped_to_the_requested_lifetime(tmp_path: Path) -> None:
    """A far-future expireTime must not pin the cache for years."""
    addon, audit_path = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    body = json.dumps({"accessToken": "ya29.x", "expireTime": "2099-01-01T00:00:00Z"}).encode()
    with patch(_ADC, return_value="src-token"), patch(_TRANSPORT, return_value=FakeResp(body)):
        addon.requestheaders(flow)
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    ttl = next(
        e["cache_ttl_effective_seconds"] for e in events if "cache_ttl_effective_seconds" in e
    )
    assert ttl <= 3600


def test_provider_error_text_never_reaches_the_audit(tmp_path: Path) -> None:
    """The IAM leg sends a real source token upstream, so a hostile or broken
    endpoint could reflect it in an error body. Provider text is not audited."""
    addon, audit_path = _addon(tmp_path, FakeBackend({}), _IMPERSONATE_ADC)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    reflected = b'{"error":{"message":"bad token: ya29.SUPER-SECRET-SOURCE-TOKEN"}}'
    err = HTTPError(
        "https://iamcredentials.googleapis.com/v1/x:generateAccessToken",
        400,
        "Bad Request",
        {},  # type: ignore[arg-type]
        io.BytesIO(reflected),
    )
    with (
        patch(_ADC, return_value="ya29.SUPER-SECRET-SOURCE-TOKEN"),
        patch(_TRANSPORT, side_effect=err),
    ):
        addon.requestheaders(flow)
    log = audit_path.read_text()
    assert "SUPER-SECRET-SOURCE-TOKEN" not in log
    assert "bad token" not in log


def test_cache_identity_covers_every_mint_input() -> None:
    """Unit-level: the cache key changes when ANY mint-affecting field changes,
    because the background notes refresh keeps the cache warm across reloads."""
    from kow.config import GcpServiceAccountInjector
    from kow.injectors.gcp_service_account import _cache_identity

    base = {
        "mode": "impersonate",
        "service_account_email": _TARGET,
        "scopes": "https://www.googleapis.com/auth/bigquery.readonly",
    }
    ref = _cache_identity(GcpServiceAccountInjector(**base))
    variants = [
        {**base, "service_account_email": "other@p.iam.gserviceaccount.com"},
        {**base, "lifetime_seconds": 1800},
        {**base, "assertion_ttl_seconds": 600},
        {**base, "iam_credentials_base_url": "https://iamcredentials.example.com"},
    ]
    for v in variants:
        assert _cache_identity(GcpServiceAccountInjector(**v)) != ref, v
