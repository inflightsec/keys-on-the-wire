"""ADR-0050 — the ADC credential endpoint.

Drives the real listener over real HTTP. The invariant under test is the one the
whole design rests on: what comes out of this port is a PLACEHOLDER, never a
credential, so an unauthenticated loopback listener is an acceptable thing to
run. The rest is protocol fidelity — the paths ADC actually probes, and the
``Metadata-Flavor`` gate the real server enforces.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from kow.addon import AgentVaultProxyAddon
from kow.config import Config, CredentialEndpointSpec
from kow.credential_endpoint import CredentialEndpoint
from tests._oauth_helpers import FakeBackend

_PH = "ya29.kow-PLACEHOLDER-01HXY1234567890"
_SA = "agent-runner@my-project.iam.gserviceaccount.com"
_FLAVOR = {"Metadata-Flavor": "Google"}


@pytest.fixture
def endpoint() -> Iterator[CredentialEndpoint]:
    spec = CredentialEndpointSpec(
        enabled=True,
        port=0,  # ephemeral
        binding="GCP",
        service_account_email=_SA,
        project_id="my-project",
        scopes="https://www.googleapis.com/auth/bigquery.readonly",
    )
    object.__setattr__(spec, "placeholder", _PH)
    ep = CredentialEndpoint(spec)
    ep.start()
    yield ep
    ep.stop()


def _get(
    ep: CredentialEndpoint, path: str, headers: dict[str, str] | None = None
) -> tuple[int, str]:
    req = urllib.request.Request(  # noqa: S310 — loopback, fixed scheme
        f"http://127.0.0.1:{ep.port}{path}", headers=_FLAVOR if headers is None else headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_token_endpoint_serves_the_placeholder_not_a_credential(
    endpoint: CredentialEndpoint,
) -> None:
    status, body = _get(endpoint, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert status == 200
    payload = json.loads(body)
    assert payload["access_token"] == _PH
    assert payload["token_type"] == "Bearer"
    assert payload["expires_in"] == 3600
    # The whole point: nothing usable left this port.
    assert "ya29.kow-PLACEHOLDER" in payload["access_token"]


def test_metadata_flavor_header_is_required(endpoint: CredentialEndpoint) -> None:
    """Matches the real server: without the header there is no answer, which is
    what makes a browser-driven request against this port useless."""
    status, _ = _get(
        endpoint, "/computeMetadata/v1/instance/service-accounts/default/token", headers={}
    )
    assert status == 403


def test_serves_the_documented_scalar_paths(endpoint: CredentialEndpoint) -> None:
    assert _get(endpoint, "/computeMetadata/v1/instance/service-accounts/default/email") == (
        200,
        _SA,
    )
    status, body = _get(endpoint, "/computeMetadata/v1/instance/service-accounts/default/scopes")
    assert status == 200
    assert body.strip() == "https://www.googleapis.com/auth/bigquery.readonly"
    assert _get(endpoint, "/computeMetadata/v1/project/project-id") == (200, "my-project")
    assert _get(endpoint, "/computeMetadata/v1/universe/universe-domain") == (
        200,
        "googleapis.com",
    )
    # Detection ping.
    status, _ = _get(endpoint, "/")
    assert status == 200


def test_unknown_path_is_404(endpoint: CredentialEndpoint) -> None:
    status, _ = _get(endpoint, "/computeMetadata/v1/instance/disks/0/device-name")
    assert status == 404


def test_named_service_account_path_matches_default(endpoint: CredentialEndpoint) -> None:
    """Clients address the account by email as often as by 'default'."""
    status, body = _get(endpoint, f"/computeMetadata/v1/instance/service-accounts/{_SA}/token")
    assert status == 200
    assert json.loads(body)["access_token"] == _PH


# --- config + lifecycle -----------------------------------------------------


def _config_yaml(tmp_path: Path, *, binding: str = "GCP") -> Path:
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {tmp_path / "audit.jsonl"}
secrets:
  GCP:
    placeholder: "{_PH}"
    inject:
      type: gcp_service_account
      mode: impersonate
      service_account_email: {_SA}
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
    bindings:
      - host: bigquery.googleapis.com
credential_endpoint:
  enabled: true
  port: 0
  binding: {binding}
  service_account_email: {_SA}
  project_id: my-project
"""
    )
    return cfg


def test_addon_starts_and_stops_the_endpoint(tmp_path: Path) -> None:
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(_config_yaml(tmp_path)), backend_override=FakeBackend({}))
    ep = addon._credential_endpoint
    assert ep is not None
    status, body = _get(ep, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert json.loads(body)["access_token"] == _PH
    addon.done()
    assert addon._credential_endpoint is None


def test_end_to_end_endpoint_token_is_substituted_by_the_injector(tmp_path: Path) -> None:
    """The whole design in one test.

    Take what the endpoint hands a client, put it in an Authorization header the
    way an ADC-based client library would, run it through the proxy, and confirm
    the placeholder is replaced by a real minted token. If this passes, an
    application that never saw a service-account key just authenticated as one.
    """
    from unittest.mock import patch

    from tests._oauth_helpers import FakeResp, apply_public_ssrf_stub, make_request

    monkeypatch = pytest.MonkeyPatch()
    apply_public_ssrf_stub(monkeypatch)
    try:
        addon = AgentVaultProxyAddon()
        addon.configure_from_path(str(_config_yaml(tmp_path)), backend_override=FakeBackend({}))
        ep = addon._credential_endpoint
        assert ep is not None

        # 1. The client resolves ADC against the endpoint.
        _, body = _get(ep, "/computeMetadata/v1/instance/service-accounts/default/token")
        client_token = json.loads(body)["access_token"]
        assert client_token == _PH  # not a credential

        # 2. The client calls the API with what it was given.
        flow = make_request(
            "bigquery.googleapis.com",
            {"Authorization": f"Bearer {client_token}"},
            path="/bigquery/v2/projects/my-project/datasets",
        )
        addon.http_connect(flow)
        iam = json.dumps(
            {"accessToken": "ya29.real-minted", "expireTime": "2099-01-01T00:00:00Z"}
        ).encode()
        with (
            patch("kow.injectors.gcp_service_account.adc_access_token", return_value="src"),
            patch("kow.injectors._token_transport.transport_open", return_value=FakeResp(iam)),
        ):
            addon.requestheaders(flow)

        # 3. What leaves kow is the minted token; what the client held never was.
        assert flow.request.headers["Authorization"] == "Bearer ya29.real-minted"
        assert _PH not in flow.request.headers["Authorization"]
        addon.done()
    finally:
        monkeypatch.undo()


def test_endpoint_placeholder_tracks_the_binding(tmp_path: Path) -> None:
    """Resolved from the secret, never configured twice — an endpoint serving a
    placeholder no binding matches would produce upstream 401s pointing nowhere."""
    cfg = Config.model_validate(
        {
            "version": 1,
            "binding_source": "file",
            "audit": {"path": str(tmp_path / "a.jsonl")},
            "secrets": {
                "GCP": {
                    "placeholder": _PH,
                    "inject": {
                        "type": "gcp_service_account",
                        "mode": "impersonate",
                        "service_account_email": _SA,
                        "scopes": "https://www.googleapis.com/auth/bigquery.readonly",
                    },
                    "bindings": [{"host": "bigquery.googleapis.com"}],
                }
            },
            "credential_endpoint": {
                "enabled": True,
                "binding": "GCP",
                "service_account_email": _SA,
            },
        }
    )
    assert cfg.credential_endpoint is not None
    assert cfg.credential_endpoint.placeholder == _PH


def test_endpoint_refuses_an_unknown_binding(tmp_path: Path) -> None:
    addon = AgentVaultProxyAddon()
    with pytest.raises(Exception, match="not a secret in this config"):
        addon.configure_from_path(
            str(_config_yaml(tmp_path, binding="NOPE")), backend_override=FakeBackend({})
        )


def test_endpoint_refuses_a_routable_host() -> None:
    with pytest.raises(Exception, match="must be loopback"):
        CredentialEndpointSpec(
            enabled=True,
            host="0.0.0.0",
            binding="GCP",
            service_account_email=_SA,  # noqa: S104
        )


# --- listener lifecycle -----------------------------------------------------


def _spec(placeholder: str = _PH) -> CredentialEndpointSpec:
    spec = CredentialEndpointSpec(enabled=True, port=0, binding="GCP", service_account_email=_SA)
    object.__setattr__(spec, "placeholder", placeholder)
    return spec


def test_double_start_is_idempotent() -> None:
    """configure() can run twice; a second listener on the same port would
    either raise or orphan the first."""
    ep = CredentialEndpoint(_spec())
    ep.start()
    port = ep.port
    try:
        ep.start()
        assert ep.port == port
        status, _ = _get(ep, "/computeMetadata/v1/instance/service-accounts/default/email")
        assert status == 200
    finally:
        ep.stop()


def test_stop_without_start_is_a_no_op() -> None:
    CredentialEndpoint(_spec()).stop()  # must not raise


def test_stop_is_idempotent() -> None:
    ep = CredentialEndpoint(_spec())
    ep.start()
    ep.stop()
    ep.stop()
    assert ep.port is None


def test_non_token_shaped_placeholder_warns(caplog: pytest.LogCaptureFixture) -> None:
    """Some SDKs validate the token shape, so a placeholder that cannot pass as
    one is a config smell worth saying out loud."""
    ep = CredentialEndpoint(_spec(placeholder="kow-PLACEHOLDER-not-token-shaped"))
    with caplog.at_level("WARNING"):
        ep.start()
    ep.stop()
    assert any("does not start with" in r.message for r in caplog.records)


def test_reload_reissues_the_endpoint_with_the_new_placeholder(tmp_path: Path) -> None:
    """A stale listener would keep serving a placeholder the new config no
    longer substitutes, which fails upstream with no clue why."""
    addon = AgentVaultProxyAddon()
    cfg = _config_yaml(tmp_path)
    addon.configure_from_path(str(cfg), backend_override=FakeBackend({}))
    first = addon._credential_endpoint
    assert first is not None

    new_ph = "ya29.kow-PLACEHOLDER-98765432109876"
    cfg.write_text(cfg.read_text().replace(_PH, new_ph))
    addon.configure_from_path(str(cfg), backend_override=FakeBackend({}))
    second = addon._credential_endpoint
    assert second is not None
    assert second is not first
    _, body = _get(second, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert json.loads(body)["access_token"] == new_ph
    addon.done()


# --- SDK protocol fidelity (Oracle review 2026-09-11) -----------------------


def _get_full(ep: CredentialEndpoint, path: str) -> tuple[int, str, str]:
    """Status, body, and content-type — the header matters as much as the body."""
    req = urllib.request.Request(f"http://127.0.0.1:{ep.port}{path}", headers=_FLAVOR)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return resp.status, resp.read().decode(), resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers.get("Content-Type", "")


def test_token_response_is_labelled_json(endpoint: CredentialEndpoint) -> None:
    """google-auth only JSON-decodes a response labelled application/json. A
    mislabelled token document hands it a string where it needs a mapping."""
    status, body, ctype = _get_full(
        endpoint, "/computeMetadata/v1/instance/service-accounts/default/token"
    )
    assert status == 200
    assert ctype == "application/json"
    assert json.loads(body)["access_token"] == _PH


def test_recursive_service_account_document(endpoint: CredentialEndpoint) -> None:
    """ADC discovery asks for ?recursive=true and expects an object with
    aliases/email/scopes. Returning a directory listing here makes the client
    fall through to another credential source, silently."""
    status, body, ctype = _get_full(
        endpoint, "/computeMetadata/v1/instance/service-accounts/default/?recursive=true"
    )
    assert status == 200
    assert ctype == "application/json"
    doc = json.loads(body)
    assert doc["email"] == _SA
    assert doc["aliases"] == ["default"]
    assert doc["scopes"] == ["https://www.googleapis.com/auth/bigquery.readonly"]


def test_recursive_service_accounts_index(endpoint: CredentialEndpoint) -> None:
    status, body, ctype = _get_full(
        endpoint, "/computeMetadata/v1/instance/service-accounts/?recursive=true"
    )
    assert status == 200
    assert ctype == "application/json"
    doc = json.loads(body)
    assert doc["default"]["email"] == _SA
    assert _SA in doc


def test_scalar_paths_are_plain_text(endpoint: CredentialEndpoint) -> None:
    _, _, ctype = _get_full(endpoint, "/computeMetadata/v1/instance/service-accounts/default/email")
    assert ctype == "text/plain"


def test_query_string_does_not_break_the_scalar_table(endpoint: CredentialEndpoint) -> None:
    """A query kow does not understand must not turn a known path into a 404."""
    status, body, _ = _get_full(
        endpoint, "/computeMetadata/v1/instance/service-accounts/default/email?alt=json"
    )
    assert status == 200
    assert body == _SA


# --- endpoint / binding coherence (Oracle review 2026-09-11) ---------------


def _cfg_dict(tmp_path: Path, *, inject: dict, endpoint: dict) -> dict:
    return {
        "version": 1,
        "binding_source": "file",
        "audit": {"path": str(tmp_path / "a.jsonl")},
        "secrets": {
            "GCP": {
                "placeholder": _PH,
                "inject": inject,
                "bindings": [{"host": "bigquery.googleapis.com"}],
            }
        },
        "credential_endpoint": {"enabled": True, "binding": "GCP", **endpoint},
    }


_GCP_INJECT = {
    "type": "gcp_service_account",
    "mode": "impersonate",
    "service_account_email": _SA,
    "scopes": "https://www.googleapis.com/auth/bigquery.readonly",
}


def test_endpoint_derives_identity_and_scopes_from_the_binding(tmp_path: Path) -> None:
    """Stated nowhere twice: what the endpoint advertises comes from what kow
    will actually authenticate as."""
    cfg = Config.model_validate(_cfg_dict(tmp_path, inject=_GCP_INJECT, endpoint={}))
    ep = cfg.credential_endpoint
    assert ep is not None
    assert ep.service_account_email == _SA
    assert ep.scopes == "https://www.googleapis.com/auth/bigquery.readonly"


def test_endpoint_refuses_an_identity_that_disagrees_with_the_binding(tmp_path: Path) -> None:
    """Advertising one service account while minting another is not an override,
    it is a way to be wrong quietly."""
    with pytest.raises(Exception, match="disagrees with the binding"):
        Config.model_validate(
            _cfg_dict(
                tmp_path,
                inject=_GCP_INJECT,
                endpoint={"service_account_email": "someone-else@p.iam.gserviceaccount.com"},
            )
        )


def test_endpoint_refuses_scopes_that_disagree_with_the_binding(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="disagrees with the binding's scopes"):
        Config.model_validate(
            _cfg_dict(
                tmp_path,
                inject=_GCP_INJECT,
                endpoint={"scopes": "https://www.googleapis.com/auth/cloud-platform"},
            )
        )


def test_endpoint_refuses_a_non_gcp_binding(tmp_path: Path) -> None:
    """A header binding has no minting step, so fronting it with a metadata
    endpoint would advertise an identity that does not exist."""
    with pytest.raises(Exception, match="not a gcp_service_account binding"):
        Config.model_validate(
            _cfg_dict(
                tmp_path,
                inject={"type": "header", "header": "Authorization", "format": "Bearer {GCP}"},
                endpoint={"service_account_email": _SA},
            )
        )
