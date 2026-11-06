"""Header splitting through token-minting injectors (Oracle C1).

The CR/LF gate in HeaderInjectionHandler runs only on the static-secret path;
minted tokens go out through each resolver's own header write. So both trust
boundaries are guarded where the value enters instead: the injector's
``header``/``format`` (settable from vault notes) at config load, and the
token endpoint's response at parse time. mitmproxy serialises a CR/LF in a
header value verbatim, so either one would split the upstream request.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from pydantic import ValidationError

from kow.config import SecretSpec
from kow.injectors._token_transport import TokenResult
from kow.injectors.gcp_service_account import _parse_iam_token
from kow.injectors.oauth2_refresh import _parse_success

_SA = "agent-runner@my-project.iam.gserviceaccount.com"
_MINTING: dict[str, dict[str, Any]] = {
    "gcp_service_account": {
        "mode": "impersonate",
        "service_account_email": _SA,
        "scopes": "https://www.googleapis.com/auth/cloud-platform",
    },
    "oauth2_client_credentials": {
        "token_url": "https://auth.example.com/token",
        "client_id_secret": "CID",
        "client_secret_secret": "CSEC",
    },
    "github_app": {"app_id": "1", "installation_id": "2", "private_key_secret": "PK"},
    "jwt_bearer": {"signing_key_secret": "KEY"},
}
_TOKEN_VAR = {"github_app": "{token}", "jwt_bearer": "{jwt}"}


def _spec(inject_type: str, **overrides: str) -> SecretSpec:
    return SecretSpec.model_validate(
        {
            "placeholder": "kow-PLACEHOLDER-01HXY1234567890",
            "inject": {"type": inject_type, **_MINTING[inject_type], **overrides},
            "bindings": [{"host": "api.example.com"}],
        }
    )


@pytest.mark.parametrize("inject_type", sorted(_MINTING))
def test_defaults_still_load(inject_type: str) -> None:
    _spec(inject_type)


@pytest.mark.parametrize("inject_type", sorted(_MINTING))
@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "Bearer TOKEN\r\nX-Evil: 1"),
        ("header", "Authorization\r\nX-Evil"),
        ("header", "X-Auth: injected"),
    ],
)
def test_break_characters_in_header_fields_are_refused(
    inject_type: str, field: str, value: str
) -> None:
    value = value.replace("TOKEN", _TOKEN_VAR.get(inject_type, "{access_token}"))
    with pytest.raises(ValidationError, match="control|field name"):
        _spec(inject_type, **{field: value})


def test_token_result_refuses_a_success_carrying_break_characters() -> None:
    result = TokenResult(outcome="success", token="ya29.ok\r\nX-Evil: 1", expires_at=1.0)
    assert result.outcome == "response_parse_failed"
    assert result.token is None


def test_gcp_iam_token_with_crlf_is_a_parse_failure() -> None:
    expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 600))
    body = json.dumps({"accessToken": "ya29.ok\r\nX-Evil: 1", "expireTime": expiry}).encode()
    injector = _spec("gcp_service_account").inject
    assert _parse_iam_token(body, injector).outcome == "response_parse_failed"  # type: ignore[arg-type]


def test_oauth2_refresh_access_token_with_crlf_is_a_parse_failure() -> None:
    from kow.config_models import Oauth2RefreshInjector

    # construct, not validate: validation resolves token_url in DNS, and the
    # parser reads only the TTL defaults.
    spec = Oauth2RefreshInjector.model_construct()
    body = json.dumps({"access_token": "at\r\nX-Evil: 1", "token_type": "Bearer"}).encode()
    assert _parse_success(body, "RT-in", spec).outcome == "response_parse_failed"
