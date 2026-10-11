"""BWS-notes vs file-backend schema parity tests.

The planned BWS-notes loader will move binding policy from a file-loaded
``bindings.yaml`` into the ``notes`` field of each BWS secret. Both
loaders must produce byte-identical ``InjectorSpec`` / ``SecretSpec`` /
``Config`` instances for the same canonical schema input — otherwise
migration between the two backends would silently change behavior.

This file pins the parity invariant per injector type. As each new
injector lands (P0.6 Body, P0.7 Multi, P1 Oauth2Refresh / GithubApp,
P2 Sigv4 / ClientCredentials / JwtBearer, P3 Sigv4 modes, P4 Hmac),
add one canonical example here and assert byte-equality between the
file-loaded and notes-loaded parses.

For v0.5.0 P0 only ``HeaderInjector`` is implemented; the union has
one element. The parity test exercises just that one type. When more
types land, extend ``CANONICAL_INJECTOR_SCHEMAS`` below.

Implementation note on the BWS-notes simulation: the daemon-side
``BwsNotesBackend`` will fetch a BWS secret, parse its ``notes``
field as YAML, and merge it with the top-level Config skeleton. For
the parity test we simulate that path by constructing the SAME yaml
blob and passing it through ``Config.model_validate``. The single
schema must round-trip identically — the storage location (file vs
BWS notes) is irrelevant once the YAML is in hand.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest
import yaml

from kow.config import Config


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Schema parity is what this file pins; the SSRF guard is its own
    test surface. Stub DNS so the explicit-URL canonical schemas
    parse hermetically regardless of resolver state."""

    def stub(host: str, *_args: object, **_kw: object) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr("kow._ssrf_guard.socket.getaddrinfo", stub)
    yield


# Canonical placeholders meeting the validator's hardening rules.
_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"
_BAR_PH = "bar_PLACEHOLDER_01HXY1234567890"

# Each entry: (label, yaml_blob). One canonical example per implemented
# injector type. Extend as new types ship.
CANONICAL_INJECTOR_SCHEMAS: list[tuple[str, str]] = [
    (
        "header_minimal_v1",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_explicit_type_v1",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: header
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_minimal_v2",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_with_methods_and_paths",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
        methods: [GET, POST]
        paths: ["/v1/*", "/v2/**"]
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_with_wildcard_host",
        f"""
version: 1
allow_wildcard_hosts: true
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: "*.example.com"
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_composite_template",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      template: "Basic {{{{ (USER + ':' + TOKEN) | b64encode }}}}"
    compose: [USER, TOKEN]
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "two_secrets",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
  BAR:
    placeholder: "{_BAR_PH}"
    inject:
      header: X-Other
      format: "{{BAR}}"
    bindings:
      - host: other.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "body_minimal_v1",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: body
      format: "{{FOO}}"
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "body_with_content_type_v2",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: body
      content_type: application/json
      format: "{{FOO}}"
    bindings:
      - host: api.example.com
        methods: [POST]
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "header_and_body_on_same_host",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: header
      header: Authorization
      format: "Bearer {{FOO}}"
    bindings:
      - host: api.example.com
  BAR:
    placeholder: "{_BAR_PH}"
    inject:
      type: body
      content_type: application/json
      format: "{{BAR}}"
    bindings:
      - host: api.example.com
        methods: [POST]
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "multi_header_plus_body",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: multi
      injectors:
        - type: header
          header: Authorization
          format: "Bearer {{FOO}}"
        - type: body
          content_type: application/json
          format: "{{FOO}}"
    bindings:
      - host: api.example.com
        methods: [POST]
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "oauth2_refresh_provider_preset",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: oauth2_refresh
      provider: google
      client_id_secret: FOO_CLIENT_ID
      client_secret_secret: FOO_CLIENT_SECRET
      refresh_token_secret: FOO_REFRESH_TOKEN
    bindings:
      - host: www.googleapis.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "oauth2_refresh_explicit",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: oauth2_refresh
      token_url: https://oauth2.example.com/token
      client_auth_method: body_post
      client_id_secret: FOO_CLIENT_ID
      client_secret_secret: FOO_CLIENT_SECRET
      refresh_token_secret: FOO_REFRESH_TOKEN
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "sigv4_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: sigv4
      region: us-east-1
      service: s3
      access_key_id_secret: FOO_AWS_ACCESS_KEY_ID
      secret_access_key_secret: FOO_AWS_SECRET_ACCESS_KEY
    bindings:
      - host: s3.us-east-1.amazonaws.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "hmac_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: hmac
      secret_key_secret: FOO_HMAC_KEY
      signing_string: "{{method}}\\n{{path}}\\n{{timestamp}}"
      header: X-Signature
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "jwt_bearer_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: jwt_bearer
      signing_key_secret: FOO_JWT_KEY
      algorithm: RS256
      issuer: avp
      audience: https://api.example.com
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "oauth2_client_credentials_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: oauth2_client_credentials
      token_url: https://oauth.example.com/token
      client_id_secret: FOO_CLIENT_ID
      client_secret_secret: FOO_CLIENT_SECRET
      scopes: read
    bindings:
      - host: api.example.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "github_app_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: github_app
      app_id: "123456"
      installation_id: "789"
      private_key_secret: FOO_APP_KEY
    bindings:
      - host: api.github.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "gcp_service_account_impersonate_minimal",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: gcp_service_account
      mode: impersonate
      service_account_email: agent@proj.iam.gserviceaccount.com
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
    bindings:
      - host: bigquery.googleapis.com
audit:
  path: /tmp/x.jsonl
""",
    ),
    (
        "gcp_service_account_key_modes",
        f"""
version: 1
secrets:
  FOO:
    placeholder: "{_FOO_PH}"
    inject:
      type: gcp_service_account
      mode: jwt_bearer_grant
      service_account_email: agent@proj.iam.gserviceaccount.com
      private_key_secret: FOO_SA_KEY
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
    bindings:
      - host: bigquery.googleapis.com
audit:
  path: /tmp/x.jsonl
""",
    ),
]


def _canonical_dump(config: Config) -> str:
    """Stable string representation for byte-equality assertions.

    ``pydantic.BaseModel.model_dump`` is order-stable for the same
    schema. ``json.dumps`` with sorted keys gives us a deterministic
    string that two different parse paths must produce identically.
    """
    import json

    return json.dumps(config.model_dump(mode="json"), sort_keys=True, indent=2)


def test_canonical_schemas_round_trip_byte_identical() -> None:
    """For each canonical schema, parse it twice through Config and
    assert byte-equality. This is the parity floor: the same YAML must
    produce the same Config regardless of which path called
    ``Config.model_validate``.

    When the daemon-side ADR-0011 lands the BWS-notes backend, that
    backend will assemble the same YAML structure from BWS Notes fields
    and call ``Config.model_validate`` on it. As long as the YAML is
    identical, the Config is identical — the parity test pins that
    invariant.
    """
    for label, yaml_blob in CANONICAL_INJECTOR_SCHEMAS:
        raw = yaml.safe_load(yaml_blob)
        # Parse twice; in practice the second path will be the BWS-notes
        # backend assembling YAML from secret.notes. For now both paths
        # are identical — the test will fail loudly if any future change
        # introduces parse-time state (e.g. a global counter, env-var
        # read, or random ordering) that breaks idempotency.
        config_a = Config.model_validate(raw)
        config_b = Config.model_validate(raw)
        dump_a = _canonical_dump(config_a)
        dump_b = _canonical_dump(config_b)
        assert dump_a == dump_b, (
            f"parity violation for canonical schema {label!r}: "
            f"two parses produced different Config instances. "
            f"This is a pre-condition for the BWS-notes backend "
            f"(daemon-side ADR-0011) — see tests/test_backend_parity.py "
            f"and the design doc §13.1."
        )


def test_canonical_schemas_inject_type_default_matches_explicit() -> None:
    """A YAML inject block with no ``type:`` field must produce the
    same parsed value as one with ``type: header`` explicit. This is
    the backward-compat invariant: every v0.4.x bindings.yaml in
    existence omits ``type:``, and they must continue to parse as
    HeaderInjector under v0.5.0.
    """
    minimal_yaml = next(
        blob for label, blob in CANONICAL_INJECTOR_SCHEMAS if label == "header_minimal_v1"
    )
    explicit_yaml = next(
        blob for label, blob in CANONICAL_INJECTOR_SCHEMAS if label == "header_explicit_type_v1"
    )
    config_minimal = Config.model_validate(yaml.safe_load(minimal_yaml))
    config_explicit = Config.model_validate(yaml.safe_load(explicit_yaml))
    assert config_minimal.secrets["FOO"].inject.type == "header"
    assert config_explicit.secrets["FOO"].inject.type == "header"
    # Both should produce identical dumps (the discriminator field's
    # default makes the type field appear in dump output for both).
    assert _canonical_dump(config_minimal) == _canonical_dump(config_explicit)


def test_canonical_schemas_cover_implemented_injector_types() -> None:
    """Meta-test: every implemented injector type has at least one
    canonical example. When new types ship, this test fails until an
    example is added — forcing parity coverage as a structural gate.
    """
    from kow.config import _INJECTOR_TYPES

    implemented = {k for k, v in _INJECTOR_TYPES.items() if not v.startswith("planned:")}

    covered_types: set[str] = set()
    for _label, yaml_blob in CANONICAL_INJECTOR_SCHEMAS:
        raw = yaml.safe_load(yaml_blob)
        for secret in raw.get("secrets", {}).values():
            inject = secret.get("inject", {})
            t = inject.get("type", "header")
            covered_types.add(t)

    missing = implemented - covered_types
    assert not missing, (
        f"injector types {sorted(missing)} are implemented in _INJECTOR_TYPES "
        f"but have no canonical example in CANONICAL_INJECTOR_SCHEMAS. "
        f"Add one; the parity test cannot pin an invariant it doesn't exercise."
    )
