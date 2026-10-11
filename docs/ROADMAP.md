# Roadmap

Forward-looking work. Design records live in [`docs/adrs/`](adrs/); an entry
here means "intended, not yet shipped." No dates — priorities, not promises.

## Shipped

- `header`, `body`, `multi` injectors; composite `template + compose`.
- `oauth2_refresh` injector — RFC 6749 §6 refresh-token grant, per-token TTL
  cache, SSRF-guarded token endpoint, refresh-token rotation + write-back
  ([ADR-0017](adrs/ADR-0017-oauth2-refresh-injector.md)).
- Host-validation hardening — reject empty / bare-`*` / public-suffix
  wildcards; wildcard hosts opt-in (`allow_wildcard_hosts`).
- Config hot-reload — atomic snapshot/publish on `configure()`; in-flight
  requests keep their captured state, no restart needed.
- Supply-chain gates — hash-pinned lockfiles, TruffleHog secret scan,
  `pip-audit`, and a pre-release checklist.
- Honeytoken tripwire — a per-secret `honeytoken` flag emits a
  `honeytoken_triggered` audit event on any use of a planted placeholder
  ([ADR-0019](adrs/ADR-0019-off-box-audit-shipping.md), `accepted`). The
  off-box shipping half (Fluent Bit sidecar → central collector) lives in
  separate repos, not here.
- Google Secret Manager backend (`backend.type: gsm`) — keyless auth,
  per-secret least privilege, `kow-binding` annotation bindings
  ([ADR-0018](adrs/ADR-0018-gcp-secret-manager-backend.md), shipped 0.8.0).
- TLS termination scoped to bound hosts — `tls_termination: bound` (default)
  MITM-terminates + injects only bound hosts; every other CONNECT tunnels
  opaquely (no decryption, real-PKI end-to-end), logged via `tls_passthrough`.
  `all` restores full termination ([ADR-0026](adrs/ADR-0026-tls-termination-scoping.md),
  accepted).

- **ssh-agent signing oracle (experimental)** — opt-in top-level `ssh:`
  section: kow serves the SSH agent protocol (RFC 9987) on a Unix socket and
  signs userauth challenges with vault-held keys; destination policy via
  verified `session-bind@openssh.com` against per-binding pinned host keys;
  `kow env` exports `SSH_AUTH_SOCK`. Ansible integrates with that one env
  var ([ADR-0053](adrs/ADR-0053-ssh-agent-signing-oracle.md), `proposed`).

## Planned

### Security posture
- *(Shipped — see above: TLS termination scoping, [ADR-0026](adrs/ADR-0026-tls-termination-scoping.md).)*

### Supply chain
- **Artifact signing + SBOM** — the gates above cover *inputs*; still to add
  on *outputs*: sign released wheels/images (e.g. Sigstore/cosign) and publish
  an SBOM (CycloneDX/SPDX) so downstream consumers can verify provenance.

### Observability
- **Metrics endpoint** — the `/healthz` liveness/readiness probe has shipped
  (a request through the proxy to the reserved
  `healthz.kow.invalid/healthz` sentinel returns `200` once kow
  is fully configured, `503` while starting; the Docker healthcheck uses it).
  Still missing a Prometheus-style metrics surface (exchange counts, cache hit
  rate, deny reasons).

### Injector types — COMPLETE

All nine injector types ship. Static substitution: `header`, `body`, `multi`, composite
`template + compose`. Network exchange (requestheaders seam): `oauth2_refresh`
([ADR-0017](adrs/ADR-0017-oauth2-refresh-injector.md)), `oauth2_client_credentials`, `github_app`
([ADR-0030](adrs/ADR-0030-oauth2-cc-github-app-injectors.md)). Request signing (request-hook seam):
`sigv4` ([ADR-0027](adrs/ADR-0027-sigv4-injector.md)), `hmac`, `jwt_bearer`
([ADR-0028](adrs/ADR-0028-hmac-jwt-signing-injectors.md)). The `_INJECTOR_TYPES` "not yet
implemented" guard is retained for any future additions.
