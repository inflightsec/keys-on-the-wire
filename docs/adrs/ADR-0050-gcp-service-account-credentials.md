---
status: proposed
date: 2026-09-11
relates_to: ADR-0018 (GSM backend — the daemon's existing GCP identity), ADR-0020 (service templates), ADR-0023 (closed audit event set), ADR-0027 (sigv4 re-signing), ADR-0028 (jwt_bearer signer), ADR-0029 (stored placeholders), ADR-0030 ("the taxonomy is now complete"), ADR-0031 (response echo scrubbing), ADR-0034 (wildcard host subdomains), ADR-0035 (pinned vetted address for token egress), ADR-0047 (destination policy defaults), ADR-0049 (a listener is not a request), docs/architecture.md §3 (G1–G9)
references:
  - RFC 7523 §2.1 — JWT profile for OAuth 2.0, authorization-grant flow
  - RFC 7519 / RFC 7515 — JWT / JWS structure and signing
  - Google — "Using OAuth 2.0 for Server to Server Applications" (incl. the addendum on authorization without OAuth)
  - Google IAM Credentials — `projects.serviceAccounts.generateAccessToken`
  - Google IAM — best practices for service accounts; credential access boundaries
  - Google Cloud — token types, Application Default Credentials, metadata server, Workload Identity Federation
  - Prior art — `salrashid123/gce_metadata_server` (metadata emulation, env-var routing, token sourcing)
---

# ADR-0050: Google service-account credentials as a brokered injector

> **Status: PROPOSED, revised 2026-09-11** after the operator stated the
> requirements in the next section. The first draft ranked five options and
> rejected metadata emulation outright; the requirements invert that ranking, and
> the rejection does not survive the placeholder construction in option D.
>
> **Implemented 2026-09-11** (uncommitted, awaiting live verification): the
> `gcp_service_account` injector in all three modes, and the credential endpoint.
> 29 new tests, full suite 1570 green, ruff and mypy clean, the ADR-0035
> token-egress chokepoint gate passing. What is NOT yet verified is named in
> *Verification status* at the end.

## Context

kow already speaks to Google in one direction. ADR-0018 gave the daemon a GSM
backend whose identity is a service account, reached keylessly through
Application Default Credentials, impersonation, or Workload Identity Federation,
with `reject_ambient_key` refusing a downloaded key and a deliberate absence of
any key-file config field. That is the *read* leg: a service account is how kow
gets secrets out of the vault.

The ask here is the other direction. An agent wants to call a Google API, and the
credential authorizing that call is a service account. Today the operator's only
real option is a service-account JSON key on disk where the agent can read it,
which is the exact failure mode kow exists to remove, and it is worse than an
ordinary API key: long-lived, usable from anywhere on the internet, and usually
bound to a role broader than the one call needed.

Three facts about Google's model shape every option.

**A service-account private key is not a bearer credential.** Unlike an API key
it is never sent to the API; it signs something. There is no static string to
substitute, so the `header` injector is structurally inapplicable and every path
below is a computed injector, in the family of `sigv4`, `hmac`, `jwt_bearer`,
`github_app`.

**Google accepts two signed artefacts.** A self-signed JWT presented directly as
`Authorization: Bearer <jwt>` works for a documented subset of APIs, with
`iss`/`sub` set to the service-account email. Or the same JWT is exchanged at
Google's token endpoint under the RFC 7523 `jwt-bearer` grant for an opaque
`ya29.` access token, which is what the rest of the surface expects.

**The key can be removed entirely.** IAM Credentials `generateAccessToken` mints
a short-lived token *for* a target service account, authenticated by whatever
identity the caller already holds, given `roles/iam.serviceAccountTokenCreator`
on the target. No key exists in that flow.

The fourth fact is the one the first draft under-weighted. **Applications do not
present credentials the way kow's HTTP path assumes.** An agent using `curl` can
be handed a placeholder. An application using a Google client library, `gcloud`,
or Terraform resolves its credential through Application Default Credentials
before any request is built, and if ADC finds nothing it fails without ever
reaching the proxy. Injector-shaped brokering therefore covers hand-rolled REST
calls and nothing else, which is a small fraction of what a Google-authenticated
application actually is.

## Requirements (operator, 2026-09-11)

1. **This ships to be used, not catalogued.** Documentation-only is not an
   acceptable terminal state.
2. **The agent never receives service-account authority.** Not the key, and not a
   live access token minted from it.
3. **The posture must match Google's own guidance**, which is: do not create
   service-account keys where an alternative exists, prefer impersonation and
   federation, keep lifetimes short.
4. **It must work with almost any application that authenticates as a Google
   service account**, not only with clients that can be handed a placeholder.
5. **The shape should generalise** to the equivalent mechanisms at other cloud
   providers.

Requirement 4 is the load-bearing one and it is what reopens the option the first
draft rejected.

## Options

**Option A — Documentation only, using the existing `jwt_bearer` injector.**
Vault-held PEM, `issuer`/`subject` set to the service-account email, `audience`
set to the target service, short `ttl_seconds`. Zero code, works against the
current release. Fails requirements 1, 3 (an exported key) and 4 (hand-rolled
callers only). **Retained as the fallback recipe, not as the answer.**

**Option B — `gcp_service_account` injector, `jwt_bearer_grant` mode.** Sign the
assertion, POST it to Google's token endpoint with the requested scopes, cache
the returned token to just under expiry, inject `Authorization: Bearer {token}`.
Mechanically this is `github_app` with a different endpoint and body, reusing
`jwt_bearer.encode`, `_token_transport.post`, `DerivedTokenCache` and the
existing `token_exchange` audit event. Covers every Google API, and with a
`subject` claim covers delegated Workspace access. Fails requirement 3 (an
exported key lives in the vault) and requirement 4 (still placeholder-shaped).

**Option C — The same injector, `impersonate` mode.** The daemon authenticates
with its own identity and calls `generateAccessToken` on the target service
account. No key material anywhere. Satisfies 2 and 3 cleanly. Still fails 4 on
its own, and it breaks a standing assumption: every injector today binds a
*secret name* whose value is fetched, and impersonation fetches nothing.

**Option D — A credential endpoint that dispenses placeholders.** kow answers the
metadata-server protocol on loopback and returns, in the `access_token` field, a
**kow placeholder rather than a real token**. ADC-based clients find it with no
code change, treat the placeholder as their bearer token, and send it to
`googleapis.com` through the proxy, where the existing injector path substitutes
the real credential minted by option C. The client believes it is on a Compute
Engine instance; the token it holds is inert anywhere except through kow, where
destination, method and path policy still apply.

This is what dissolves the first draft's rejection. That draft refused metadata
emulation because a loopback endpoint authenticates nobody, so any process at any
uid could ask it for a token. That objection was aimed at an endpoint dispensing
*tokens*. An endpoint dispensing *placeholders* hands a thief an opaque string
that is useless off-box and policy-bound on-box, which is the same trust level as
`kow env` output and no worse than the placeholders already sitting in the
agent's environment.

Routing needs no root and no link-local binding: Google's libraries honour
`GCE_METADATA_HOST` (with `GCE_METADATA_IP` additionally required by
`google-auth` for Python, `GCE_METADATA_ROOT` additionally read by `gcloud`, and
`METADATA_SERVER_DETECTION` to force detection), so the agent's environment gains
a variable next to the ones kow already sets.

**Option E — Extend `oauth2_client_credentials` rather than add a type.** Add
`private_key_jwt` client auth and a configurable grant type. Cheaper on surface
area; cannot express a signing key honestly, and cannot express impersonation at
all.

## Decision

**Ship option C as the minting engine and option D as the delivery mechanism.
Option B ships alongside as the keyless-impossible fallback. Option A becomes a
doc page. Option E is rejected.**

1. **One new injector type, three modes.** `gcp_service_account` with
   `mode: self_signed_jwt | jwt_bearer_grant | impersonate`. The type reopens the
   taxonomy ADR-0030 declared closed; that is admitted rather than avoided,
   because bending a client-credentials model to carry a signing key and an
   impersonation target is the more expensive lie.

2. **`impersonate` is the default and the documentation leads with it.** Google's
   guidance is to not create keys. kow should not ship a feature whose happy path
   contradicts the platform's own advice. `jwt_bearer_grant` exists for the host
   with no Google identity to impersonate from, and says so in its own errors.

3. **Two layers, named separately, because conflating them is the trap.** *Layer
   1* is how the **daemon** authenticates to Google: ADC, federation, or one
   held credential. *Layer 2* is how each **binding** gets authority: a
   per-binding impersonated token, scoped and short-lived. Requirements 2 and 3
   are layer-2 properties and are satisfied absolutely. Layer 1 is a bootstrap
   question with an honest answer below, not a place where zero is achievable on
   a host that is not itself on Google infrastructure.

4. **The recommended layer-1 bootstrap is a dedicated impersonation seat.** One
   service account whose only permission is to be impersonated, holding no data
   access of its own, with each target granting it
   `roles/iam.serviceAccountTokenCreator`. On an off-GCP host its credential is
   the one long-lived artefact in the system; it lives in the vault, never on an
   agent host, and a thief who takes it gains exactly the mint rights explicitly
   granted and nothing else. Federation replaces it wherever an attestable
   identity exists, and hardware-held key material is the documented upgrade
   path. This is stated in the docs as the system's single residual key, not
   hidden.

5. **The dispensed placeholder is shaped like the real thing.** Some SDKs
   validate token format, so the placeholder carries a `ya29.` prefix followed by
   CSPRNG material, and is a stored placeholder per ADR-0029 with the same
   minimum entropy as any other. It is minted per binding, not per request, and
   the endpoint reports an expiry that drives client-side refresh at a cadence
   kow chooses.

6. **The credential endpoint is a listener, and ADR-0049's rule applies.** It
   ships behind its own top-level config section, opt-in, bound to loopback,
   because a long-lived listener is not a request and does not belong in a
   taxonomy built for requests. Unlike ADR-0049 it introduces no second
   concurrency model for *traffic*: the endpoint answers small fixed JSON
   documents and never carries API data, which stays on the ordinary proxy path.

7. **Scope is IAM plus OAuth scopes, and kow does not pretend otherwise.** The
   narrowing levers are the target service account's roles and the `scopes`
   requested at mint time, both enforced by Google. ADR-0047's refusal of payload
   inspection holds; credential access boundaries are a later slice, not a v1
   claim. As in ADR-0049 decision 5, least privilege on the bound identity is a
   **stated requirement**, and `kow doctor` warns on a target holding a primitive
   or project-wide role.

8. **Destination scope is explicit hosts.** `*.googleapis.com` under ADR-0034
   would put one token in front of every enabled service. Bindings name the
   services they mean; token endpoints are pinned per ADR-0035.

9. **The invariants hold, including on the new path.** G1 holds by construction:
   what the agent receives from the credential endpoint is a placeholder, and
   what it sends is a placeholder. G3 is an ordinary HTTPS destination check. G5
   works unchanged, because a denied binding forwards the placeholder and Google
   answers with its own 401. G6 is the existing fsync ordering. G8's window is
   the mint cache TTL, and in `impersonate` mode there is no key to rotate at
   all. The one genuinely new exposure is the loopback endpoint itself, bounded
   by the placeholder construction in decision 5.

10. **Generalisation is the point, and it is deliberately not built yet.** The
    same shape covers the other providers' SDK credential endpoints: dispense
    placeholder credentials, then re-sign or substitute on egress, which for AWS
    is the existing `sigv4` injector re-signing a request the client signed with
    a placeholder key. The endpoint is therefore specified as a *credential
    endpoint plane* with Google as its first and only implementation, so the
    second provider is a driver rather than a redesign.

## Rejected alternatives

**Dispensing real access tokens from the credential endpoint.** The obvious
implementation, and the one that forfeits the entire property: a live token on an
unauthenticated loopback port, readable by any process at any uid, valid off-box
for its full lifetime. Rejected. The endpoint never emits a usable credential.

**Binding the link-local address, or `iptables` redirection to reach it.** Both
work and both require root and a host-wide change. The environment-variable
override achieves the same routing inside the agent's own environment, which is
where kow's configuration already lives.

**Bending `oauth2_client_credentials` (option E).** A model whose fields are a
client id and a client secret cannot honestly express a signing key, and cannot
express impersonation at all.

**Accepting the service-account JSON key file whole.** Tempting, since one
download contains `client_email`, `private_key` and `token_uri`. Rejected for v1:
it encourages storing verbatim the artefact Google's guidance says not to create,
and puts a parser in front of vault content. The operator stores the PEM and
states the email.

**Storing a long-lived access token in the vault.** Valid for an hour, not
revocable, stale for most of its life. Not offered.

## What this costs, stated plainly

Modes B and C are each roughly one injector module, one config model, one
resolver branch and tests, against precedent that already exists in `github_app`.
That is a normal slice.

The credential endpoint is not. It is a second listening surface with its own
protocol fidelity problem: clients probe `/computeMetadata/v1/` for the token,
the service-account email, project and numeric project id, and at least one SDK
fetches a universe-domain path during ADC initialisation, with a 404 meaning
"assume googleapis.com". Getting a subset wrong produces a client that hangs or
silently falls through to another credential source, which is a worse failure
than an error. The environment-variable matrix differs per language, so the
generated agent environment has to set all of them, and `kow doctor` has to prove
the endpoint answers what each SDK family asks for rather than what the spec
says.

Mode C also makes the daemon's own identity load-bearing in a new way. Today it
reads secrets; afterwards it mints tokens for other identities, so compromising
the daemon's credential is an escalation to every impersonation target. The
`serviceAccountTokenCreator` grant list belongs in the documentation next to the
feature, not behind it.

And one property genuinely degrades relative to the injector path. A client that
caches its ADC token holds the placeholder for the lifetime the endpoint
advertised, so revocation takes effect when kow refuses to substitute, not when
the client stops trying. That is still strictly better than a real cached token,
which no revocation reaches at all until expiry.

## Open before implementation

- **Keyless bindings in the policy model.** Whether `impersonate` binds a
  valueless vault entry or a new keyless binding shape, and what audit events
  carry in `secret_name` when no secret is fetched.
- **Which identity impersonates.** Reuse the GSM backend's configured identity or
  require a separately declared seat. Sharing couples vault-read authority to
  token-minting authority in a way ADR-0024 would recognise.
- **The endpoint's answer set, enumerated.** Every path each SDK family requests,
  the `Metadata-Flavor` header requirement, the universe-domain behaviour, and
  which requests are answered versus 404'd, with a conformance test per SDK.
- **gRPC-transport coverage, measured.** Credential resolution is HTTP, but
  several Google client libraries carry API traffic over gRPC, which the proxy
  path must be shown to handle before "almost any app" is a claim kow makes.
  Where it does not, the docs name the REST-transport switch.
- **Placeholder lifetime and advertised expiry.** What the endpoint reports, how
  it interacts with client-side caching, and whether a forced short expiry is the
  revocation lever.
- **Loopback exposure, restated honestly.** The endpoint hands placeholders to
  any local process. What that gives an attacker at another uid, given
  destination policy, and whether a peer-credential check on a Unix socket is
  worth the SDK incompatibility it would cause.
- **`subject` and delegation.** Whether domain-wide delegation ships at all, and
  behind what opt-in and audit field.
- **Setup helper scope.** Whether `gcp-setup` grows an impersonation-target flag
  applying `serviceAccountTokenCreator` per target and hard-failing a
  project-level bind, as it already does for `secretAccessor`.
- **Response echo scrubbing.** Whether minted tokens join the ADR-0031 scrub set.

## Workload Identity Federation, assessed

Raised as a candidate simplification. It is not one, and it belongs to a
different layer, so it is recorded here and dropped rather than left open.

Federation answers *layer 1* — how the daemon authenticates to Google — which is
already ADR-0018's territory, where the GSM backend accepts a WIF credential
configuration today. It does not touch layer 2 at all: the per-binding minting,
the placeholder substitution, and the credential endpoint are identical whether
the daemon's identity came from federation, ADC, or a seat key.

It also does not remove the residual credential on an off-cloud host, which was
the hope. Google requires the external identity provider to expose an OIDC
discovery document and JWKS over public HTTPS, or for the JWKS to be uploaded to
the pool directly (capped at eight keys, rotated by hand). On a host with no
attestable platform identity, satisfying that means kow standing up an OIDC
issuer and holding *its* signing key — the same long-lived artefact in a
different shape, plus public infrastructure to run. Federation genuinely wins
where an attestable identity already exists, and it is the documented upgrade
path in decision 4. It is not a simplification of this ADR and needs no ADR of
its own until hardware-held key material makes it a real improvement.

## Verification status

**Verified by mutation, not just by passing.** Seven deliberate breaks — the
endpoint serving a real token, the ``Metadata-Flavor`` gate removed, the injector
made fail-open, the cache key stripped of key material, the minted token added to
an audit event, a routable bind address allowed, the delegation gate removed —
were each applied to the source and each killed the suite. Tests that cannot fail
are decoration; these fail.

**Verified by test.** All three mint modes end to end through the addon; the
agent-visible placeholder replaced by the minted credential; no key and no minted
token in the audit log on any path; fail-closed 503 with the placeholder intact
on a missing key, a malformed key, an absent source identity, a refused
impersonation, and a failed seat leg; a rotated seat key invalidating the cached
token; the endpoint serving only the placeholder, gating on `Metadata-Flavor`,
and 404ing unknown paths; the config validators for every mode-coherence rule
including the domain-wide-delegation gate; and one end-to-end test that takes the
endpoint's answer, feeds it through the proxy as a client would, and asserts the
substitution.

**Adversarial review, and what it changed (2026-09-11).** A cross-model review
(OpenAI, read-only) returned ten findings; six were real and are fixed, and one
corrected a claim in this document rather than the code.

- *The exchange assertion must not carry* ``sub``. Google reads it as "act as this
  user" and rejects an assertion whose ``sub`` is the service account itself. The
  first implementation sent it on every assertion, and the test asserted that wrong
  shape rather than the protocol. Both fixed; ``sub`` now appears only for
  delegation and in the self-signed form where Google defines it.
- *The endpoint mislabelled its content types and did not answer*
  ``?recursive=true``. ``google-auth`` only JSON-decodes a response marked
  ``application/json`` and discovers the default account through the recursive
  document, so Python ADC would have fallen through to another credential source
  silently. Fixed, with tests on both the header and the document shape.
- *Provider error text was audited verbatim.* The impersonation leg sends a real
  source token upstream, so a hostile or misconfigured endpoint could reflect it
  into a durable log. No provider text is audited now; only locally-derived
  outcome labels.
- *The cache identity was incomplete* (audience, both TTL fields, the seat token
  endpoint). The full-reload path drops the cache, but the ADR-0032 background
  notes refresh keeps it warm, so this was reachable. Now every mint-affecting
  field is length-prefixed into the key.
- *Success parsing was lax.* A 200 carrying a malformed body was coerced into a
  credential and cached. Now the token must be a non-empty string, OAuth responses
  must be Bearer with a positive expiry, and an IAM expiry is clamped to the
  lifetime this binding requested.
- *The endpoint was not checked against its binding.* It could advertise one
  identity or scope set while kow authenticated as another, and notes activation
  could replace the bound spec after validation. Identity and scopes are now
  derived from the binding, a disagreement is a load error, a non-GCP binding is
  refused, and the resolution re-runs after notes activation and after every
  background refresh.

**The one finding that changed this document instead of the code.** The review
argued that "placeholder-only" does not make the listener acceptable, because the
placeholder is an on-box *capability*: any local process can fetch it and make
authenticated calls through kow within the binding's scope. That is correct, and
the earlier wording here understated it. The property that holds is narrower than
first written: credential **theft** goes to zero, credential **use** is open to
anything on the host. Operators who need the tighter boundary put kow and the
agent in one network namespace, and the docs now say so instead of calling
loopback an authentication boundary.

**macOS, and what building its e2e leg found (2026-09-11).** Two things, both
recorded rather than papered over.

*The Keychain backend cannot hold a service-account key.* It refuses any value
containing a newline, because the `security -i` line protocol truncates there and
would store a prefix of the key. That refusal predates this work and is correct;
what is new is that the key-bearing modes collide with it. The macOS leg now pins
the refusal as a regression test instead of assuming it.

**Superseded by ADR-0051 (2026-09-12), and the reason matters.** The conclusion
drawn above — "so on macOS use `source: adc`, which needs no key" — was wrong, and
wrong in the dangerous direction. On a host that is not on Google infrastructure,
`google.auth.default()` resolves ADC to
`~/.config/gcloud/application_default_credentials.json`: a plaintext file holding
a long-lived **user** refresh token, readable by any process running as that user,
carrying the operator's own identity rather than the seat's narrow mint rights.
The Keychain's inability to hold a seat key was therefore steering operators onto
a *larger* credential in a *worse* place, which inverts the point of this ADR's
decision point 4. ADR-0051 removes the constraint instead (`use_helper: require`
routes the backend through the signed helper, which passes bytes on stdin), so the
seat key is storable on macOS and `source: adc` goes back to meaning what it was
supposed to mean: keyless **on GCE, GKE or Cloud Run**, where ADC is the metadata
server and nothing is on disk.

*The suite's substitution assertions were not reaching the proxy.* curl has
treated localhost as an implicit no-proxy host since 7.86, so every
`curl -x <proxy> http://127.0.0.1:<upstream>` in the macOS e2e file went direct
and observed the placeholder unchanged — which the assertion reads as a
substitution failure, from a request that never touched kow. macOS ships curl
8.x, so this affected the existing legs too. All of them now pass `--noproxy ""`.

**Not yet verified, and needed before this is called done.** No real Google SDK
has been pointed at the endpoint (the build sandbox has no package egress), so
the probe-path set is validated against documentation and prior art rather than
against `google-auth`, `gcloud`, and a Go client. No live call has been made
against real GCP IAM, so the impersonation request and response shapes are
asserted against the documented contract only. gRPC-transport client libraries
are unmeasured. Until those three land, the operator-facing claim is "works with
ADC-based clients" with the measurement pending, not "works with almost any app".

## Consequences

**Good.** The credential most likely to be sitting on an agent's disk as a
long-lived JSON key becomes brokerable, and on the default path no such key is
created at all. Coverage stops being "clients that can hold a placeholder" and
becomes "clients that speak ADC", which is nearly all of them. The agent's view
of the world is a machine that appears to have an identity, which is exactly the
fiction a credential proxy should be maintaining. The invariants survive without
reinterpretation, unlike the transport work in ADR-0049. And the credential
endpoint plane is provider-shaped, so the same construction extends to the other
clouds with their existing injectors doing the substitution.

**Bad.** A tenth injector type in a taxonomy declared complete, plus a second
listening surface whose correctness is defined by undocumented SDK behaviour
rather than by a specification. kow acquires a dependency on a cloud platform's
IAM. The daemon's identity becomes an escalation target. One long-lived seat
credential remains on any host not itself on Google infrastructure, and calling
that "keyless" would be a lie the docs must not tell. Client-side token caching
puts a revocation lag between the operator's action and the agent's failure.

**Out of scope.** Resource-level authorization inside Google APIs, credential
access boundaries in v1, ID tokens for identity-aware endpoints, federation as an
injector mode (it is how the *daemon* authenticates and belongs to ADR-0018), the
non-token metadata surface beyond what ADC requires, and the second provider's
driver.
