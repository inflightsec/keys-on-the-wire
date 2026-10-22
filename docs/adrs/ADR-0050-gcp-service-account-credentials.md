---
status: proposed
date: 2026-09-11
relates_to: ADR-0018 (GSM backend — the daemon's GCP identity), ADR-0023 (closed audit event set), ADR-0028 (jwt_bearer signer), ADR-0029 (stored placeholders), ADR-0030 ("the taxonomy is now complete"), ADR-0031 (echo scrubbing), ADR-0034 (wildcard hosts), ADR-0035 (pinned token egress), ADR-0047 (destination policy), ADR-0049 (a listener is not a request), ADR-0051 (removes the macOS key-storage constraint)
references:
  - RFC 7523 §2.1 — JWT authorization-grant profile
  - Google — "OAuth 2.0 for Server to Server Applications"; IAM Credentials `generateAccessToken`; Application Default Credentials and the metadata server
  - Prior art — `salrashid123/gce_metadata_server`
---

# ADR-0050: Google service-account credentials as a brokered injector

> **Revised 2026-09-11** after the operator stated the requirements below. The first draft rejected metadata emulation outright; the requirements invert that ranking, and the rejection does not survive the placeholder construction in option D.

## Context

ADR-0018 gave the daemon a GSM backend whose identity is a service account — the *read* leg, how kow gets secrets out of the vault. The ask here is the other direction: an agent calls a Google API and the authorizing credential is a service account. Today the only option is a JSON key on disk where the agent can read it: long-lived, usable from anywhere, and usually bound to a role broader than the one call needed.

Four facts shape every option.

- **A service-account key is not a bearer credential.** It signs something rather than being sent, so `header` is structurally inapplicable and every path is a computed injector.
- **Google accepts two signed artefacts** — a self-signed JWT presented directly (a documented subset of APIs), or the same JWT exchanged under the RFC 7523 `jwt-bearer` grant for a `ya29.` access token.
- **The key can be removed entirely.** `generateAccessToken` mints a short-lived token *for* a target service account, authenticated by whatever identity the caller holds. No key exists in that flow.
- **Applications do not present credentials the way kow's HTTP path assumes.** A client library, `gcloud` or Terraform resolves through ADC before any request is built, and fails without reaching the proxy if ADC finds nothing. Injector-shaped brokering therefore covers hand-rolled REST calls and little else.

## Requirements (operator)

Ships to be used, not catalogued. The agent never receives service-account authority — not the key, not a live token minted from it. The posture matches Google's own guidance (do not create keys; prefer impersonation and federation; keep lifetimes short). **It must work with almost any application that authenticates as a service account**, not only clients that can hold a placeholder. And the shape should generalise to other clouds.

The fourth is load-bearing, and reopens the option the first draft rejected.

## Options

- **A — Documentation only**, using the existing `jwt_bearer` injector. Zero code, but an exported key and hand-rolled callers only. Retained as the fallback recipe.
- **B — `jwt_bearer_grant` mode.** Sign, exchange, cache, inject; mechanically `github_app` with a different endpoint, reusing the existing signer, transport, cache and audit event. Covers every Google API, but still an exported key and still placeholder-shaped.
- **C — `impersonate` mode.** The daemon calls `generateAccessToken` on the target. No key material anywhere, but it breaks a standing assumption: every injector binds a *secret name* whose value is fetched, and impersonation fetches nothing.
- **D — A credential endpoint that dispenses placeholders.** kow answers the metadata protocol on loopback and returns a **placeholder rather than a real token**. ADC clients find it unmodified and send it through the proxy, where C's minting substitutes the real credential. The first draft refused metadata emulation because a loopback endpoint authenticates nobody — but that objection was aimed at an endpoint dispensing *tokens*. One dispensing *placeholders* hands a thief an opaque string that is useless off-box and policy-bound on-box. Routing needs no root: Google's libraries honour `GCE_METADATA_HOST`, plus `GCE_METADATA_IP` for Python and `GCE_METADATA_ROOT` for `gcloud`.
- **E — Extend `oauth2_client_credentials`.** Cheaper, but client id plus secret cannot express a signing key honestly, or impersonation at all.

## Decision

**Ship C as the minting engine and D as the delivery mechanism. B ships as the keyless-impossible fallback. A becomes a doc page. E is rejected.**

- **One new injector type, three modes.** This reopens the taxonomy ADR-0030 declared closed, admitted rather than avoided, because bending a client-credentials model to carry a signing key is the more expensive lie.
- **`impersonate` is the default** and the docs lead with it: kow should not ship a feature whose happy path contradicts the platform's own guidance. `jwt_bearer_grant` exists for hosts with no Google identity to impersonate from, and says so in its errors.
- **Two layers, named separately, because conflating them is the trap.** *Layer 1* is how the **daemon** authenticates to Google. *Layer 2* is how each **binding** gets authority: a per-binding, scoped, short-lived token. Requirements 2 and 3 are layer-2 properties and are satisfied absolutely; layer 1 is a bootstrap question where zero is not achievable off Google infrastructure.
- **The recommended layer-1 bootstrap is a dedicated impersonation seat** — one service account whose only permission is to be impersonated, with no data access of its own. Off-GCP its credential is the system's single residual key; it lives in the vault, never on an agent host, and a thief gains exactly the mint rights granted. Federation replaces it where an attestable identity exists. Stated in the docs, not hidden.
- **The dispensed placeholder is shaped like the real thing** — a `ya29.` prefix plus CSPRNG material, a stored placeholder per ADR-0029, minted per binding rather than per request, with an advertised expiry driving client refresh at a cadence kow chooses.
- **The endpoint is a listener, so ADR-0049's rule applies**: its own opt-in config section, bound to loopback. Unlike ADR-0049 it adds no second concurrency model for traffic, since it answers small fixed JSON documents and never carries API data.
- **Scope is IAM roles plus OAuth scopes, both enforced by Google.** ADR-0047's refusal of payload inspection holds; credential access boundaries are a later slice. Least privilege on the bound identity is a stated requirement, and `kow doctor` warns on a target holding a project-wide role.
- **Destination scope is explicit hosts.** `*.googleapis.com` would put one token in front of every enabled service. Token endpoints are pinned per ADR-0035.
- **The invariants hold.** G1 by construction — the agent receives a placeholder and sends a placeholder. G5 unchanged, since a denied binding forwards it and Google answers 401. G8's window is the mint cache TTL, and in `impersonate` mode there is no key to rotate. The one new exposure is the loopback endpoint, bounded by the placeholder construction.
- **Generalisation is the point and is deliberately not built.** The endpoint is specified as a *credential endpoint plane* with Google as its first implementation, so the second provider is a driver rather than a redesign — for AWS, `sigv4` re-signing a request the client signed with a placeholder key.

## Rejected alternatives

- **Dispensing real access tokens.** The obvious implementation, and the one that forfeits the entire property: a live token on an unauthenticated loopback port, valid off-box for its full lifetime.
- **Link-local binding or `iptables` redirection.** Both work and both need root and a host-wide change; the environment variable achieves the same routing inside the agent's own environment.
- **Accepting the service-account JSON file whole.** Encourages storing verbatim the artefact Google says not to create, and puts a parser in front of vault content. The operator stores the PEM and states the email.
- **Storing a long-lived access token.** Valid for an hour, not revocable, stale for most of its life.

## What this costs

Modes B and C are each about one injector module, config model, resolver branch and tests — a normal slice against `github_app` precedent.

The endpoint is not. Its correctness is defined by undocumented SDK behaviour rather than a specification: getting any probe path wrong produces a client that hangs or silently falls through to another credential source, which is worse than an error. The environment-variable matrix differs per language, so `kow doctor` must prove the endpoint answers what each SDK family actually asks for.

Mode C makes the daemon's identity load-bearing in a new way: compromising its credential is now an escalation to every impersonation target. And one property genuinely degrades — a client caching its ADC token holds the placeholder for the advertised lifetime, so revocation takes effect when kow refuses to substitute, not when the client stops trying. Still better than a real cached token, which no revocation reaches until expiry.

## Open before implementation

Keyless bindings in the policy model (what audit events carry in `secret_name` when nothing is fetched). Which identity impersonates — reusing the GSM backend's couples vault-read authority to token-minting authority. The endpoint's answer set, enumerated per SDK family with a conformance test each. gRPC-transport coverage, measured, before "almost any app" is a claim kow makes. Placeholder lifetime versus client caching as the revocation lever. Whether domain-wide delegation ships at all. Whether minted tokens join the ADR-0031 scrub set.

## Workload Identity Federation, assessed

Raised as a candidate simplification; it is not one. Federation answers *layer 1*, already ADR-0018's territory, and does not touch layer 2. It also does not remove the residual credential off-cloud: Google requires an OIDC discovery document and JWKS over public HTTPS, so on a host with no attestable identity that means kow standing up an OIDC issuer and holding *its* signing key — the same artefact in a different shape. It wins where an attestable identity already exists, and is the documented upgrade path.

## Verification status

**Verified by mutation, not just by passing.** Seven deliberate breaks — serving a real token, removing the `Metadata-Flavor` gate, making the injector fail-open, stripping key material from the cache key, auditing the minted token, allowing a routable bind address, removing the delegation gate — each killed the suite. All three mint modes are covered end to end, with fail-closed 503s and the placeholder intact on every credential failure path.

**Adversarial review (2026-09-11)** returned ten findings, six real and all fixed. The exchange assertion must not carry `sub` (Google reads it as "act as this user"), and the test had asserted the wrong shape rather than the protocol. The endpoint mislabelled content types and ignored `?recursive=true`, so Python ADC would have silently fallen through to another credential source. Provider error text was audited verbatim, letting a hostile endpoint reflect a real source token into a durable log. The cache identity was incomplete and reachable, since the background notes refresh keeps the cache warm. Success parsing coerced a malformed 200 body into a credential. And the endpoint was not checked against its binding, so it could advertise one identity while kow authenticated as another.

**The finding that changed this document instead of the code.** "Placeholder-only" does not make the listener acceptable, because the placeholder is an on-box *capability*: any local process can fetch it and make authenticated calls within the binding's scope. The property is narrower than first written — credential **theft** goes to zero, credential **use** is open to anything on the host. Operators needing the tighter boundary put kow and the agent in one network namespace, and the docs say so instead of calling loopback an authentication boundary.

**Superseded on macOS by ADR-0051.** The Keychain backend refuses newline-containing values, so it could not hold a seat key, and the conclusion drawn here — "use `source: adc`, which needs no key" — was wrong in the dangerous direction. Off Google infrastructure, ADC resolves to a plaintext file holding a long-lived **user** refresh token, carrying the operator's whole identity rather than the seat's narrow mint rights. ADR-0051 removes the constraint instead, so `source: adc` goes back to meaning keyless **on GCE, GKE and Cloud Run**, where nothing is on disk.

**Not yet verified.** No real Google SDK has been pointed at the endpoint (the build sandbox has no package egress), so the probe-path set is validated against documentation and prior art. No live call against real GCP IAM. gRPC transports are unmeasured. Until those land, the claim is "works with ADC-based clients, measurement pending", not "works with almost any app".

## Consequences

**Good.** The credential most likely to be sitting on an agent's disk as a long-lived JSON key becomes brokerable, and on the default path no such key is created at all. Coverage stops being "clients that can hold a placeholder" and becomes "clients that speak ADC", which is nearly all of them. The invariants survive without reinterpretation, unlike ADR-0049. The endpoint plane is provider-shaped, so the construction extends to other clouds.

**Bad.** A tenth injector type in a taxonomy declared complete, plus a second listening surface defined by undocumented SDK behaviour rather than a specification. kow acquires a dependency on a cloud platform's IAM, and the daemon's identity becomes an escalation target. One long-lived seat credential remains on any host not on Google infrastructure, and calling that "keyless" would be a lie the docs must not tell.

**Out of scope.** Resource-level authorization inside Google APIs, credential access boundaries, ID tokens for identity-aware endpoints, federation as an injector mode, the non-token metadata surface beyond what ADC requires, and the second provider's driver.
