# ADR-0052 — Query-parameter credential injection (`inject.type: query`)

**Status:** Proposed — open questions below are unresolved; not ready for sign-off
**Date:** 2026-09-13
**Supersedes:** none
**Related:** ADR-0013 (declarative policy fixtures, the `decide()` core this extends), ADR-0023 (closed set of audit event types), ADR-0024 (vault-side notes can narrow a binding, never declare one), ADR-0027/0028 (the request-signing injectors whose signatures cover the URL), ADR-0047 (per-binding method/path scope)

## Context

kow detects a credential by finding the binding's placeholder in the request. That detection is **header-only**, and always has been. `find_header_placeholder_matches` (`src/kow/policy.py:161`) walks a header index and returns matches from configured target headers; `decide()` step 3 (`src/kow/policy.py:249`) is the only placeholder-match step in the verdict. A repo-wide search for writes to `flow.request.path`, `flow.request.url` or `flow.request.query` returns nothing. The query string is parsed in exactly two places, both read-only: audit path-prefix truncation (`src/kow/handlers.py:386`, `:662`) and the git-smart-http `?service=` canonicalisation (`src/kow/addon.py:591`).

The consequence is precise. A client that carries its credential in the URL, `GET /v1/resource?key=<placeholder>`, matches no binding. `decide()` returns `_FORWARD`, the request goes upstream unmodified, and the placeholder reaches the vendor, which rejects it with its ordinary auth error. That is indistinguishable from "this destination is not bound", which is the correct G5 shape but arrived at by accident rather than by design.

**What prompted this:** iron-proxy (Apache-2.0, Go) ships `secrets.replace.match_query` beside its header matcher, and now sits in front of Nous Research's Hermes Agent sandboxes. It is the one substitution capability in that project with no counterpart here. See [`docs/comparison.md`](../comparison.md).

**What this is not about, stated because the investigation began there and was wrong.** This is not "kow cannot broker Gemini". `HeaderInjector.header` (`src/kow/config_models.py:209`) is an unrestricted `str`, so `x-goog-api-key` is an ordinary `type: header` binding exactly like Anthropic's `x-api-key`, and Google's API accepts that header. Every major inference vendor offers a header form. The population this ADR actually serves is narrower: clients and SDK code paths that emit the query form only, and the small set of APIs that offer no header alternative at all.

## The argument against, up front

A `type: query` injector writes a **real credential into a URL**. URLs are logged by design at every hop that a header is not: the vendor's access logs, any intermediary, `Referer` propagation on anything the response renders, and shell history when an operator reproduces a call. kow's own audit path is clean here (it truncates to a query-stripped 64-char prefix), but kow does not control the other end. kow's whole premise is that a credential's blast radius stays small; this feature deliberately widens it for the destinations that use it.

That argument does not settle the question, because the alternative for an affected client is a *real* credential in the URL with no proxy at all. But it means the feature should be opt-in per binding, never a default, and the docs must name the trade rather than bury it.

## Decision (proposed)

Add `query` to the closed injector taxonomy as a **leaf** injector, usable standalone or as a `multi` child.

```yaml
GEMINI_QUERY_KEY:
  placeholder: "gemini-query-PLACEHOLDER-01HXY1234567890ABCD"
  hosts: ["generativelanguage.googleapis.com"]
  methods: ["GET", "POST"]
  inject:
    type: query
    param: "key"
    format: "{GEMINI_QUERY_KEY}"
```

1. **Schema.** `QueryInjector` in `config_models.py`, mirroring `HeaderInjector`: `param: str`, and exactly one of `format` (literal substitution) or `template` (requires `compose:` on the parent). One line added to `_INJECTOR_TYPES`, the matching class, and the `InjectorSpec` / `LeafInjectorSpec` unions, per the convention comment above that dict.

2. **Detection.** A sibling `find_query_placeholder_matches` reading the parsed query, and a `decide()` step 3 that matches **across both surfaces as one set**. Ambiguity is evaluated on the union, not per surface: two distinct placeholders, one in a header and one in the query, is `ambiguous_placeholder_match` and a 400, exactly as two in headers is today. Placeholder uniqueness is already enforced at config load, so no new invariant is introduced, only a wider search.

3. **Substitution.** Rewrite the single named parameter in `flow.request.query` in the `requestheaders` hook, in memory, then emit the `inject_decision` audit event before returning. G6 ordering is preserved unchanged because a query rewrite is the same kind of pre-return in-memory mutation the header path already performs.

4. **G5 by omission, unchanged.** A scope or destination failure means kow simply does not rewrite, so the placeholder forwards verbatim and the vendor returns its normal auth failure. No new denial shape.

5. **Signer conflict rejected at config load.** `sigv4` and `hmac` sign a canonical request that includes the query string. A query rewrite after signing invalidates the signature; before signing, it silently changes what is signed. Config load rejects a `query` binding and a request-signing binding on the same host, mirroring the existing body-signer/body-injector conflict rejection (`src/kow/config.py:688`).

6. **No audit-schema change.** The existing `inject_decision` event covers this; `binding_source` and the existing fields carry it. Under ADR-0023 that keeps the contract version where it is. This must be confirmed against the declared field allowlist before implementation.

## Rejected alternatives

- **Do nothing, document the header form.** Cheapest and genuinely correct for every vendor that offers a header, which is most of them. Rejected only if the open questions below turn up real destinations with no header path; if they do not, this is the right answer and this ADR should be closed rather than accepted.
- **A generic "replace the placeholder anywhere in the request" matcher.** Uniform and tempting, but it would match path segments and body fragments that no binding declared, turning every binding into an implicit body injector and destroying the property that an operator can read a binding and know where the secret lands.
- **Vault-note authoring for query bindings.** ADR-0024 holds: a note can narrow a binding, never declare one. A query binding declares where a credential is written, so it lives in `bindings.yaml`.

## Consequences

**Good**
- Closes the one substitution gap against iron-proxy, with the same per-binding host/method/path scope, just-in-time vault sourcing and audit trail the header path already has.
- Leaf placement means `multi` composes it with a header or body leaf at no extra cost.

**Bad**
- Widens a brokered credential's exposure into URL-shaped logging that kow does not control. Named in the docs, opt-in per binding, never defaulted.
- Reopens a taxonomy that `CONTRIBUTING.md:200` declares complete. Accepting this ADR means amending that sentence in the same PR, not quietly contradicting it.
- Touches `src/kow/addon.py` and `policy.decide()`, which `AGENTS.md` fences as security-affecting and requiring explicit human sign-off.

**Out of scope**
- Path-segment credentials (`/v1/{token}/resource`). Different matcher, different scope-interaction with `paths:`, and no demand evidenced yet.
- Fragment or `Referer` scrubbing on the response side.
- iron-proxy's management API and destination-side SSRF CIDR defaults, both noted during the same review and tracked separately.

## Open questions (to close before this moves to `accepted`)

1. **Is there a real destination with no header alternative?** Name at least one, or reject in favour of "do nothing". Gemini does not qualify.
2. **Does the vendor echo the query string anywhere the agent can read it back?** If a bound destination reflects the full URL in an error body, the injected credential returns into the agent's context and G1 is defeated for that binding. Does this need a response-side check, reusing the ADR-0031 echo-scrubbing machinery?
3. **`methods:` default.** ADR-0047 has the bundled skill always write `methods:` explicitly. A credential in a URL is most often a `GET`; should the skill's query-binding workflow refuse to propose anything but `GET` without an explicit override?
4. **Placeholder shape in a URL.** The marker-carrying placeholder must survive percent-encoding by arbitrary clients. Does detection compare decoded values, and does that open a normalisation-mismatch gap between what `decide()` matched and what is rewritten?
5. **Audit field allowlist.** Confirm `inject_decision` can carry a query binding with no new field, or accept an ADR-0023 contract bump.
