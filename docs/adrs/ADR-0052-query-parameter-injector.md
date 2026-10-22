# ADR-0052 — Query-parameter credential injection (`inject.type: query`)

**Status:** Proposed — open questions unresolved; not ready for sign-off
**Date:** 2026-09-13
**Related:** ADR-0013 (the `decide()` core), ADR-0023 (closed audit event types), ADR-0024 (notes narrow, never declare), ADR-0027/0028 (signers cover the URL), ADR-0047 (method/path scope)

## Context

Placeholder detection is header-only; nothing writes `flow.request.query`. A client carrying its credential as `?key=<placeholder>` therefore matches no binding and forwards unmodified — the right G5 shape reached by accident rather than design.

Prompted by iron-proxy's `secrets.replace.match_query`, the one substitution capability it has and we do not. This is **not** a "kow cannot broker Gemini" problem: `HeaderInjector.header` is an unrestricted `str`, so `x-goog-api-key` is an ordinary header binding. The real population is clients that emit only the query form.

**The argument against.** A query injector writes a real credential into a URL, which is logged where headers are not: vendor access logs, intermediaries, `Referer`, shell history. kow's audit strips the query, but kow does not control the other end. The counterweight is that an affected client otherwise sends the same credential in the same URL with no proxy at all. Conclusion: opt-in per binding, never defaulted, trade named in the docs.

## Decision (proposed)

Add `query` to the closed injector taxonomy as a **leaf**, standalone or as a `multi` child.

```yaml
GEMINI_QUERY_KEY:
  placeholder: "gemini-query-PLACEHOLDER-01HXY1234567890ABCD"
  hosts: ["generativelanguage.googleapis.com"]
  methods: ["GET", "POST"]
  inject: { type: query, param: "key", format: "{GEMINI_QUERY_KEY}" }
```

- **Schema.** `QueryInjector` mirrors `HeaderInjector`: `param`, plus exactly one of `format` or `template`.
- **Detection** matches header and query **as one set**, so a header/query pair of different placeholders is `ambiguous_placeholder_match` and a 400, exactly as two headers are today.
- **Substitution** rewrites the named parameter in the `requestheaders` hook before `inject_decision`, preserving G6 ordering.
- **Signer conflict rejected at config load**: `sigv4` and `hmac` sign the query string, so rewriting after signing breaks the signature and before it changes what was signed.
- **No audit-schema change**, pending confirmation against the field allowlist.

## Rejected alternatives

- **Do nothing, document the header form.** Correct for most vendors. If the open questions find no destination lacking a header path, this is the right answer and the ADR should be closed.
- **Match the placeholder anywhere in the request.** Would match paths and bodies no binding declared, destroying the property that a binding tells you where the secret lands.
- **Vault-note authoring.** A query binding declares where a credential goes, so ADR-0024 keeps it in `bindings.yaml`.

## Consequences

Closes the iron-proxy gap with the same scope and audit trail as headers, and composes with `multi` for free. Costs: wider exposure into logging kow does not control; reopens a taxonomy `CONTRIBUTING.md:200` calls complete, so accepting means amending that line in the same PR; touches `addon.py` and `decide()`, which require human sign-off.

Out of scope: path-segment credentials, response-side `Referer` scrubbing, iron-proxy's management API and SSRF defaults.

## Open questions (close before `accepted`)

1. Name a real destination with no header alternative, or reject. Gemini does not qualify.
2. Does any bound vendor echo the full URL in an error body? That returns the credential to the agent and defeats G1.
3. Should the skill refuse to propose anything but `GET` without an override?
4. Does detection compare decoded values, and does percent-encoding open a normalisation mismatch?
5. Audit field allowlist: covered, or an ADR-0023 bump?
