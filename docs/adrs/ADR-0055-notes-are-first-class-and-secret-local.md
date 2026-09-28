# ADR-0055 — Notes are the first-class config carrier, and their scope is exactly one secret

**Status:** Proposed
**Date:** 2026-09-27
**Supersedes:** none
**Related:** ADR-0011 (BWS notes bindings), ADR-0021 (multi-host notes binding), ADR-0024 (notes host allowlist), ADR-0025 (notes binding marker), ADR-0054 (model-checked policy invariants — `noteLocality`)

## Context

The notes-first doctrine has been implicit since ADR-0011: the notes field riding alongside a secret's value in the vault is where that secret's kow binding lives, so onboarding a credential needs no config-file edit and no redeploy. The Kaggle API key was the clean case in point: the note alone carried everything required to use the secret — host binding, header, format — and the proxy picked it up on the next notes refresh.

What has never been written down is the boundary. As note-carried config grows richer (ADR-0021 multi-host, ADR-0047 method scopes, service templates), the temptation grows to let a note configure things *near* the secret: another secret it "pairs with", a global default, an engine setting. That path ends with the vault's least-privileged writer reconfiguring the proxy — a privilege escalation through metadata.

## Decision

Two requirements, one existing and now canonical, one new and binding:

**R1 — first-class carrier.** A secret's note MAY carry the complete configuration needed to use that secret through kow: bindings (hosts, methods, paths), injector type and parameters, template selection. If a credential cannot be fully onboarded through its note, that is a gap to fix in the notes schema, not a reason to reach for the config file.

**R2 — strict locality.** A note's blast radius is EXACTLY its own secret. Parsing a note MUST NOT create, modify, or influence: another secret's bindings or injectors, `unmatched_destination_policy` or any global engine setting, audit configuration, or coordination settings (ADR-0022). Out-of-scope keys in a note are rejected at parse with a `policy_advisory` audit event naming the key — never silently honoured, never silently dropped.

**Formal statement.** R2 is checked as the `noteLocality` non-interference invariant in `specs/decide.qnt` (ADR-0054): removing a secret from the resolved config may change the verdict only for requests that carry that secret's placeholder or target a host that secret binds (the destination allow-list is legitimately a union of bindings). Any other observable influence is a locality violation. The invariant runs in CI (`.github/workflows/specs.yml`) over randomized request/config space.

## Consequences

**Good.** The vault write permission stays exactly as dangerous as it looks: writing a note can (mis)configure one credential's egress, never the proxy. Notes-first onboarding stays zero-touch. The property is machine-checked, not folklore.

**Bad.** Legitimate cross-secret conveniences (e.g. "this OAuth client secret shares its binding with its refresh token") must be expressed by duplicating config per secret or via config-file constructs, never by one note reaching into another's scope.

**Out of scope.** The notes schema itself (ADR-0011/0021/0025 own it); enforcement code changes — the current parser already builds per-secret specs, and this ADR pins that shape as a contract rather than an accident.
