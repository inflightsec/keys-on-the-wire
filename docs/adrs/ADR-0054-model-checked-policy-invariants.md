# ADR-0054 — Model-checked policy invariants (Quint pilot)

**Status:** Proposed
**Date:** 2026-09-27
**Supersedes:** none
**Related:** ADR-0013 (declarative policy fixtures, the `decide()` core), ADR-0022 (cross-instance refresh-token rotation), ADR-0032 (periodic notes refresh), ADR-0047 (explicit binding scope)

## Context

kow's guarantees (G1–G9 in `docs/architecture.md`) are stated as binary invariants and tested empirically: unit tests, the ADR-0013 declarative policy fixtures, and the ADR-0043 adversarial gallery all *sample* the state space. What nothing currently does is explore it exhaustively. The gap is sharpest where state is concurrent:

- **ADR-0022 refresh-token rotation across instances** is a small distributed protocol. Two proxy instances, one rotating token family, interleaved refresh attempts, a backend read-modify-write — the classic shape in which "each step looked correct in review" hides an interleaving that ends with both instances holding a dead token (availability) or a stale token being injected after rotation (a G4-adjacent correctness hole).
- **The `decide()` pipeline** (`src/kow/policy.py`) races the ADR-0032 background notes refresh: a request evaluated mid-refresh must land on either the old bound set or the new one, never a hybrid where the destination check used one generation and the secret fetch used another.

The prompt for acting now is external: AI agents have collapsed the historic cost of TLA+-family specification (HN 49863600, 2026-09; harvest note in the operator's knowledge base). The work shifts from writing the spec to *reviewing* it, and practitioner consensus in that thread — whole-program proof is not worth it, contained security-critical domains are exactly where model checking pays — describes this codebase precisely. One thread datum matches our shape: a model-checked spec caught a clustering bug that unit tests missed.

Two warnings from the same source are load-bearing constraints, not footnotes. A generated spec is a **bug-finding tool, not a proof of correctness**: the spec can be wrong in the same direction as the code. And **spec↔code drift** is the classic failure of formal methods in industry — a spec checked once and never reconciled is worse than none, because it radiates false assurance.

## Decision

**Pilot Quint, scoped to two models, with a pre-registered adoption gate.**

Language: **Quint** (Informal Systems) rather than raw TLA+. Same semantics, checker is Apalache, but the syntax is close enough to a typed programming language that both agent generation and operator review are realistic. The `quint` CLI is npm-distributed and runs under bun, consistent with house tooling; no Python surface is added.

Scope of the pilot — exactly two models under `specs/`:

1. **`rotation.qnt`** — the ADR-0022 rotation protocol: N proxy instances, one token family, backend as a shared store with the real consistency model. Invariants: (a) no request is ever injected with a token the backend has retired beyond the grace window; (b) rotation cannot deadlock the family (liveness under weak fairness); (c) two instances never both believe they performed the same rotation.
2. **`decide.qnt`** — the per-request decision pipeline interleaved with notes refresh. Invariants: (a) **fail-closed** — every path that cannot positively establish (binding match ∧ scope match ∧ fresh secret) ends in placeholder-forwarded-verbatim, the G4/G5 conjunction; (b) **generation coherence** — one request never mixes bound-set generations.

Drift control, so the spec stays tethered to the code: the ADR-0013 declarative policy fixtures are the shared oracle. A conformance script replays each fixture as a trace against `decide.qnt` (`quint run` trace mode); a fixture the model rejects, or a model transition no fixture exercises, fails CI. The spec is reviewed like code — agent-generated is fine, unreviewed is not.

**Pre-registered adoption gate** (fixed now, before results): the pilot votes ADOPT only if it (a) finds at least one confirmed real bug or forces a documented sharpening of a G-invariant's wording, and (b) the conformance harness runs under 5 minutes in CI. Otherwise PARK: keep the specs as documentation, drop the CI gate, record the outcome here. No middle verdict.

## Consequences

**Good.** The two most interleaving-sensitive components get exhaustive state exploration instead of sampled tests. G4/G5 stop being prose backed by examples and become checked properties. The fixture-conformance loop means the spec cannot silently drift. Cost of authoring is low in 2026; cost of *review* is bounded by the two-model scope.

**Bad.** A new toolchain (quint/Apalache, JVM under Apalache) enters dev dependencies. Two DSL files must be maintained by whoever touches rotation or `decide()` — the models become a tax on exactly the code that changes for security reasons. False confidence remains possible: the models abstract the backend's real consistency behaviour, and a wrong abstraction validates a wrong implementation.

**Out of scope.** Modelling TLS termination, the ssh-agent oracle (ADR-0053), injectors, or anything payload-semantic (ADR-0047 territory — authorisation lives in the payload and no state model sees it). End-to-end proof of the Python implementation. Any claim that a green model run constitutes a security proof — G1/G2 evidence remains `gcore` and `tcpdump`, not a checker.

## References

- HN thread: https://news.ycombinator.com/item?id=49863600 (AI-assisted TLA+ adoption; seL4-scale discussion; vibe-spec warnings)
- Quint: https://quint-lang.org/ — checker: Apalache
- Prior art in-thread: Stateright (implementation-level checking, Rust) considered and rejected — wrong language, and the fixture-conformance loop covers the spec↔code gap it targets.

## Amendment (2026-09-27) — pilot implemented

Shipped: `specs/decide.qnt` (policy pipeline + snapshot-publish race, plus the ADR-0055 `noteLocality` non-interference invariant), `specs/rotation.qnt` (ADR-0022 lease+CAS), `tests/test_spec_conformance.py` (fixture↔model conformance generator + invariant battery, marker `specs`), pre-commit hook `quint-specs` (typecheck, ~2s), and `.github/workflows/specs.yml` (full battery, `KOW_REQUIRE_QUINT=1`). Battery runs in ~25s — well inside the 5-minute gate.

**First finding (model-confirmed, code-level confirmation pending):** the ADR-0032 notes refresh publishes `_header_index` and `_header_index_config` as two separate field writes (`addon.py:349-350`, `433-435`) from a `asyncio.to_thread` worker, while handlers read them unlocked on the event loop — the model reproduces a torn read where `decide()` runs with one generation's config and another's index (`tornPublishWitnessTest`, pinned deterministically; `snapshotFixed` proves a single atomic snapshot swap closes it). Gate status: counts toward ADOPT only once confirmed against the real interpreter's memory model or conceded as design-level; the witness stays either way.

Also verified by the rotation model: stale-lease double-leader is reachable (the lease is availability, not safety — CAS carries correctness), and crash-between-exchange-and-write-back is the irrecoverable `needs_reauth` terminal §5 documents.

## Amendment (2026-09-27, second) — Oracle adversarial round

Cross-model review (Oracle, OpenAI-family) returned nine concerns; all were triaged and the substantive ones fixed the same day:

- **CAS was never contested (C2, confirmed).** The first rotation model only encoded the revoke-on-rotate provider class, making `casConflict` unreachable and the §4 discard rule dead code. Fixed: `exchangeLateOk` models ADR-0022 race 1(a) (per-request issuers), with `casConflictWitnessTest` pinning the contested write-back.
- **Follower path peeked at provider state (C3, confirmed — design finding).** `followerServe` guarded on `vaultRt == provRt`, which no instance can observe; worse, ADR-0022 §3.3's "serves it without its own exchange" is under-specified — access tokens never live in the vault, so a follower has nothing to serve without exchanging. The model now has the follower rejoin the ordinary acquire→exchange cycle. **ADR-0022 §3.3 needs revision.**
- **Vacuous invariant (C4, confirmed).** `servedStale` could never become true. Fixed with the `rotationStrict`/`rotationBuggy` pair: the buggy instance enables the forbidden serve-on-conflict, and CI asserts it VIOLATES `noStaleServe` — every safety invariant now has a demonstrated failure mode.
- **Witness↔code tether (C5, confirmed).** The snapshot witness checks the model, not `addon.py`. Fixed with `test_addon_publish_pattern_tripwire`, which fails when the two-write publish shape in `addon.py` changes and names the spec cleanup required.
- **Translation fidelity (C6/C7, confirmed).** The conformance generator now matches placeholders only in their configured target header, and hard-refuses fixtures binding `paths:` (the model's exact-segment abstraction cannot express prefix scopes yet).
- **Supply chain (C8, confirmed).** All local quint invocations (pytest + pre-commit) now export `npm_config_ignore_scripts=true`, matching CI's `--ignore-scripts`.
- **Overstated assurance (C9, accepted).** All "every interleaving"/"exhaustive" claims reworded: `quint run` is randomized bounded exploration — evidence, not proof. `quint verify` (Apalache symbolic checking) is the named upgrade path; a local attempt stalled on the Apalache distribution download and was not retried.
- **Dismissed:** C1 (invalid action SHAs) was an artifact of this review's own payload sanitisation — the workflow on disk carries real pinned SHAs.

Battery after fixes: 8 pytest checks green in ~25s, including the two new negative/tripwire tests.

## Amendment (2026-09-28, third) — symbolic verification delivered (C9 closed)

The Apalache distribution download had merely been cut off by an impatient local timeout; retried, it works on the stock JVM. `quint verify` (exhaustive bounded checking) now runs in CI alongside the randomized battery: `decideSpec/allGates` to depth 6, `snapshotFixed/servedCoherent` to depth 10, `rotationStrict/allSafe` to depth 10 — all hold. The two negative checks are asserted as MUST-FAIL: Apalache finds the snapshot torn-read counterexample (6s) and the rotationBuggy forbidden-serve violation (depth 15; note depth 12 was too shallow and reported clean — bounded depths must exceed the witness length, which is why the CI pins 15). The snapshot race is now confirmed by symbolic search, not just the hand-pinned witness.

## Amendment (2026-09-28, fourth) — Oracle round two

Second adversarial pass over the fixed change set (with rebuttal context) returned six concerns; all addressed:

- **Cold-cache probe escaped the scripts lockdown (r2-C1, HIGH, confirmed).** The `--version` probe ran before the no-scripts env applied; a first-ever npx/bunx fetch could execute lifecycle code. The env now covers every invocation including the probe.
- **Any tool failure counted as a counterexample (r2-C2, HIGH, confirmed).** `must_violate` and the falsifiability pytest accepted every nonzero exit. Both now demand quint's own violation verdict in the output; a crash or typo turns the check red instead of green.
- **Strict verification stopped short of the contested CAS (r2-C3, confirmed).** Depth 10 < the 13-step conflict trace. Strict is now verified to depth 15 — through the conflict region (≈4 min, timeout raised to 25).
- **Sticky crash flag vacated consistency forever (r2-C4, confirmed).** Reworked: a currency-restoring CAS write clears `crashedMid`, and the invariant is now the implication "quiescent mismatch ⇒ un-repaired crash damage" — one historical crash no longer excuses later bugs.
- **Crash-brick was not terminal in a mixed-provider world (r2-C5, confirmed).** Provider class is now a model parameter: `rotationStrict`/`rotationBuggy` (per-request, CAS contested) vs `rotationStrictRevoking` (revoke-on-rotate, where the crash-brick witness genuinely has no recovery lane). Class-specific witnesses moved into their matching instances. All three verified: strict d15, revoking d12, buggy violates at d15.
- **Tripwire too loose (r2-C6, partially accepted).** Now pins the exact ordered two-line write sequences (order IS the race), and states plainly it is a heuristic tether, not a semantic proof.
