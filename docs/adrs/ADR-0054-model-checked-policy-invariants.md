# ADR-0054 — Model-checked policy invariants (Quint pilot)

**Status:** Proposed
**Date:** 2026-09-27
**Related:** ADR-0013 (the `decide()` core), ADR-0022 (cross-instance rotation), ADR-0032 (notes refresh), ADR-0047 (binding scope)

## Context

G1–G9 are stated as binary invariants and tested empirically: unit tests, policy fixtures and the ADR-0043 gallery all *sample* the state space. Nothing explores it exhaustively, and the gap is sharpest where state is concurrent — ADR-0022 rotation across instances, and `decide()` racing the ADR-0032 notes refresh, where a request must land on the old bound set or the new one and never a hybrid.

AI assistance has collapsed the cost of TLA+-family specification, shifting the work from writing a spec to reviewing one. Two warnings are load-bearing: a generated spec is a **bug-finding tool, not a proof**, and **spec/code drift** makes a stale spec worse than none, because it radiates false assurance.

## Decision

**Pilot Quint, two models, with a pre-registered adoption gate.** Quint over raw TLA+ because the syntax is close enough to a typed language that agent generation and human review are both realistic; the checker underneath is Apalache.

- **`rotation.qnt`** — the ADR-0022 protocol. No injection with a retired token, no rotation deadlock, no two instances believing they performed the same rotation.
- **`decide.qnt`** — the decision pipeline interleaved with notes refresh. **Fail-closed**: anything that cannot establish binding ∧ scope ∧ fresh secret forwards the placeholder verbatim. **Generation coherence**: one request never mixes bound-set generations.

**Drift control.** The ADR-0013 fixtures are the shared oracle: a conformance script replays each as a trace against `decide.qnt`, and CI fails on a fixture the model rejects or a transition no fixture exercises. Agent-generated is fine; unreviewed is not.

**Adoption gate, fixed before results.** ADOPT only if the pilot finds a confirmed bug or forces a documented sharpening of a G-invariant, *and* the harness runs under 5 minutes. Otherwise PARK. No middle verdict.

## Consequences

The two most interleaving-sensitive components get exhaustive exploration instead of sampling, and G4/G5 become checked properties rather than prose with examples. Against that: a new toolchain (quint, Apalache, JVM) in dev dependencies, two DSL files taxing exactly the code that changes for security reasons, and the residual risk that a wrong abstraction of the backend's consistency model validates a wrong implementation.

Out of scope: TLS termination, the ADR-0053 ssh oracle, injectors, anything payload-semantic, end-to-end proof of the Python, and any claim that a green run is a security proof. G1/G2 evidence remains `gcore` and `tcpdump`.

## Outcome (2026-09-27 to 09-28)

Shipped `specs/decide.qnt`, `specs/rotation.qnt`, `tests/test_spec_conformance.py`, a `quint-specs` pre-commit hook and `.github/workflows/specs.yml`. Battery runs in ~25s, well inside the gate.

**First finding:** the notes refresh publishes `_header_index` and `_header_index_config` as two separate writes from a worker thread while handlers read them unlocked, so `decide()` can run with one generation's config and another's index. Reproduced as a pinned witness and later confirmed by symbolic search; `snapshotFixed` proves an atomic snapshot swap closes it. `test_addon_publish_pattern_tripwire` tethers the witness to the real two-write shape in `addon.py`.

**Two adversarial review rounds** (Oracle, cross-vendor) found fifteen concerns and hardened the pilot substantially:

- **Vacuous invariants.** `servedStale` could never be true, and CAS conflict was unreachable because only the revoke-on-rotate provider class was modelled. Every safety invariant now has a demonstrated failure mode via a paired buggy instance that CI asserts MUST violate it.
- **Design finding — ADR-0022 §3.3 needs revision.** The follower path guarded on provider state no instance can observe, and "serves it without its own exchange" is under-specified: access tokens never live in the vault, so a follower has nothing to serve without exchanging.
- **Any failure counted as success.** `must_violate` accepted every nonzero exit, so a crash or typo read as a counterexample. It now demands quint's own violation verdict.
- **Bounded depth must exceed the witness.** Strict rotation verified clean at depth 10 and violating at 15; the contested-CAS trace is 13 steps. CI pins 15.
- **Supply chain.** All quint invocations, including the `--version` probe, now run with lifecycle scripts disabled.
- **Overstated assurance.** `quint run` is randomized bounded exploration, not proof. `quint verify` (Apalache) now runs in CI alongside it.

## References

- Quint: https://quint-lang.org/ — checker: Apalache
- HN 49863600 (AI-assisted TLA+ adoption; vibe-spec warnings)
- Stateright considered and rejected: wrong language, and the fixture-conformance loop covers the gap it targets.
