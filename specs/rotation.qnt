// ADR-0054 — Quint model of the ADR-0022 cross-instance refresh-token
// rotation protocol (lease + CAS write-back). ADR-0022 is `proposed` and
// deliberately unimplemented; this model checks the protocol BEFORE code
// exists — the cheapest time to find an interleaving bug.
//
// Abstractions (kept honest in comments):
//   * Token generations are ints. `provRt` is the refresh token the
//     provider currently honours; an exchange with any other value is
//     `invalid_grant` (the rotate-and-revoke provider class from ADR-0022
//     race 1b; the issue-per-request class 1a is out of scope here).
//   * The vault CAS is a TRUE conditional write. BWS's optimistic re-read
//     is weaker (documented TOCTOU in ADR-0022 §2) — this model therefore
//     checks the protocol's ceiling, not BWS's floor.
//   * Time is a bounded abstract clock; lease expiry is `lockExp < now`.
//
// CI contract (randomized bounded exploration via `quint run` — evidence,
// NOT exhaustive proof; `quint verify` (Apalache) is the upgrade path):
//   quint run --main=rotationStrict --invariant=allSafe specs/rotation.qnt
//     → no violation found across sampled interleavings (including lease
//       expiry + steal → two simultaneous "leaders", and the per-request
//       provider class where CAS conflicts actually occur).
//   quint run --main=rotationBuggy --invariant=noStaleServe ...
//     → MUST find a violation: rotationBuggy allows the §4-forbidden
//       serve-on-conflict, proving the invariant can actually fail.
//   quint test --main=rotationBuggy specs/rotation.qnt
//     → deterministic witnesses (double-leader, CAS conflict, crash-brick,
//       buggy serve).
//
// Model finding (2026-09-27, Oracle-confirmed): ADR-0022 §3.3's follower
// path ("serves it without its own exchange") is under-specified for
// rotating providers — access tokens are never stored in the vault, so a
// follower has nothing to serve without running its own exchange. The
// follower here therefore rejoins the ordinary acquire→exchange cycle
// once the lease frees; §3.3 needs a revision in ADR-0022.

module rotationSpec {
  // true  = the ADR-0022 §4 rule (discard minted token on CAS conflict).
  // false = the forbidden variant that serves it anyway — exists to prove
  //         noStaleServe is falsifiable (see rotationBuggy).
  const STRICT_DISCARD: bool
  // true  = provider issues a token per request (ADR-0022 race 1a): a
  //         stale-but-issued RT still exchanges, so two instances can mint
  //         concurrently and contest the CAS.
  // false = revoke-on-rotate class (race 1b): only the current RT works,
  //         and a crash that loses a minted RT is genuinely terminal.
  const PER_REQUEST_ISSUER: bool

  pure val INSTANCES = Set(1, 2)
  pure val TTL = 4         // lease TTL in ticks (> worst-case exchange, §1)
  pure val MAX_TIME = 16   // clock bound to keep runs finite

  // phases: "idle" | "want" (needs a fresh access token) |
  //         "leader" (lease acquired, pre-exchange) |
  //         "minted" (exchange done, pre-write-back)
  var phase: int -> str
  var heldRt: int -> int     // refresh token read from the vault at acquire
  var obsVer: int -> int     // vault version observed at acquire (CAS basis)
  var mintedRt: int -> int   // rotated RT received from the exchange

  var now: int
  var provRt: int            // provider's currently-honoured refresh token
  var vaultRt: int
  var vaultVer: int
  var lockHolder: int        // -1 = free
  var lockExp: int

  var crashedMid: bool       // a leader died between exchange and write-back
  var servedStale: bool      // a §4-forbidden serve happened (must stay false)

  def lockLive = lockHolder != -1 and lockExp >= now

  action init = all {
    phase' = INSTANCES.mapBy(i => "idle"),
    heldRt' = INSTANCES.mapBy(i => -1),
    obsVer' = INSTANCES.mapBy(i => -1),
    mintedRt' = INSTANCES.mapBy(i => -1),
    now' = 0, provRt' = 0, vaultRt' = 0, vaultVer' = 0,
    lockHolder' = -1, lockExp' = -1,
    crashedMid' = false, servedStale' = false,
  }

  // ── helpers to keep frames readable ──────────────────────────────────
  action unchangedVault = all { vaultRt' = vaultRt, vaultVer' = vaultVer }
  action unchangedLock = all { lockHolder' = lockHolder, lockExp' = lockExp }
  action unchangedFlags = all { crashedMid' = crashedMid, servedStale' = servedStale }

  // ── clock ────────────────────────────────────────────────────────────
  action tick = all {
    now < MAX_TIME,
    now' = now + 1,
    phase' = phase, heldRt' = heldRt, obsVer' = obsVer, mintedRt' = mintedRt,
    provRt' = provRt, unchangedVault, unchangedLock, unchangedFlags,
  }

  // ── an instance notices its cached access token expired ─────────────
  action want(i: int): bool = all {
    phase.get(i) == "idle",
    phase' = phase.set(i, "want"),
    heldRt' = heldRt, obsVer' = obsVer, mintedRt' = mintedRt,
    now' = now, provRt' = provRt, unchangedVault, unchangedLock, unchangedFlags,
  }

  // ── §3.1 acquire (or §3.4 steal an expired lease) ────────────────────
  action acquire(i: int): bool = all {
    phase.get(i) == "want",
    not(lockLive),
    lockHolder' = i, lockExp' = now + TTL,
    phase' = phase.set(i, "leader"),
    heldRt' = heldRt.set(i, vaultRt),
    obsVer' = obsVer.set(i, vaultVer),
    mintedRt' = mintedRt, now' = now, provRt' = provRt,
    unchangedVault, unchangedFlags,
  }

  // ── §1 heartbeat: leader renews while in flight (OPTIONAL — the model
  // may skip it, which is exactly the slow-exchange/GC-pause reality) ───
  action renew(i: int): bool = all {
    lockHolder == i, lockLive,
    phase.get(i) == "leader" or phase.get(i) == "minted",
    lockExp' = now + TTL, lockHolder' = lockHolder,
    phase' = phase, heldRt' = heldRt, obsVer' = obsVer, mintedRt' = mintedRt,
    now' = now, provRt' = provRt, unchangedVault, unchangedFlags,
  }

  // ── token exchange: honoured RT rotates the provider ────────────────
  action exchangeOk(i: int): bool = all {
    phase.get(i) == "leader",
    heldRt.get(i) == provRt,
    provRt' = provRt + 1,                 // provider rotates + revokes old
    mintedRt' = mintedRt.set(i, provRt + 1),
    phase' = phase.set(i, "minted"),
    heldRt' = heldRt, obsVer' = obsVer, now' = now,
    unchangedVault, unchangedLock, unchangedFlags,
  }

  // ── ADR-0022 race 1(a): per-request provider class — an in-flight
  // exchange with a PREVIOUSLY-issued RT also succeeds and yields yet
  // another RT. This is the lane where two instances mint concurrently
  // and the CAS write-back is actually contested. ──────────────────────
  action exchangeLateOk(i: int): bool = all {
    PER_REQUEST_ISSUER,                   // this lane exists only for 1a
    phase.get(i) == "leader",
    heldRt.get(i) < provRt,               // stale but honoured (1a class)
    provRt' = provRt + 1,
    mintedRt' = mintedRt.set(i, provRt + 1),
    phase' = phase.set(i, "minted"),
    heldRt' = heldRt, obsVer' = obsVer, now' = now,
    unchangedVault, unchangedLock, unchangedFlags,
  }

  // ── invalid_grant (revoke-on-rotate class, race 1(b)): §4 — discard,
  // re-resolve. Both provider classes stay in `step` so exploration
  // covers both worlds. ────────────────────────────────────────────────
  action exchangeStale(i: int): bool = all {
    phase.get(i) == "leader",
    heldRt.get(i) != provRt,
    phase' = phase.set(i, "want"),        // re-read via a fresh acquire
    lockHolder' = if (lockHolder == i) -1 else lockHolder,
    lockExp' = lockExp,
    heldRt' = heldRt, obsVer' = obsVer, mintedRt' = mintedRt,
    now' = now, provRt' = provRt, unchangedVault, unchangedFlags,
  }

  // ── §4 CAS write-back succeeds: serve, release, done ────────────────
  action casOk(i: int): bool = all {
    phase.get(i) == "minted",
    vaultVer == obsVer.get(i),
    vaultRt' = mintedRt.get(i), vaultVer' = vaultVer + 1,
    lockHolder' = if (lockHolder == i) -1 else lockHolder,
    lockExp' = lockExp,
    phase' = phase.set(i, "idle"),        // served the fresh access token
    heldRt' = heldRt, obsVer' = obsVer, mintedRt' = mintedRt,
    now' = now, provRt' = provRt,
    // A write that restores vault↔provider currency repairs the crash
    // damage — the crashedMid excuse must lapse with it (Oracle r2 C4),
    // so any LATER unexplained mismatch fails the invariant again.
    crashedMid' = (crashedMid and mintedRt.get(i) != provRt),
    servedStale' = servedStale,
  }

  // ── §4 CAS conflict: the minted token MUST be discarded, never served.
  // (Serving it anyway would set servedStale — the forbidden branch is
  // simply absent from the protocol; the invariant documents the rule.) ─
  action casConflict(i: int): bool = all {
    phase.get(i) == "minted",
    vaultVer != obsVer.get(i),
    phase' = phase.set(i, "want"),
    mintedRt' = mintedRt.set(i, -1),      // discard before header mutation
    lockHolder' = if (lockHolder == i) -1 else lockHolder,
    lockExp' = lockExp,
    heldRt' = heldRt, obsVer' = obsVer,
    now' = now, provRt' = provRt, unchangedVault, unchangedFlags,
  }

  // ── The §4-FORBIDDEN branch: serve the minted token despite the CAS
  // conflict. Disabled under STRICT_DISCARD (the specified protocol);
  // rotationBuggy enables it so noStaleServe is demonstrably falsifiable
  // rather than true by construction. ──────────────────────────────────
  action buggyServeOnConflict(i: int): bool = all {
    not(STRICT_DISCARD),
    phase.get(i) == "minted",
    vaultVer != obsVer.get(i),
    servedStale' = true,
    phase' = phase.set(i, "idle"),
    mintedRt' = mintedRt.set(i, -1),
    lockHolder' = if (lockHolder == i) -1 else lockHolder,
    lockExp' = lockExp,
    heldRt' = heldRt, obsVer' = obsVer,
    now' = now, provRt' = provRt, unchangedVault,
    crashedMid' = crashedMid,
  }

  // ── leader crash. Between exchange and write-back this is the
  // documented terminal state (§5 needs_reauth): provider rotated, vault
  // stale, nobody can recover without operator re-auth. ────────────────
  action crash(i: int): bool = all {
    phase.get(i) == "leader" or phase.get(i) == "minted",
    crashedMid' = (crashedMid or phase.get(i) == "minted"),
    phase' = phase.set(i, "idle"),
    mintedRt' = mintedRt.set(i, -1),
    // lock is NOT released — expiry (§3.4) is the backstop
    heldRt' = heldRt, obsVer' = obsVer,
    now' = now, provRt' = provRt, unchangedVault, unchangedLock,
    servedStale' = servedStale,
  }

  action step = {
    nondet i = oneOf(INSTANCES)
    any {
      tick, want(i), acquire(i), renew(i), exchangeOk(i), exchangeLateOk(i),
      exchangeStale(i), casOk(i), casConflict(i), buggyServeOnConflict(i),
      crash(i),
    }
  }

  // ── Invariants ───────────────────────────────────────────────────────

  // Quiescent consistency, stated so a crash can never vacate the check
  // wholesale (Oracle r2 C4): a vault↔provider mismatch at quiescence is
  // permitted ONLY while un-repaired mid-rotation crash damage exists —
  // the documented needs_reauth terminal (§5). Any mismatch without that
  // excuse is a protocol bug.
  val quiescentConsistent =
    (INSTANCES.forall(i => phase.get(i) == "idle") and not(lockLive)
     and vaultRt != provRt)
      implies crashedMid

  // §4: a CAS-conflicted minted token is never served.
  val noStaleServe = not(servedStale)

  // The vault version only counts real writes: it can never exceed the
  // number of provider rotations (each successful CAS follows an exchange).
  val versionBounded = vaultVer <= provRt

  val allSafe = quiescentConsistent and noStaleServe and versionBounded

  // ── Witnesses (quint test) ───────────────────────────────────────────

  // Follower path (post-C3 correction): once the leader's write frees the
  // lease, the waiting instance runs its OWN acquire→exchange with the
  // fresh vault RT — no provider state is peeked at, and no access token
  // is conjured out of the vault.
  run followerRejoinsTest = init
    .then(want(1)).then(want(2))
    .then(acquire(1))
    .then(exchangeOk(1))
    .then(casOk(1))                       // vault now holds the rotated RT
    .then(acquire(2))                     // follower leads with fresh state
    .then(exchangeOk(2))                  // exchange succeeds: RT is current
    .then(casOk(2))
    .expect(phase.get(2) == "idle" and vaultRt == provRt)

  // Stale lease ⇒ TWO simultaneous lease-holders is REACHABLE (leader 1's
  // lease expires mid-flight; 2 steals). The lease is availability, not
  // safety: CAS then forces 1's late write-back into casConflict, and the
  // §4 discard keeps every invariant intact.
  run staleLeaseDoubleLeaderTest = init
    .then(want(1)).then(want(2))
    .then(acquire(1))
    .then(exchangeOk(1))                  // 1 minted, slow write-back
    .then(tick).then(tick).then(tick).then(tick).then(tick)  // lease lapses
    .then(acquire(2))                     // 2 steals (§3.4)
    .expect(phase.get(1) == "minted" and phase.get(2) == "leader")

}

// The checkable instances. `rotationStrict` is the protocol as specified
// (§4 discard rule in force); `rotationBuggy` additionally allows the
// forbidden serve-on-conflict so `noStaleServe` is proven falsifiable.
module rotationStrict {
  import rotationSpec(STRICT_DISCARD = true, PER_REQUEST_ISSUER = true).*

  // The CAS write-back actually contested (per-request provider class):
  // both instances mint; the loser's §4 discard fires. This is the
  // transition C2 proved unreachable in the first model draft.
  run casConflictWitnessTest = init
    .then(want(1)).then(want(2))
    .then(acquire(1))
    .then(exchangeOk(1))                  // 1 minted RT1
    .then(tick).then(tick).then(tick).then(tick).then(tick)  // lease lapses
    .then(acquire(2))                     // 2 steals, reads vault RT0/ver0
    .then(exchangeLateOk(2))              // 1a class: stale RT0 also honoured
    .then(casOk(1))                       // 1 writes first (ver 0 → 1)
    .then(casConflict(2))                 // 2's CAS loses; §4 discard
    .expect(phase.get(2) == "want" and mintedRt.get(2) == -1
            and not(servedStale))

}

// Revoke-on-rotate provider class: the crash-mid-rotation brick is
// genuinely terminal here — no lane can exchange the lost RT (in the
// per-request class the same trace is only a transient mismatch, which is
// why this witness lives in THIS instance; Oracle r2 C5).
module rotationStrictRevoking {
  import rotationSpec(STRICT_DISCARD = true, PER_REQUEST_ISSUER = false).*

  // Crash between exchange and write-back = the documented brick: provider
  // rotated, vault stale, peer loops on invalid_grant. §5's terminal
  // needs_reauth exists precisely because no protocol step can recover this.
  run crashBrickWitnessTest = init
    .then(want(1))
    .then(acquire(1))
    .then(exchangeOk(1))
    .then(crash(1))                       // minted token lost with the process
    .then(want(2))
    .then(tick).then(tick).then(tick).then(tick).then(tick)  // lease lapses
    .then(acquire(2))
    .then(exchangeStale(2))               // invalid_grant: vault RT is revoked
    .expect(crashedMid and vaultRt != provRt)
}

module rotationBuggy {
  import rotationSpec(STRICT_DISCARD = false, PER_REQUEST_ISSUER = true).*

  run buggyServeWitnessTest = init
    .then(want(1)).then(want(2))
    .then(acquire(1))
    .then(exchangeOk(1))
    .then(tick).then(tick).then(tick).then(tick).then(tick)
    .then(acquire(2))
    .then(exchangeLateOk(2))
    .then(casOk(1))
    .then(buggyServeOnConflict(2))        // the §4-forbidden serve
    .expect(servedStale)
}
