# ADR-0051 — Route the Keychain backend through `kow-keyd`

**Status:** Proposed
**Date:** 2026-09-12
**Supersedes:** none
**Related:** ADR-0046 (the Keychain backend and the `security(1)` transmit path this extends), ADR-0050 (the GCP binding whose seat key is the first credential that cannot fit through the old path)

## Context

The Keychain backend cannot store a multi-line value. `KeychainBackend.update()` hands the credential to `security -i`, whose interactive parser treats a newline as end-of-command, so a PEM would be truncated and a *prefix* of a signing key would be stored. `_reject_untransmittable()` refuses newline, carriage return and NUL at the API boundary rather than let that happen. That refusal is correct and stays on that path.

The constraint is the transmit path, not the Keychain. A generic-password item holds arbitrary `CFData`; it is `security(1)`'s line protocol that cannot carry the bytes.

What forced the question now is ADR-0050. Its recommended posture on a host that is not on Google infrastructure is a dedicated impersonation seat whose key lives in the vault. On macOS that key is a PEM, so the Keychain cannot hold it, and the operator is pushed toward `source: adc` instead. On a workstation `google.auth.default()` resolves ADC to `~/.config/gcloud/application_default_credentials.json` — a plaintext file holding a long-lived **user** refresh token, readable by any process running as that user, carrying the operator's own identity rather than one service account's narrow mint rights. The Keychain's inability to hold a seat key was therefore steering operators onto a strictly worse credential.

`helper/kow-keyd.c` already exists and already solves the transport problem: `set` reads the value from stdin as raw bytes into `CFData` and stores it with `SecItemAdd`, `get` writes the bytes back to stdout with no trailing newline. No command line is involved in either direction.

### What the helper is not

An adversarial review of the first draft of this ADR (2026-09-12) killed the security framing it inherited, and the correction is important enough to state before the decision rather than after it.

**The helper is not an access boundary against a same-UID attacker.** Its ACL names the helper's code identity, and *anyone who can run the helper satisfies that ACL*. A process under the operator's UID runs `kow-keyd get --service kow --account NAME` and receives the secret on stdout. The helper is an unauthenticated read/write/delete oracle by construction, and it has to be, because it is a short-lived exec'd tool with no caller authentication — macOS offers no same-UID peer authentication worth relying on, which the helper's own header says.

Two further facts point the same way. The default self-signed identity's private key lives in the operator's own login keychain with `/usr/bin/codesign` authorised against it, so a same-UID attacker can sign their own binary with the same identifier and satisfy the same designated requirement. And ACL denial is only categorical for a process that has suppressed user interaction, as the helper does; a process that leaves interaction enabled gets a *prompt*, and "Always Allow" writes the attacker into the ACL permanently.

So ADR-0046's stated boundary is unchanged and still correct: **the access boundary is the macOS user account.** Run kow in its own account and keep agent workloads out of it. The CHANGELOG entry that introduced the helper claims it makes "only kow can read this item" enforceable; that claim is wrong and is corrected as part of this change.

What the helper *is*, and the only thing this ADR buys with it: a transport that carries arbitrary UTF-8 bytes to and from a keychain item without a line-oriented command protocol in the middle.

## Decision

Add an **explicitly opt-in** helper transmit path to the Keychain backend. When it is in use, all four operations go through `kow-keyd` and none through `security(1)`.

```yaml
backend:
  type: keychain
  config:
    type: keychain
    service: kow
    use_helper: off         # off | require   (new; default off)
```

1. **Two modes, and `auto` is deliberately absent.** `off` is the default and is exactly today's behaviour. `require` uses the helper and refuses to start if it is missing or does not answer a startup probe. There is no auto-detect mode, because which transmit path is in use determines *whether existing items can be read at all*, and selecting persisted-data semantics from the current presence of a file on disk is how an upgrade silently strands a keychain full of credentials.

2. **All four operations, or none.** An item created by the helper carries an ACL naming the helper; an item created by `security(1)` does not. Reading either one with the other transport fails. The mode therefore selects a transport for the whole backend, not per call.

3. **Switching transports requires migrating secrets, and the error gives the sequence that works.** Items written before `use_helper: require` was set are not readable by the helper: their ACL does not list it, interaction is suppressed, and the helper exits 51. The remedy is **not** "re-add it" — `update()` re-reads the item before writing, and that read is refused by the same ACL, so the operator loops. The transport that *owns* the item has to delete it: with `use_helper: off`, `kow secret remove <NAME>`; then set `require`; then `kow secret add <NAME> --stdin-raw`. The error message carries that sequence. Migration is an operator action with a documented procedure, not something kow attempts silently.

   Two failure statuses mean this, not one. macOS returns `errSecInteractionNotAllowed` when the process has no session and `errSecAuthFailed` when interaction was disabled explicitly, which is what the helper does at startup. Only the first was mapped to exit 51 originally, so a real ACL denial reached the caller as a generic exit 1 and the operator was told "kow-keyd failed" instead of how to migrate. Found on a real Mac, not in review.

4. **The helper path is not configurable, and the candidate set is narrow.** ADR-0046 refused a config field for `SECURITY_BIN` because a settable path to a security-critical binary is a hijack surface. Discovery walks a module-level list of absolute candidates (`KEYD_CANDIDATES`), and `use_helper` selects *whether* to look, never *where*. The list holds root-owned system locations only — `/usr/local/libexec/kow-keyd` and `/usr/libexec/kow-keyd`. Homebrew prefixes are deliberately excluded: `/opt/homebrew` is owned by the installing user on Apple Silicon, so a candidate there is writable by exactly the attacker this check is meant to exclude.

5. **A candidate is validated before exec, and the residual is stated.** It must be a regular file, not a symlink, executable, owned by root, not writable by group or other, and every parent directory up to `/` must be root-owned and not group/other writable. **The BSD mode bits are not the whole story on macOS**: an extended ACL supplements them without being visible in `st_mode`, so a root-owned 0755 binary can still carry an ACE granting the operator `write`, or its directory `delete_child`. The leaf and every parent are therefore also checked for `allow` entries via `ls -lde`, and that check fails closed if the ACLs cannot be read. Deny entries are accepted, because they only ever subtract access. This defends the **write** path, where a substituted binary would receive the value on stdin. It does not defend the read path and does not need to, because a same-UID attacker can already read secrets by invoking the legitimate helper (see above). A check-to-exec race remains, narrowed to an attacker who can already write into a root-owned directory chain; it is not closed, and saying otherwise would be the kind of claim this ADR exists to stop making.

6. **`set` updates in place; it no longer deletes first.** The helper's old `do_set` deleted every matching item and then added a replacement. A crash, timeout, ACL-construction failure or `SecItemAdd` failure between those two steps leaves the keychain with **no value at all**, which is worse than the `security add -U` path it replaces — and the Python read-back detects the loss only after it is irreversible. The helper now attempts `SecItemUpdate` on `kSecValueData` and falls through to `SecItemAdd` **only on `errSecItemNotFound`**; every other status is reported. The premise the old code was written against ("an item's ACL can only be set at creation") is true of the ACL and irrelevant to the data, and a helper-owned item already has the ACL we want.

   The keychain answers the existence question, rather than a boolean probe asking first. An `item_exists()` check was written and then removed on review: it folded authentication, interaction, parameter and database errors all into "absent" and then tried to *create* the item, turning a reportable failure into a spurious add and a possible duplicate.

   `replace` (delete-then-recreate, with the deletion's status checked rather than discarded) remains as a helper-level verb for resetting an item's ACL, but **Python never calls it** and it is not the migration mechanism — see decision 3 for why deletion has to come from the transport that owns the item.

7. **Duplicate detection moves before the mutation.** The existing check counts items *after* the write, which on this path can never fire: the query-based delete inside `set` collapses every duplicate, so the post-write count is always one and verification passes while two prior items were silently destroyed. The check moves ahead of the write, using the helper's own `list` output (one line per match, no deduplication), and fails closed — an enumeration that does not answer refuses the write rather than proceeding. This is the one place where the helper path is stricter than the `security(1)` path, which fails open there, and the asymmetry is intentional: the old path's read-back is a real backstop, and this path's was not.

8. **Read-back verification stays exactly as it is.** `update()` still re-reads and compares, still refuses a write it cannot verify, still cleans up an item it created and refuses to clean up one it did not.

9. **Newline and carriage return stay refused in the *name*; only the *value* is relaxed.** The account name travels on argv, where those bytes survive, but the helper's `list` output is newline-delimited, so a name containing a newline would be read back as two accounts and corrupt both enumeration and the duplicate count. NUL stays refused in the name because argv cannot carry it. The value is refused nothing, because it never touches a line-oriented protocol. `service` keeps ADR-0046's `^[A-Za-z0-9._-]+$` validator, which also keeps it clear of the same `list` framing.

10. **Values are UTF-8 on both legs, and the failure is handled.** The backend protocol speaks `str`. `set` encodes UTF-8; `get` decodes strictly, and a `UnicodeDecodeError` is caught and re-raised as a `BackendUnavailableError` that names the secret and withholds the bytes. This is reachable in practice, not only in theory: the helper is a public CLI and can be used to store arbitrary bytes. The honest summary is that this backend is multi-line and NUL-safe over UTF-8, not arbitrary-binary-safe.

11. **Exit codes map to the backend exception taxonomy.** 44 → `SecretNotFoundError`. 51 → `BackendUnavailableError` naming all three causes it can mean: a locked keychain, an item whose ACL predates the helper, or an item created by another writer. 34 → `errSecMissingEntitlement`, described as exactly that rather than as a general "the binary is unsigned" test, which it is not. 2 is a usage error, i.e. a kow bug, and says so. Anything else carries one sanitised line of stderr.

12. **`require` probes at startup, and the probe is not subject to `self_check`.** `_ensure_ready()` runs `kow-keyd list --service <service>` and requires a sane exit, catching a missing, non-executable or wrong-protocol binary at configuration time instead of at the first credential fetch. A failed probe clears the resolved helper path, so every later call refuses with that reason rather than quietly using `security(1)` — including at `self_check: off` and `warn`. That knob decides how loudly to complain about reachability; `require` is not a statement about loudness, it is a statement that the other transport is unacceptable. The probe does not and cannot verify the binary is the *right* one; that would need a pinned code requirement, which the self-signed path cannot supply meaningfully.

## Known limits, carried deliberately

**Multi-line values are not multi-line-safe at every CLI entry point by default.** `kow secret add --stdin` reads one line and strips its terminator, which is correct for an API key and would silently truncate a PEM. Rather than change what `--stdin` means for every secret already scripted against it, multi-line input is a separate flag, `--stdin-raw`, which reads to EOF and strips nothing. The truncating behaviour of `--stdin` is pinned by test so it cannot be mistaken for a bug later.

**A failed create can compensate by deleting a concurrently-created item.** `update()` decides whether to clean up a bad write from a pre-read taken before the write, so if another process creates the item in that window and the read-back mismatches, the cleanup deletes *their* item. This is ADR-0046 behaviour and predates this change; fixing it properly needs an item reference returned by the write, which neither transport currently gives. Recorded rather than silently inherited.

**The duplicate check cannot see across the default keychain search list.** Generic-password uniqueness is per keychain, so a same-named item in another keychain on the search list can coexist with one added to the default keychain. Naming an explicit `keychain:` removes the ambiguity, which is what the e2e legs and any careful install do.

## What this costs, stated plainly

Turning `use_helper` on strands every secret already in the keychain until it is re-added. That is a real migration, it is the price of the ACL changing owner, and it is why the default is `off` and why there is no auto-detect.

The helper needs a signing identity and a build step that `pip install` does not perform. It also needs installing into a root-owned directory, which means `sudo`. Both are deliberate friction on a path that most operators do not need: if your credentials are all single-line API keys, the `security(1)` path is unchanged and remains the default.

This does not make the Keychain a fleet backend, does not make it syncable, does not change its threat model, and does not touch the data-protection keychain tier. `--data-protection` remains implemented in the helper and unreachable from config, because it needs a paid Team ID; that stays ADR-0046's L2 decision.

## Rejected alternatives

**Encode the PEM to a single line (base64) and decode on read.** The smallest change, and wrong. It introduces an `encoding:` concept into a backend protocol that has none, so every backend and consumer acquires a knob; the stored item stops being inspectable as a key in Keychain Access; and it buys a workaround for a constraint the helper removes outright.

**Pass the value to `security` some other way.** `add-generic-password -w <value>` puts the credential on argv, where the macOS process table publishes it to every local user for the life of the call. No other input mode of `security(1)` carries arbitrary bytes.

**Keep `auto` as the default.** Rejected on review. It picks the semantics of stored data from the presence of a file, so installing the helper during an unrelated upgrade breaks every existing secret at the next restart, and the failure surfaces as a keychain error far from its cause.

**Keep `set`'s delete-then-add.** Rejected on review. It converts every ordinary update into a window where the credential does not exist, in exchange for an ACL guarantee that only matters when migrating a legacy item — which is now its own verb.

**Make the helper a daemon, or add caller authentication to it.** A socket is a second door into the same room, and there is no same-UID peer authentication on macOS to put on it. This is why the helper cannot be an access boundary and why this ADR stops claiming it is one.

## Consequences

The Keychain becomes able to hold a service-account PEM, which makes ADR-0050's recommended posture — a vault-held impersonation seat with mint rights and no data access — available on macOS instead of pushing the operator onto a broader user credential. ADR-0050's macOS note and the GCP workflow's gotcha change from "use a networked backend" to "install the helper, or use a networked backend".

ADR-0046's security boundary is **unchanged**: the macOS user account. The helper's own documentation, the CHANGELOG entry that introduced it, and the `keychain.py` module docstring all currently imply otherwise and are corrected here. That correction is the most valuable thing in this ADR, and it is worth noting that it came out of reviewing a design that intended to build *on top of* the wrong claim.
