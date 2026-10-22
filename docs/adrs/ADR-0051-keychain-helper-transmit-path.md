# ADR-0051 — Route the Keychain backend through `kow-keyd`

**Status:** Proposed
**Date:** 2026-09-12
**Related:** ADR-0046 (the Keychain backend this extends), ADR-0050 (whose seat key first exposed the limit)

## Context

The Keychain backend cannot store a multi-line value: `security -i`'s parser treats a newline as end-of-command, so a PEM would be stored truncated, and `_reject_untransmittable()` refuses newline, CR and NUL at the API boundary instead. **The constraint is the transmit path, not the Keychain** — a generic-password item holds arbitrary `CFData`.

ADR-0050 forced the question. Its recommended posture off Google infrastructure is a vault-held impersonation seat, whose key on macOS is a PEM. Unable to store one, operators were steered to `source: adc`, a plaintext file holding a long-lived **user** refresh token — the operator's whole identity instead of one seat's narrow mint rights. The limitation was pushing people onto a strictly worse credential.

`helper/kow-keyd.c` already solves transport: raw bytes over stdin and stdout, no command line either way.

### What the helper is not

An adversarial review killed the security framing this ADR inherited, and the correction belongs before the decision.

**The helper is not an access boundary against a same-UID attacker.** Its ACL names the helper's code identity, and anyone who can run the helper satisfies it — an unauthenticated read/write/delete oracle by construction, since macOS offers no same-UID peer authentication worth relying on. Reinforcing that: the default self-signed identity's key sits in the operator's own login keychain with `codesign` authorised against it, so an attacker can sign a binary meeting the same requirement; and ACL denial is categorical only for a caller suppressing interaction, while one that does not gets a prompt, where "Always Allow" writes them in permanently.

ADR-0046's boundary stands: **the access boundary is the macOS user account.** The CHANGELOG entry claiming the helper makes an item kow-only is wrong and is corrected here. What the helper *is*: a transport for arbitrary UTF-8 bytes with no line-oriented protocol in the middle.

## Decision

An **explicitly opt-in** helper path (`use_helper: off | require`, default `off`). When active, all four operations use `kow-keyd` and none use `security(1)`.

**`auto` is deliberately absent.** Which transport is active decides whether existing items are readable at all, so selecting it from a file's presence on disk is how an unrelated upgrade silently strands a keychain. `require` refuses to start if the probe fails, at every `self_check` level, because it states that the other transport is unacceptable rather than how loudly to complain.

**All four operations or none**, since helper-created items carry an ACL that `security(1)` cannot read, and vice versa. **Switching transports is therefore an operator migration**, and the error prints the sequence: re-adding loops forever because `update()` re-reads first and that read is refused, so the owning transport must delete. Two macOS statuses mean this, `errSecInteractionNotAllowed` and `errSecAuthFailed`; mapping only the first left real denials surfacing as a generic failure, found on a real Mac rather than in review.

**The helper path is not configurable** — discovery walks a fixed list of root-owned locations, and `use_helper` selects whether to look, never where. Homebrew prefixes are excluded because `/opt/homebrew` is owned by the installing user on Apple Silicon. **Candidates are validated before exec**: regular file, not a symlink, root-owned, not group/other writable, every parent likewise. **BSD mode bits are not the whole story** — an extended ACL supplements them invisibly, so leaf and parents are also checked for `allow` ACEs, failing closed if ACLs cannot be read. This defends the **write** path, where a substituted binary would receive the value on stdin; it does not defend reads and need not, since a same-UID attacker can already invoke the legitimate helper. A check-to-exec race remains, narrowed to an attacker who can already write a root-owned directory chain, and is not closed.

Two correctness fixes ride along. **`set` updates in place**: delete-then-add left a window with no value at all, worse than the path it replaced and detected only once irreversible, so `SecItemUpdate` now falls through to `SecItemAdd` only on `errSecItemNotFound`. **Duplicate detection moves ahead of the write**, because the delete inside `set` collapsed duplicates before the post-write count could ever fire — verification passed while two items were destroyed. It now fails closed, stricter than the `security(1)` path on purpose: that path's read-back is a real backstop and this one's was not.

Newline and CR stay refused in the *name* (the `list` protocol is newline-delimited) but not the value. Values are UTF-8 on both legs, so this backend is multi-line and NUL-safe over UTF-8, not arbitrary-binary-safe. Read-back verification is unchanged.

## Known limits, carried deliberately

`--stdin` still truncates at one line, so multi-line input is the separate `--stdin-raw` flag rather than a change in meaning for every scripted use. A failed create can delete a concurrently-created item, because cleanup decides from a pre-read — ADR-0046 behaviour, recorded rather than silently inherited. The duplicate check cannot see across the keychain search list; an explicit `keychain:` removes the ambiguity.

## What this costs

Turning it on strands every existing secret until re-added, which is the price of the ACL changing owner and the reason the default is `off`. The helper needs a signing identity, a build step `pip install` does not perform, and `sudo` to install. Deliberate friction on a path most operators do not need, since single-line API keys work unchanged.

## Rejected alternatives

- **Base64 to one line.** Adds an `encoding:` concept to a protocol that has none, so every backend gains a knob, and the item stops being inspectable in Keychain Access.
- **Another `security(1)` input mode.** `-w <value>` publishes the credential on argv to every local user. No other mode carries arbitrary bytes.
- **`auto` as the default.** Picks the semantics of stored data from a file's presence, breaking every secret at the next restart, far from the cause.
- **Keep delete-then-add.** Trades a no-value window on every update for an ACL guarantee that only matters when migrating, which is now its own verb.
- **A daemon with caller authentication.** A second door into the same room, with no same-UID peer authentication to put on it.

## Consequences

The Keychain can hold a service-account PEM, making ADR-0050's recommended posture available on macOS. ADR-0046's boundary is **unchanged**: the macOS user account. The helper's documentation, the CHANGELOG entry introducing it and the `keychain.py` docstring all implied otherwise and are corrected here. That correction is the most valuable thing in this ADR, and it came out of reviewing a design that intended to build on top of the wrong claim.
