---
status: accepted
date: 2026-08-06
---

# ADR-0045: Rename agent-vault-proxy → keys-on-the-wire (CLI `avp` → `kow`)

- **Status:** Accepted (amended 2026-09-07 — see "Amendment: minting splits from derivation")
- **Date:** 2026-08-06

## Amendment (2026-09-07): minting splits from derivation

Decision 4 below said minting and derivation *both* keep `avp-PLACEHOLDER-`. That
conflated two things with different compatibility properties, and the minting
half is now flipped to `kow-PLACEHOLDER-`.

- **Minted** placeholders (ADR-0029) are written into the vault note and read
  back from it, so the daemon matches whatever string is stored. Changing what
  we mint affects only NEW bindings, and existing ones keep working because
  recognition accepts both eras. `mint_placeholder()` now emits `kow-`.
- **Derived** placeholders (ADR-0011) are recomputed independently by `kow env`
  and the daemon and stored nowhere. Flipping that prefix would make the daemon
  derive `kow-…` while an already-written `~/.config/kow/env` still exported
  `avp-…`, and injection would stop silently. Unchanged; it still needs the
  2.0.0 migration this ADR describes.

The constants are now explicit about which is which: `MINT_PREFIX`,
`DERIVE_PREFIX`, `LEGACY_PREFIX`, and `ACCEPTED_PREFIXES` in
`src/kow/placeholders.py`. Anything asking "is this a placeholder?" must use
`ACCEPTED_PREFIXES` or `STORED_PLACEHOLDER_RE`, never a single prefix, or a
legacy placeholder gets mistaken for a live credential.

One correction to the original text: decision 4 claimed `STORED_PLACEHOLDER_RE`
already "accepts the forward `kow-PLACEHOLDER-` prefix on read". It did not —
the regex was built from the single `avp-` constant. It does now.

## Context

The project shipped as `agent-vault-proxy` (CLI `avp`) through 0.9.0. The name describes the mechanism but buries the product's actual promise — the real key is swapped in *on the wire*, in-flight, so the caller never holds it. ADR-0037 (relicense to Apache-2.0) already flagged "a product rename on the horizon that this change can ship alongside." The name is now final: **keys-on-the-wire**, CLI **`kow`**, under the existing **InflightSec** org.

`avp` is a poor long-term CLI: it collides with nothing dangerous but carries no meaning to a new user. `kow` was chosen over `ifs` (collides with the shell `IFS` variable) and over a longer `keys` (too generic).

The hard constraint on the rename is **existing installs must not break**. A deployed instance has real state that encodes the old name: stored placeholders in vaults (`avp-PLACEHOLDER-…`), config env vars (`AVP_CONFDIR`), a config directory (`/etc/agent-vault-proxy`), a systemd unit, a system user, and binding annotations keyed `avp-binding`. A rename that silently changes any of those is a breaking change dressed up as a cosmetic one.

## Decision

Ship the rename as a **backward-compatible 1.0.0**: every old name keeps working, with a documented removal in **2.0.0**. Nothing an existing deployment depends on breaks on upgrade.

### Renamed now (1.0.0)

1. **Python package / import module** `agent_vault_proxy` → `kow` (`git mv src/agent_vault_proxy src/kow`; internal, no external contract).
2. **Distribution / PyPI name** `agent-vault-proxy` → `keys-on-the-wire`. Version bumped to **1.0.0**.
3. **CLI command** `kow` is canonical. `avp` and `agent-vault-proxy` remain as **deprecated console-script aliases** (removed in 2.0.0) so existing scripts and muscle memory keep working.
4. **Placeholder prefix is UNCHANGED** — minting and derivation still emit `avp-PLACEHOLDER-`. This is deliberate and load-bearing: the daemon matches a request by `spec.placeholder in value` (`policy.py`), so the minted prefix **is** the on-wire contract. An agent's existing env file holds `avp-PLACEHOLDER-<tail>`; if the daemon started minting/deriving `kow-<tail>` it would no longer match that value and injection would silently stop — the exact way to brick a live deployment. Keeping the prefix byte-identical means **zero migration** (no `kow env` re-run). `STORED_PLACEHOLDER_RE` additionally **accepts** the forward `kow-PLACEHOLDER-` prefix on read (roll-forward/back safety). The mint flips to `kow-` in 2.0.0, which must ship a real migration for the derived placeholders already in live env files.
5. **Config env var** `KOW_CONFDIR` is canonical; `AVP_CONFDIR` is still read as a **deprecated fallback** that emits a `DeprecationWarning`. Removed in 2.0.0.
6. **Brand, repo, docs.** README, PyPI/CI badges, project URLs, and prose move to keys-on-the-wire. Repo renamed to `inflightsec/keys-on-the-wire`.

### Kept this release for backward compatibility (moves to `kow` in 2.0.0)

- **Filesystem paths** — `/etc/agent-vault-proxy`, `/var/lib/agent-vault-proxy`, `/var/log/agent-vault-proxy`, `~/.config/avp/`. These are hardcoded default paths (`addon.py`, `doctor.py`) and unit/install templates; an existing install has real files there. Changing the defaults would break default-path deployments, so the code and install docs keep them.
- **systemd unit name** `agent-vault-proxy.service` and **system user** `avp` / `_avp` — install-time identity of running deployments.
- **Binding annotation key** `avp-binding` (and `avp-owner` / `avp-ro`) — this key is written into users' vault-secret annotations; renaming it needs a dual-read in the note parser, deferred to the same 2.0.0 pass as the paths.
- **CLI hint / log strings** that print `avp env`, `[avp env]`, etc. — they ride the still-working `avp` alias and the kept `~/.config/avp/` path, so they stay coherent until the paths move.
- **Bundled plugin / skill** — plugin name `avp`, marketplace `agent-vault-proxy`, skill dir `skills/avp/`, invoke `/avp:avp`. Renaming these breaks existing plugin installs; done as part of the marketplace migration, not here. GitHub's repo-rename redirect keeps `/plugin marketplace add inflightsec/agent-vault-proxy` working.

### Removed in 2.0.0 (the breaking release)

The `avp` CLI aliases; the `AVP_CONFDIR` fallback; the filesystem paths, systemd unit, and system user; the `avp-binding` annotation key (with its own dual-read migration); the plugin/skill name. 2.0.0 also **flips the minted placeholder prefix to `kow-`** — a real on-wire change (the daemon matches the minted prefix) that must ship a migration for derived placeholders already in live env files. 2.0.0 carries a migration note.

## Out of scope (considered, not decided here)

- **JWT issuer claim.** There is no hardcoded product issuer — `iss` is operator-declared (`config_models.py`, default `None`); the `avp` seen in tests is a fixture value. Nothing to rename.
- **Git history / historical ADRs.** Not rewritten. Prior ADRs mention `AVP`/`agent-vault-proxy` as dated facts and stand as written; this ADR supersedes them on naming. Same handling as ADR-0037 §2–3.
- **PyPI package rename.** PyPI cannot rename a project. `keys-on-the-wire` is registered fresh; `agent-vault-proxy` gets a final deprecation-shim release that depends on `keys-on-the-wire` and prints a move notice.

## Consequences

- Existing deployments upgrade to 1.0.0 with **zero required changes**: old placeholders resolve, `AVP_CONFDIR` still works (with a warning), the `avp` command still runs, files stay where they are.
- Freshly minted placeholders are still `avp-PLACEHOLDER-` (unchanged), so nothing on the wire or in a vault changes shape this release; credential injection is byte-identical to 0.9.0.
- **External release steps (owner-run):** register `keys-on-the-wire` on PyPI and publish; rename the GitHub repo to `inflightsec/keys-on-the-wire` and **update the PyPI Trusted Publishing config in the same move** (it is keyed on `owner/repo`, so the rename breaks publishing until updated); publish the Homebrew formula as `keys-on-the-wire` with `oldname "agent-vault-proxy"`; ship the `agent-vault-proxy` deprecation shim.
- The half-migrated surface (kow CLI + package + brand, but avp placeholders / paths / annotation / plugin) is deliberate and documented here so it reads as a staged migration, not an oversight.
