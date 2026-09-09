---
name: kow
description: >
  Author keys-on-the-wire (kow) secret bindings the NOTES-FIRST way — tell the user
  EXACTLY what to add to Bitwarden Secrets Manager notes, Google Secret Manager
  annotations, or a future backend so a new credential is brokered through the proxy,
  with NO config-file edit and NO redeploy. Proposes only; never writes the secret to
  the vault. USE WHEN add kow secret, kow binding, broker or route an API key/token
  through keys-on-the-wire, "what do I put in the bitwarden notes", "add a secret to
  gsm for avp", new backend secret, onboard a credential to the vault proxy, connect an
  OAuth service through kow, "avp oauth login", sign in / add a Google/GitHub/Microsoft
  OAuth login, get a refresh token into the vault, help me set up OAuth for kow, kow is
  not injecting, kow isn't working, debug a kow binding, why didn't my key get swapped.
  NOT FOR editing the kow config file directly (that's the discouraged file source),
  running or deploying the proxy, or having the assistant store the secret value.
---

# kow

Helps an agent walk a user through brokering a **new** secret through **keys-on-the-wire (kow)** — the local proxy that swaps a placeholder for the real secret in-flight, so the calling process never holds the credential. This skill's whole job is to hand the user the **exact thing to paste where**, using the **notes/annotation source** so nothing in kow's config file changes and nothing is redeployed.

> **Placeholder prefixes are SPLIT — never "correct" one to the other.** Newly **minted** placeholders (`kow binding new`) carry **`kow-PLACEHOLDER-`**. **Derived** placeholders (simple mode, note has no `placeholder:` key) still carry **`avp-PLACEHOLDER-`**: both `kow env` and the daemon recompute those independently and store them nowhere, so flipping that prefix would silently stop injection for every already-written env file until `kow env` was re-run. Both prefixes are **accepted on read**. An existing `avp-PLACEHOLDER-…` in a vault note is CORRECT — leave it alone. Derivation flips in 2.0.0 with a migration (ADR-0045 amendment).

## Three hard rules

1. **Notes-first, config never.** Modern kow reads bindings from each secret's own metadata — the **BWS `notes` field**, the **GSM `kow-binding` annotation**, and equivalent per-secret metadata on future backends (`binding_source: both` is the default; notes win over file). So a new credential is added entirely in the vault UI/CLI — **no editing `bindings`/`secrets:` in the kow config, no `ansible`/`kow setup` redeploy.** Only reach for the config (file source) when a note genuinely can't express the binding (see Gotchas).
2. **Propose, never apply — for the SECRET.** This skill NEVER writes the secret value or the annotation to the vault for the user. It prints the secret name, tells the user where to put the value, and prints the annotation text to paste. The human applies it. (The assistant handling the raw secret is exactly what kow exists to prevent.)
3. **Persist the placeholder at generation — BLOCKING.** The instant `kow binding new` mints a placeholder it is shown once, on that command's output. You MUST get it into durable storage in the SAME session — never leave it living only in terminal scrollback. The placeholder is a non-secret sentinel (unlike rule 2's secret), so you *may and should* write it yourself: put the printed `export <NAME>='kow-PLACEHOLDER-…'` line straight into the consuming app's `.env`/config, or hand the user the exact line and confirm they saved it. A binding whose placeholder never reaches the consumer injects nothing — this is the single most common "kow isn't working" cause. (Backstop: the placeholder is also recoverable later from the vault note and via `kow env`, but do NOT defer to that — wire it now.)

## Workflow routing

| Trigger | Workflow |
|---------|----------|
| "add/route/broker a secret through kow", "what do I put in the notes" | `Workflows/AddSecret.md` |
| "connect an OAuth service", "avp oauth login", "sign in with Google/GitHub through kow", "get a refresh token into the vault" | `Workflows/OauthLogin.md` |
| "kow isn't injecting", "my key isn't being swapped", "the binding doesn't work" | § Diagnosing below — read the audit BEFORE touching the note |

## Diagnosing "kow isn't injecting" — the audit answers it in one look

**Read the audit first. Do not theorise about the note, the marker, the encoding, or the placeholder until you have.** A real investigation burned eleven rounds re-examining a note that was perfect, because nobody asked the audit what it saw. The decisive question is not "is my binding right" but **"what does the audit say about that host"**, and there are exactly four answers:

| What the audit shows for the host | What it means | Where to look next |
|---|---|---|
| `inject_decision` with `reason: binding_matched` | **Injection works.** The binding is fine. | Upstream rejected the key, or you are reading the wrong request. |
| `inject_decision` with any other `reason` | Binding seen, injection refused. | That `reason` string names the cause — read it, don't guess. |
| `tls_passthrough` with `reason: unbound_destination` | Host is genuinely unbound. | The note is missing, unmarked, or names a different host. |
| **Host absent from the audit entirely** | **The request never reached kow.** | Client side: `NO_PROXY`, or a process that never inherited `HTTPS_PROXY`. Nothing about the binding is implicated. |

**Absence is NOT passthrough.** This is the trap that cost the eleven rounds. A tunnelled connection *logs* a `tls_passthrough` naming the host, so "the host never appears in the audit" **rules the passthrough theory out** rather than supporting it. Reading an absence as evidence for a specific mechanism sends you a whole layer away from the fault.

Read it on the kow host (root; the audit stream carries no secret material by design):

```bash
sudo grep -i <host-fragment> /var/log/kow/audit.jsonl \
  | jq -c '{type, decision, reason, secret_name, destination}' | tail -20
```

**Then reproduce deliberately, carrying the placeholder**, because kow only ever swaps a placeholder the client actually sends:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  --proxy http://127.0.0.1:14322 --cacert /usr/local/etc/kow/ca.pem \
  -H "Authorization: Bearer <THE-PLACEHOLDER>" https://<host>/<path>
```

## Quick reference — the note is tiny

**Generate it with the tool, don't hand-write it.** `kow binding new --host <host> --name <NAME>` builds the note and validates it through the daemon's own parser before printing — marker guaranteed, `{secret}` token guaranteed, bad host refused. This is the deterministic path; hand-authoring is the fallback (and the source of two prior outages). See `Workflows/AddSecret.md` §3.

**Every note MUST begin with the marker line `# kow-binding` — the exact string, as the first non-blank line (ADR-0025).** A note without the marker is a human description: never parsed, never a binding. A note *with* the marker that fails to parse fails loud (`invalid_binding_metadata`).

Below the marker, a binding annotation is **flat YAML** with only these keys: `host`, `placeholder`, `header`, `format`, `methods`, `paths`. The credential is referenced as the generic token **`{secret}`** (the note has no name key — the secret *is* the value). Bare-host shorthand (`host: api.example.com`) works when the defaults (Authorization / Bearer) fit. `placeholder:` (ADR-0029) pins the exact sentinel the consumer must emit — minted by the tool, never hand-typed.

Bearer API on one host — paste into the BWS secret's Notes field:

```yaml
# kow-binding
host: api.example.com
placeholder: kow-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p
header: Authorization
format: "Bearer {secret}"
```

- **Fail-closed:** a secret with no *marked* annotation is never injected.
- **Backends:** BWS → the secret's **Notes**; GSM → `--update-annotations=kow-binding=<yaml>` (same marker-first contract); future backends → their per-secret metadata field.
- Full schema, the auth-pattern catalog (Bearer / token / X-API-Key / Basic / composite), and scoping live in `References/NoteSchema.md`.

## Wire the consumer — the placeholder is the other half of the binding

A binding alone injects nothing: the consuming app must **emit the secret's placeholder** for kow
to have something to swap. The placeholder is a sentinel, NOT a secret — safe to print, paste, and
write into configs without any special permission.

**Stored placeholders (ADR-0029 — the default path):** `kow binding new` mints the placeholder
INTO the note (`placeholder: kow-PLACEHOLDER-…`) and prints the wiring line on stderr:

```bash
kow binding new --host api.acme.com --name ACME_API_KEY
# stdout → the note to paste into the vault
# stderr → export ACME_API_KEY='kow-PLACEHOLDER-…'   ← wire THIS into the consumer
```

Wire it in the same session: write the line into the target `.env` / consumer config yourself (or
hand it to the user verbatim). Then remind the user the daemon reads notes at reload — a restart of
the kow daemon is needed before the new binding is live. Stored placeholders survive salt rotation
and secret renames; the whole ceremony needs no access to the kow host.

**Derived placeholders (legacy notes without `placeholder:`):** kow derives them from a per-install
salt and they still carry the `avp-PLACEHOLDER-` prefix; discover with the flagless one-liner on the kow host:

```bash
sudo kow env --print | grep <SECRET_NAME>
# (source installs without avp on PATH: /opt/kow/.venv/bin/kow)
```

`kow env` prefers the stored placeholder wherever a note pins one, so its output always matches
what the daemon enforces. If the sandbox lacks sudo on the kow host, hand the user the one-liner
and wire the value they return.

## Gotchas

- **kow swaps a placeholder you SEND; it never adds a credential you didn't ask for.** Matching is a scan of request header *values* for a known placeholder (`policy.py`: `if not value or _PLACEHOLDER_MARKER not in value: continue`). So an unauthenticated request through the proxy is forwarded untouched and comes back anonymous — that is the design working, NOT a broken binding. Testing with a bare `curl https://api.github.com/rate_limit` and reading `limit=60` as "kow injects nothing" is a false negative that fooled two separate debugging sessions. Always send the placeholder in your test.
- **A notes-only binding DOES cause TLS termination — that layer is not the suspect.** A host bound purely by a vault note, appearing nowhere in `bindings.yaml`, is terminated, matched and injected. The notes activation rebuilds the host index that `tls_clienthello` reads, on both the cold-load and the ADR-0032 background-refresh paths. Pinned by `tests/test_notes_only_tls_termination.py` and confirmed live. Do not spend rounds suspecting it.
- **`kow env` warnings are diagnostics, not failures.** `skipping secret name 'DO-API-TOKEN' — not a valid shell identifier` means exactly what it says: a hyphen cannot appear in a shell variable name, so that secret cannot be projected as an `export` line. It is deliberately not auto-mapped to `_`, because `DO-API-TOKEN` and `DO_API_TOKEN` would then collide silently. The fix is renaming the secret in the vault; nothing in kow needs changing.
- **Missing marker = inert note (ADR-0025).** A note whose first non-blank line is not exactly `# kow-binding` is ignored as a description — the secret simply stays unbound (a host-shaped unmarked note logs a load-time warning naming the secret). Never hand the user a note template without the marker line.
- **Multi-host notes (ADR-0021).** `host` accepts a list (or a `hosts:` alias) — a token spanning several hosts fans out to one binding per host. A multi-host list must set an explicit `format`, may **not** include a curated host (`api.github.com` etc.) or a `*.` wildcard element, and applies one **uniform** `methods`/`paths` scope. For per-host scope or a curated host in the mix, use the **file source** instead (a fixed placeholder no longer needs it — the note's `placeholder:` key pins one). See `References/NoteSchema.md`.
- **Composite/multi-part auth is file-source-only.** Basic auth assembled from two secrets (`email:token`) needs the config's `compose:` + `inject.template` — a note holds one secret. To stay notes-only, pre-encode the whole credential into a single secret and use `format: "Basic {secret}"`.
- **Stored beats derived (ADR-0029) — and a binding without wiring is a no-op.** `kow binding new` mints a `placeholder:` into the note and the daemon prefers it over salt derivation; notes without the key still derive. The stored value is format-gated (`kow-PLACEHOLDER-` or legacy `avp-PLACEHOLDER-`, plus ≥21 lowercase-base32 chars — never hand-type one) and uniqueness is enforced fail-closed at resolve with thief-loses semantics: a note claiming (equal or overlapping) a derived- or file-placeholder secret's placeholder unbinds only itself; two stored claimants of the same string both drop, audited with both names. Two follow-ups people skip, and then report "kow doesn't inject": (1) the consumer must actually emit the placeholder — wiring is a mandatory AddSecret step, not an afterthought; (2) the daemon reads notes at reload only — restart it after adding a secret. A pre-ADR-0029 daemon rejects the new key loudly; upgrade the daemon before adopting stored-placeholder notes.
- **`both` precedence.** With `binding_source: both`, the two sources are unioned with the notes source resolved first, so a notes binding wins over a file binding for the same secret; file-only and notes-only bindings both resolve (a file-only name is not dropped). Don't declare the same secret in both places without understanding that notes win.
- **Wildcard hosts need explicit opt-in.** A note cannot widen a credential's blast radius to `*.suffix` unless `allow_wildcard_hosts` is enabled — fail-closed by default. Keep hosts exact.
- **Annotation-write is a trust boundary (ADR-0018).** Whoever can edit a secret's notes/annotation can redirect the credential to a host they control (confused-deputy). Annotation-write must be locked to the same trust tier as value-read; `kow doctor` warns when it isn't. So "anyone can add a binding" is only safe when note-write is gated.
- **Never pre-encode a secret the assistant can see.** For Basic/base64 cases, tell the user to compute the encoding themselves (or use the file-source composite template); don't ask them to paste the raw credential to you to encode.
- **OAuth is config-source only today, and it's the least-simple flow.** An `oauth2_refresh` binding can't be expressed in a note (the parser has no OAuth support), so `Workflows/OauthLogin.md` necessarily emits a `bindings.yaml` block + a daemon reload — the one place the "notes-first, no config" rule bends. It also needs three vault secrets (client id, client secret, refresh token) and the runtime injector currently *requires* a client secret. Guide it patiently and do the mechanical parts; the refresh token is still minted by consent and never seen by the agent.
- **OAuth North Star (follow-ups to reach static-key simplicity).** To make OAuth as one-touch as `AddSecret`, three changes are needed and NOT yet built: (1) **note-based `oauth2_refresh` bindings** — teach the note parser `type: oauth2_refresh` so the binding lives in the vault, killing the config edit; (2) **client-id-in-note** — the client id is *public*, so carry it inline in the annotation instead of a separate vault secret (drops one entry); (3) **public-client support in the runtime injector** — make `client_secret_secret` optional so true PKCE public clients (no secret) work end to end. Target end-state: create one refresh-token secret + paste one annotation → run `avp oauth login` → done. **Specified in ADR-0042 §7 (note-native OAuth onboarding, v-next/proposed)** — build from that record, don't hand-roll them from this skill.
