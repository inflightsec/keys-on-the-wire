# Architecture: keys-on-the-wire

> **What this is.** A small loopback HTTPS proxy that fetches API keys from Bitwarden Secrets Manager (BWS) on demand and injects them into outbound requests on behalf of an agent. The agent never holds real secrets in memory - only placeholder strings.
>
> **What this is *not*.** An egress firewall. Egress policy belongs to the operator's firewall of choice (OpenSnitch, nftables, firewalld, …). The proxy stays in its lane: **credential brokerage** for opted-in destinations.

## 1. Executive summary

`keys-on-the-wire` is a [mitmproxy](https://mitmproxy.org/)-based HTTP/HTTPS forward proxy running on loopback as a dedicated system user. The agent process ships with credential **placeholders** as if they were the real secrets. When the agent issues an outbound request, the proxy:

1. Detects a known placeholder in the request header
2. Verifies the destination is in the operator-declared binding for that secret
3. Fetches the real secret from BWS (with TTL cache)
4. Substitutes placeholder → real secret on the upstream socket
5. Records the decision in an append-only audit log

Both outcomes of that sequence are drawn in [§4.3 Request lifecycle](#43-request-lifecycle).

Requests whose destinations aren't bound to any secret are forwarded unmodified, the proxy is a transparent intermediary, not a gatekeeper. Destination filtering / network-egress lockdown is **out of scope** and is left to the host's existing firewall.

Scope:

- **In scope:** static API keys (Anthropic, OpenAI, GitHub PAT, etc.); BWS as backing store; per-secret destination bindings; sandbox-only CA; structured audit log.
- **Out of scope:** kernel-level egress enforcement, multi-tenant routing. (Request signing shipped: AWS SigV4 as `inject.type: sigv4` — ADR-0027, S3-hardened in ADR-0036; `hmac` / `jwt_bearer` — ADR-0028. OAuth refresh-token flows shipped in v0.7 as `inject.type: oauth2_refresh` — ADR-0017; `oauth2_client_credentials` and `github_app` — ADR-0030.)

The implementation is a few thousand lines of Python (≈2,500 statements across ~20 modules — the credential hot path is concentrated in `addon.py`) plus a systemd unit. Operational complexity stays small: one daemon, one config file, one audit log.

> Design records cited as **ADR-NNNN** live in [`docs/adrs/`](adrs/) (0011 onward; see that directory's README for the sequence note).

## 2. Threat model

### In scope

| ID | Threat | Defense |
|---|---|---|
| **T-1** | **Prompt injection.** Untrusted input flips the agent into hostile behavior; the agent attempts to leak credentials. | The proxy ensures real secrets never enter the agent's address space (G1) - the agent cannot exfiltrate what it doesn't have. |
| **T-2** | **Agent process compromise.** RCE in the agent gives the attacker the agent's UID. | Same protection as T-1: secrets aren't in memory to be read. |
| **T-1.5** | **Laundering through bound destinations.** Agent uses `GITHUB_PAT_*` legitimately against `api.github.com` (bound) to create a public gist containing exfil data. | Per-binding method/path scope. `methods: [GET]` blocks POSTs entirely; the placeholder is forwarded verbatim on a scope violation (G5), audited as `binding_scope_violation`. |
| **T-3.5** | **Supply-chain compromise of proxy dependencies.** Poisoned Python package in `mitmproxy`, `bitwarden-sdk`, or a transitive dep gives an attacker code execution at proxy UID at next install. | Hash-pinned `requirements.lock` (`pip install --require-hashes`). Dep updates require operator review. |

### Explicitly out of scope (no defense claim)

- **T-3 - Agent UID interactive shell with network egress.** A persistent attacker on the agent's UID can attempt to talk to the network. **The proxy does not block this.** The host's egress firewall is the relevant control. The proxy's contract starts when a request arrives at `127.0.0.1:14322` and ends when the response is delivered.

  > **Subset worth stating explicitly:** a malicious dep at the agent's UID *can* use the proxy as its own authenticated channel. The proxy injects the real secret on any request that matches a binding's placeholder, host, method, and path, it cannot tell legitimate-agent traffic from poisoned-dep traffic when both run at the same UID. The G1 in-memory isolation defends against memory-theft attacks; the per-binding `methods:` / `paths:` scope is what limits what an authenticated bad actor at the same UID can do once they have the proxy's cooperation. Lock those scopes down; pair with egress filtering for the agent UID.
- **T-4 - Proxy process compromise.** UID-of-proxy compromise = total compromise of all bound secrets in flight. Not eliminated, mitigated by systemd sandboxing and supply-chain discipline. Documented as accepted residual risk **R1**.
- **T-5: Host root.** No userspace mechanism survives this.
- **T-6, BWS itself compromised.** Outside trust boundary.
- **T-7, Kernel exploit.** Outside threat model.
- **T-8: Side channels** (timing, response sizes, audit log inference). Not what this layer addresses.
- **T-9, Application-layer leakage in upstream responses.** If an upstream API echoes secrets in response bodies and the agent logs them, that is a different problem.

### Why egress is out of scope (the architectural decision)

An earlier design treated the proxy as both a credential broker AND a kernel-level egress lock. During deploy this was discarded for three reasons:

- **Reliability.** `nft meta skuid` matching did not reliably catch sudo-spawned processes on every host (root cause: socket-UID tagging behavior with `setuid()`; unconfirmed). Rules appeared installed but packets traversed regardless.
- **Conflicts with legitimate local services.** "Everything denied except proxy" conflicted with loopback services (TTS, IPC) and required iterative carve-outs.
- **Most importantly: users already have a preferred egress firewall.** Forcing our own kernel rules duplicates concerns and creates an "ours vs theirs" precedence problem.

Decision: the proxy is a **credential broker**; egress filtering is the operator's stack. They're orthogonal, both useful, and neither should depend on the other.

## 3. Atomic guarantees

Each guarantee is binary and individually testable.

| ID | Guarantee | Test |
|---|---|---|
| **G1** | Agent process address space never contains real secret bytes | `gcore <pid>; strings core \| grep <secret-prefix>` returns 0 |
| **G2** | Real secret bytes appear on the wire only inside upstream TLS records sent from the proxy | `tcpdump -i lo` agent↔proxy: never. `tcpdump -i any` proxy→upstream: yes, only inside TLS. |
| **G3** | Per-request destination check from CONNECT target + SNI + Host header consistency, before injection | Mismatched Host → 403 audit event, no injection |
| **G4** | Fail-closed on any uncertainty, with the externally-visible behavior matched to the failure class. **Request-time** failures the proxy can recover from per-request (BWS unreachable, named secret missing) → placeholder forwarded verbatim; upstream returns its own auth failure (401/403); proxy audits `inject_decision: denied`. **Startup or persistent** failures the proxy cannot serve under (config invalid, audit log unwritable, preflight `fail_on_warning` tripped) → the daemon refuses to start (or, if mid-life on a config reload, refuses to serve and surfaces a 503 to the next request until restored). Either way, no request is ever modified with a degraded or guessed credential. | Stop BWS → next request fails closed with upstream auth fail; corrupt bindings.yaml → daemon refuses to start |
| **G5** | Enforcement by omission, non-permitted destination receives the placeholder verbatim, not an error | Upstream returns its standard auth-failure; proxy did not 5xx |
| **G6** | The `inject_decision` audit event is fsynced before the proxy writes the modified request bytes to any upstream socket. Enforced by mitmproxy's request lifecycle (the modified request is not written to the upstream socket until the `requestheaders` hook returns) combined with `audit.emit()` performing a synchronous `os.fsync()` inside that hook. An explicit "do not reorder" comment in `addon.py` marks the ordering as non-refactorable. | Instrument upstream-write call site; fault-inject fsync hang and verify the upstream write blocks until fsync completes |
| **G7** | The proxy CA is per-host and is only trusted by callers that explicitly load it via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`. Operators must NOT add it to system-wide trust stores. | From a non-proxy-configured shell: `curl --proxy 127.0.0.1:14322 https://upstream` → TLS verification fails |
| **G8** | Rotated BWS secret picked up within configured TTL (default 300 s) | Rotate, observe stale until TTL, fresh after |
| **G9** | Proxy restart does not lose audit history; restart itself is audited | Kill mid-session → restart → log intact + `proxy_restart` event |

The most important counter-intuitive choice is **G5 enforcement by omission**: returning 5xx on a binding violation would tell an attacker probing the agent that the exfil destination is blocked, turning the proxy into a side channel. Forwarding the placeholder lets the upstream's normal auth rejection surface - monitored as an auth failure with no leak about proxy mechanics.

## 4. Reference architecture

### 4.1 Process layout

```
┌────────────────────────────┐
│   systemd (system slice)   │
└─────────────┬──────────────┘
              │ owns
              ▼
┌──────────────────────────────────────────┐
│   kow.service              │
│   ─────────────────────────────────      │
│   User=kow (fixed system user)           │
│   Group=kow                              │
│   HOME=/var/lib/kow        │
│   python -m kow            │
│     → mitmproxy in-process addon         │
│     → BWS Python SDK + cache             │
│   Listens: 127.0.0.1:14322               │
│   Audit:   /var/log/kow/   │
│            audit.jsonl (chattr +a)       │
└──────────────────────────────────────────┘
              ▲
              │ HTTPS_PROXY=http://127.0.0.1:14322
              │ NODE_EXTRA_CA_CERTS=/etc/kow/ca.pem
              │ NO_PROXY=localhost,127.0.0.1,::1,…
              │
┌──────────────────────────────────────────┐
│   Agent process (any UID)                │
│   Sees only placeholders in env          │
└──────────────────────────────────────────┘
```

### 4.2 Bindings configuration

YAML at `/etc/kow/bindings.yaml`. Re-read on service restart; file-mtime auto-reload is not implemented (planned for a later release). See [`bindings.example.yaml`](../bindings.example.yaml) for the full grammar; abbreviated:

```yaml
version: 1

secrets:
  ANTHROPIC_API_KEY:
    placeholder: "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
    inject:
      header: "Authorization"
      format: "Bearer {ANTHROPIC_API_KEY}"
    bindings:
      - host: "api.anthropic.com"
      - host: "*.claude.com"

  GITHUB_PAT:
    placeholder: "ghp_PLACEHOLDER_WORK_01HXY1234567890"
    inject:
      header: "Authorization"
      format: "token {GITHUB_PAT}"
    bindings:
      - host: "api.github.com"
        methods: [GET]      # closes T-1.5 laundering via gist POST
      - host: "uploads.github.com"

unmatched_destination_policy: forward_unmodified

cache:
  ttl_seconds: 300
  max_entries: 100
  jitter_seconds: 30

audit:
  path: /var/log/kow/audit.jsonl
  fail_on_unwritable: true

backend:
  type: bws
  config:
    type: bws
    organization_id: "<bws-org-uuid>"
    access_token_path: /etc/kow/bws-token
    state_path: /var/lib/kow/bws-state.json
    # EU region: explicit URLs
    # api_url: https://api.bitwarden.eu
    # identity_url: https://identity.bitwarden.eu
```

Additional backends plug in by registering a new `type` discriminator; see [`docs/adapter-architecture.md`](adapter-architecture.md) for the protocol and the registry.

**Composite bindings (v0.4+):** auth schemes that assemble multiple atomic BWS values on the wire (e.g., Jira / Atlassian Cloud Basic auth `base64(email:token)`) use `inject.template` instead of `inject.format`, plus a `compose:` list of 1-4 BWS secret names. The template is Jinja2 syntax (operators already know it) evaluated through `jinja2.sandbox.ImmutableSandboxedEnvironment` with an AST-level deny-by-default validator at config-load, class-walk escapes, control flow, attribute traversal, subscript, and arithmetic are all structurally impossible. The composite never gets its own cache entry: raw BWS values are cached, the template renders per request.

Example (Jira Basic auth):

```yaml
JIRA_API_BASIC:
  placeholder: "jira_PLACEHOLDER_01HXY1234567890AB"
  inject:
    header: "Authorization"
    template: "Basic {{ (JIRA_EMAIL + ':' + JIRA_API_TOKEN) | b64encode }}"
  compose:
    - JIRA_EMAIL
    - JIRA_API_TOKEN
  bindings:
    - host: "your-tenant.atlassian.net"
```

Whitelisted callables (anything else is rejected at config-load):

| Name | Kind | Signature | Notes |
|---|---|---|---|
| `b64encode` | filter | `str → str` | Standard RFC 4648 §4 base64 of UTF-8 bytes. ASCII output. |
| `b64decode` | filter | `str → str` | Strict; raises on invalid padding/characters. |
| `sha256` | filter | `str → str` | Lowercase hex digest of UTF-8 bytes. |
| `urlencode` | filter | `str → str` | Percent-encode per RFC 3986, no safe characters. |
| `hmac_sha256` | function | `(key: str, msg: str) → str` | Lowercase hex HMAC-SHA256. |
| `hmac_sha512` | function | `(key: str, msg: str) → str` | Lowercase hex HMAC-SHA512. |
| `hmac_sha1` | function | `(key: str, msg: str) → str` | Lowercase hex HMAC-SHA1 (legacy APIs). |
| `totp` | function | `(secret_b32: str) → str` | RFC 6238 TOTP, SHA-1/30 s/6 digits. The one non-deterministic helper (wall clock). |

**Operator language:** variable references (compose names), string literals, the `+` operator (string concat only), filter pipes `|`, and function calls. Nothing else - no `if`/`for`/`set`/comparison/subscript/attribute access/arithmetic/`__class__` walking, no `format`/`xmlattr`/`attr` filters. Templates and compose lists are validated at config-load: bad syntax, unknown name, wrong filter arity → kow refuses to start. See [`bindings.example.yaml`](../bindings.example.yaml) for more examples.

**Config-load invariants:**

- Wildcard hosts are OFF by default: any `*.` binding fails config load unless `allow_wildcard_hosts: true` (ADR-0034 adds a `subdomains:` label allowlist to narrow one)
- Wildcard depth ≤ 1 DNS label (reject `*.com`)
- Empty `bindings: []` rejected explicitly (deny-all must be intentional, not via omission)
- `methods: []` and `methods: [*]` rejected: omit the field instead
- Bad config on hot-reload: keep old config, log error, never crash
- Placeholder validated fail-closed at config load: marker present, minimum length (`_PLACEHOLDER_MIN_LEN` = 24), uniqueness across the secret set, and no substring overlap

**Host-matching semantics (read before you write a binding):**

- **Exact match is byte-for-byte string equality.** `api.openai.com` matches `api.openai.com` and nothing else. Case-sensitive in principle, though real DNS is case-insensitive: write hostnames lowercase.
- **Wildcards use a `*.` prefix and match exactly one DNS label.** `*.openai.com` matches `api.openai.com` but NOT `evil.api.openai.com` (two labels). The wildcard prefix cannot itself contain `.`. This is enforced both at config load (wildcard depth ≥ 2 DNS labels) and at match time (the matched prefix has no dot). Wildcard bindings additionally require the `allow_wildcard_hosts` opt-in — off by default, any `*.` host is rejected at config load.
- **No IDNA / punycode normalization.** A host like `xn--bcher-kva.example` matches only that exact ASCII form. If the agent's HTTPS client sends the Unicode form (`bücher.example`), it won't match the punycode binding, and vice versa. Pick one form and use it consistently in both BWS-side state and your bindings.
- **No trailing-dot normalization.** `api.example.com` and `api.example.com.` are different hosts to the matcher. mitmproxy typically strips the trailing dot, but don't rely on it - match what your client actually sends.
- **No port handling.** The host string is the hostname only. There is no `host: "api.example.com:443"` form. If you need port-scoped routing, use the host alone: the proxy listens on a single inbound port (14322) and forwards to upstream's chosen port.
- **CONNECT host vs. Request host must agree.** The proxy enforces SNI/Host-header consistency at injection time, a CONNECT to `api.openai.com:443` whose subsequent request line says `Host: evil.com` is denied (`sni_host_mismatch`). This closes a class of TLS proxy laundering.
- **Redirects are NOT followed by the proxy.** The proxy forwards the upstream's 3xx response to the agent and stops. If the agent follows the redirect to a host not in any binding, the real secret is not injected: the placeholder forwards verbatim and the upstream rejects it. Defenders treat redirects as the calling code's problem.
- **Binding order matters.** Within a single `secrets:` entry, bindings are evaluated top-to-bottom; the first matching binding wins. If two `host:` patterns could both match, the more specific one should come first.

**Binding source (`binding_source`, ADR-0011):**

Bindings can come from the `bindings.yaml` file (above), from each BWS secret's `notes` field, or both. The `binding_source` key selects which:

| value | behaviour |
|---|---|
| `file` | Bindings come ONLY from `secrets:` in `bindings.yaml`. Identical to pre-ADR-0011; no backend listing happens. |
| `notes` | Bindings are resolved from each secret's per-secret metadata (BWS `notes` field, GSM `kow-binding` annotation). The daemon lists the backend's secrets, derives each one's salted placeholder, fetches and parses its note, and enforces the result. `secrets:` in the file is ignored (leave it `{}`). The legacy values `bws_notes` / `gsm_notes` are accepted as deprecated aliases (normalized to `notes` with a `DeprecationWarning`). |
| `both` (default) | Resolve from BOTH, unioned. For a secret defined in both, the **notes binding wins** (it's closer to the secret). |

In `notes`/`both` mode, placeholders are not hand-authored — they are derived deterministically from a per-install salt:

```
avp-PLACEHOLDER-<base32(HMAC-SHA256(install_salt, secret_name))[:21]>
```

The salt (32 random bytes, `0600`, rejected if group/other-readable or wrong-owner) is generated once at `kow setup` and stored at `install_salt_path` (default: `$KOW_CONFDIR/install-salt`, else `install-salt` under the daemon's `$HOME` — the `kow`-writable confdir, e.g. `/var/lib/kow/`). It makes placeholders non-precomputable from the secret name alone. The same derivation runs in `kow env` (which writes the agent's `export NAME='<placeholder>'` file) and in the daemon, so both sides agree without a second config. A derived-placeholder **collision** across the secret set is a hard startup failure listing the conflicting names.

**Notes-binding marker (`# kow-binding`, ADR-0025):** a note/annotation is parsed as a binding **only when its first non-blank line is exactly `# kow-binding`**. The marker line is stripped and the remainder parses under the normal grammar (bare hostname, or the flat mapping). An unmarked note is a human description — `NoBinding`: it cannot bind, cannot be malformed, and cannot exclude the same secret's file bindings. An unmarked note that *looks* host-shaped (bare FQDN, or a `host:`/`hosts:` line) logs a load-time warning naming the secret and the missing marker. A **marked** note with an empty or unparsable body is `InvalidBinding` — the marker is explicit intent, so errors are loud, fail-closed, and audited. The contract is uniform across sources: BWS notes and the GSM `kow-binding` annotation alike.

A request carrying a placeholder whose secret has **no binding** in its note (including an unmarked note) fails closed and audits `no_binding_in_notes`; a **malformed marked** note audits `invalid_binding_metadata`. Both forward the placeholder verbatim (no real value injected).

**What a note can express — and the misreading to avoid.** `_ALLOWED_NOTE_KEYS` (`notes_binding.py`) is exactly `{host, hosts, header, format, methods, paths, placeholder}`, and any other key fails closed. There is no `inject:`/`type:` key, so **a note expresses static-header injection of one secret and nothing else**. Every other injector — `body`, `oauth2_client_credentials`, `oauth2_refresh`, `github_app`, `sigv4`, `hmac`, `jwt_bearer`, `multi` — is **file source only**.

This distinction is easy to invert, and the failure is expensive in the wrong direction: on 2026-09-20 an operator reading the note grammar as the product's full surface concluded kow could not broker OAuth2 client-credentials at all, when `oauth2_client_credentials` (ADR-0030) had shipped two months earlier. The rule worth stating positively: **notes-first is the default for a one-secret header credential; anything needing two secrets, a token URL, a signature, or a non-header injection point is file source.**

**Migration precedence trap.** Under `binding_source: both` a note **wins over** a file binding for the same secret. Moving a secret from note to file source therefore requires *deleting the note* — leaving it in place silently disables the injector that replaced it.

**Two-part credentials and the Basic assumption.** A note holds one secret, so a two-part credential (`client_id`+`client_secret`, `email:token`) is notes-expressible only when the upstream accepts both parts pre-encoded into one header value, i.e. HTTP Basic. RFC 6749 §2.3.1 requires authorization servers to support Basic, **but that is not evidence about a given server**: one commercial provider's token endpoint answers a valid Basic header with `400 {"code":"invalid_request","message":"client_id was not specified"}`, requiring the credentials in the request body instead. Probe the upstream with one request before choosing the binding shape — fake credentials suffice, since a "missing parameter" error and a "bad credentials" error distinguish the two cases. A wrong choice here produces an inert note that looks correct in the vault. Full decision table: [Troubleshooting](troubleshooting.md).

**Notes host allowlist (`notes_host_allowlist`, ADR-0024).** Opt-in top-level key that bounds where notes/annotation bindings may route: **annotations may only narrow scope, never add a host.** When absent (default), nothing changes. When set, a notes/annotation host outside the list has its binding dropped fail-closed and a request toward it audits the distinct reason `host_not_in_allowlist`. Motive: on GCP, `secretmanager.secrets.update` (edit the `kow-binding` annotation) and `versions.access` (read the value) are independently grantable, so without this an annotation-only writer could route a secret to a host they control (confused deputy). Multi-host notes (ADR-0021) are judged per host — a disallowed host drops only its own fan-out entry. `*.suffix` allowlist entries ride the `allow_wildcard_hosts` opt-in. File `secrets:` bindings are the trusted tier and exempt. IAM hygiene (restricting annotation-write) remains the primary GCP control; this is the structural backstop.

> Listing secrets requires a listable backend (`bws`, `gsm`, `static`, `aws-secrets-manager`, `keychain`). Notes are fetched at configure() time (the binding-policy refresh boundary, analogous to re-reading the file) AND re-resolved in the background every `notes_refresh_seconds` (ADR-0032, default 60s) for vault backends, so a newly-added secret is brokered without a restart; the refresh keeps the warm value/token caches and fails safe (keeps live bindings) if the vault can't be listed. Per-request credential VALUE fetches still honour `cache.ttl_seconds`.

### 4.3 Request lifecycle

Two outcomes are worth seeing before the exhaustive trace: a request that gets
injected, and one that does not. Sources and regeneration: [`docs/diagrams/`](diagrams/).

**Authorized — the placeholder is swapped on the wire.**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/kow-injection.dark.png">
  <img alt="Sequence diagram: the agent sends a placeholder, the binding policy authorizes the destination, the vault is read, the audit record is fsynced, and only then does the real key reach the upstream socket" src="diagrams/kow-injection.light.png">
</picture>

**Denied by omission — the placeholder is forwarded verbatim (G5).**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/kow-denied.dark.png">
  <img alt="Sequence diagram: the same placeholder used against POST /gists when the binding allows only GET; kow forwards the placeholder rather than an error and upstream returns its own 401" src="diagrams/kow-denied.light.png">
</picture>

The full trace, including the `http_connect` hook the diagrams elide:

```
1. Agent: CONNECT api.anthropic.com:443 HTTP/1.1
              │
2. Proxy (http_connect hook):
     - Parse target
     - If destination is in any binding: continue
     - Else if unmatched_destination_policy = forward_unmodified: continue
     - Else (deny): emit deny audit + return 403
              │
3. Agent (inside MITM-tunneled TLS):
     GET /v1/messages
     Authorization: Bearer sk-ant-PLACEHOLDER-…
              │
4. Proxy (requestheaders hook):
     a. tag flow.metadata with request_id
     b. SNI/Host consistency check (G3)
     c. Destination allow-list check (applies for plain HTTP too)
     d. Scan headers for a known placeholder
        → no placeholder: forward unmodified
        → placeholder found: continue
     e. Verify the matched secret's bindings include this destination
        → no: emit `destination_not_in_binding` audit, forward verbatim (G5)
     f. Verify the matched binding's method/path scope permits this request
        → no: emit `binding_scope_violation` audit, forward verbatim (G5)
     g. BWS fetch via cache (G4 fail-closed on unreachable)
     h. Substitute placeholder → real secret on the request header
     i. Emit `inject_decision: allowed` audit, synchronous fsync (G6)
              │
5. Proxy → upstream (TLS): forward modified request
              │
6. Upstream → proxy: response
              │
7. Proxy → agent: forward response unchanged
              │
8. Proxy: emit `upstream_response` audit with status code only
```

### 4.4 Audit log

JSONL, append-only via `chattr +a`. One event per line. Every record carries
`v` — the audit JSON contract version (`AUDIT_CONTRACT_VERSION` in `audit.py`).
**Current version: 5** (v2 added `binding_source` to `inject_decision` and the
`no_binding_in_notes` reason, per ADR-0011; v3 added the `honeytoken_triggered`
event, per ADR-0019; v4 added the `policy_advisory`
event type, per ADR-0047; v5 added the three ssh-agent oracle events
`ssh_session_bound` / `ssh_sign_allowed` / `ssh_sign_denied`, per ADR-0053 —
keys appear as SHA256 fingerprints only, never blobs or signed data). Bumping
this version is a contract change: see hard constraint #3 in
[`AGENTS.md`](../AGENTS.md).

**`policy_advisory` (v4).** Advisories get their own event type precisely so
they never inflate `inject_decision` counts: a consumer counting allowed
`inject_decision` records as successful injections keeps working unchanged.
One reason uses it today: `binding_methods_unscoped`, which also carries
`method`. It is emitted at decision time, before the secret is fetched and
injected, so an advisory is not the request's final outcome: the request may
still fail at the execution layer and produce its own terminal
`inject_decision` with the same `request_id`.

```json
{"ts":"2026-05-17T14:32:11.123456+00:00","v":4,"type":"inject_decision","request_id":"01HXY...","decision":"allowed","reason":"binding_matched","secret_name":"ANTHROPIC_API_KEY","binding_source":"bws_notes","destination":{"host":"api.anthropic.com","port":443,"path_prefix":"/v1/messages"}}
{"ts":"2026-05-17T14:32:11.234567+00:00","v":4,"type":"upstream_response","request_id":"01HXY...","status":200}
```

`binding_source` (`inject_decision` events) records which source supplied the
binding: `file` (a `bindings.yaml` entry), `bws_notes` (BWS notes metadata), or
`gsm_notes` (a GSM `kow-binding` annotation) — audit provenance stays
backend-typed even though the config mode is the generic `notes`. When file and
notes both define the same secret, notes wins (ADR-0011) and the event carries
the notes label.

Rules:

- `fail_on_unwritable: true` - disk full / attribute removed / permission flip = proxy returns 503 (G4 + G6)
- Synchronous `fsync()` after every event, no exceptions. Throughput is bounded by the audit disk's fsync latency, but at the volume a credential broker sees (a few hundred decisions per minute at most) this is well below any threshold worth optimizing.
- **Never log** header values, request bodies, response bodies, or query strings (Vault-style audit minimization)
- **Closed event-type set (ADR-0023):** `AUDIT_EVENT_TYPES` in `audit.py` enumerates every `type` the stream may carry; `AuditWriter.emit()` raises on any unlisted type. A new event type cannot ship without a conscious edit there plus no-leak test coverage. The current set is `inject_decision`, `deny`, `token_exchange`, `refresh_token_rotated`, `honeytoken_triggered`, `proxy_restart`, `upstream_response`, `tls_passthrough` (ADR-0026 — a TLS connection tunnelled un-terminated because its destination is unbound; dest host + reason only, never decrypted), `notes_refreshed` (ADR-0032 — the background refresh changed the bound set; added/removed names only), `policy_advisory` (ADR-0047 — a one-time advisory that a binding omits `methods:`; its own type so advisories never inflate `inject_decision` counts), and the ADR-0053 ssh-agent oracle events `ssh_session_bound` (a verified `session-bind@openssh.com`: destination host-key fingerprint + forwarding flag), `ssh_sign_allowed`, and `ssh_sign_denied` (the signing verdict, fsynced before the signature bytes reach the client socket — the G6 analogue; reason taxonomy in `kow/sshagent/policy.py`).
- Off-host shipping: a separate tailer forwards this stream to a central collector (ADR-0019); the local log stays the fail-closed source of truth and is never in the shipper's failure path

**Reason taxonomy on `inject_decision` events** (use these to filter and alert from the audit stream):

| `decision` | `reason` | Meaning |
|---|---|---|
| `allowed` | `binding_matched` | Header injector substituted the placeholder; substitution is on the wire |
| `allowed` | `body_binding_matched` | Body injector substituted a placeholder occurrence in the streaming body. Per-secret event; emitted on first match per request, **before** the substituted bytes return to mitmproxy (same G6 ordering as the header path) |
| `allowed` | `binding_methods_unscoped` | Binding omitted `methods:` and took a mutating verb. Emitted as `policy_advisory`, once per binding+verb per process (ADR-0047) |
| `denied` | `unmatched_destination` | Host not in any binding, `unmatched_destination_policy: deny` |
| `denied` | `sni_host_mismatch` | CONNECT host disagrees with request host (TLS-level deception attempt) |
| `denied` | `ambiguous_placeholder_match` | Two distinct configured placeholders appeared in the same target header — refusal to guess |
| `denied` | `destination_not_in_binding` | Header placeholder matched a secret, but the destination isn't in that secret's bindings |
| `denied` | `binding_scope_violation` | Method or path scope on the binding rejected this request |
| `denied` | `secret_unavailable:<ExcName>` | Backend returned `BackendUnavailableError` / `SecretNotFoundError` |
| `denied` | `secret_fetch_error:<ExcName>` | Backend raised an uncaught exception (G6 fail-closed catch-all) |
| `denied` | `composite_unavailable:<ExcName>` | One or more compose entries failed to fetch |
| `denied` | `composite_fetch_error:<ExcName>` | Compose-path catch-all |
| `denied` | `render_failed` | Composite template render raised (template-internal detail logged separately, not audited) |
| `denied` | `composite_render_unexpected_error:<ExcName>` | Body composite resolver raised an exception type that `_fetch_and_render_composite` doesn't catch (closure-capture bug, `MemoryError`, `RecursionError`); G6 fail-closed catch-all at the body-streaming layer |
| `denied` | `invalid_binding_metadata` | A BWS secret's **marked** notes blob is MALFORMED (bad YAML, unknown key, bad value, or empty body under the `# kow-binding` marker). Fail closed; a precise diagnostic is surfaced via `kow doctor` (ADR-0011, ADR-0025) |
| `denied` | `no_binding_in_notes` | A BWS secret's notes blob carries NO binding (empty/missing/unmarked note, or no `host`). Distinct from `invalid_binding_metadata` — the secret simply isn't bound yet, not typo'd (ADR-0011, ADR-0025) |
| `denied` | `host_not_in_allowlist` | A notes/annotation host was rejected by the file-side `notes_host_allowlist` — the note tried to route the secret to a host the file didn't pre-approve. Distinct from `invalid_binding_metadata` (the note is well-formed; the destination is un-approved). The confused-deputy control (ADR-0024) |

For multi-injector secrets (`inject.type: multi`), each substituted leaf emits its own event (one `binding_matched` per header leaf that fires, one `body_binding_matched` per body leaf that fires). `secret_name` is the parent secret's name; consumers parsing the stream see one substitution event per (request, leaf-that-fired).

**OAuth2 events (ADR-0017).** `oauth2_refresh` bindings add two event types. `token_exchange` fires after an upstream RFC 6749 §6 token exchange returns (cache hits emit nothing), fsynced before the proxied request bytes leave kow; it carries `binding_name`, `token_url_host`, an `outcome` (`success` or a failure class — full taxonomy in ADR-0017 §7), and cache-lifetime metadata. `refresh_token_rotated` fires when the upstream issues a *different* refresh token; it carries `binding_name`, `refresh_token_secret` (the reference name), and a write-back `outcome`. Ordering per request: `token_exchange` → `refresh_token_rotated` → `inject_decision`. Neither event ever carries a token value, old or new.

**`honeytoken_triggered` event (ADR-0019 §5).** When an `inject_decision` names a secret the operator flagged `honeytoken: true`, the writer emits a second record immediately after it (same synchronous fsync), so a fleet collector can alert on one unambiguous event type. It fires on ANY decision touching the honeytoken — `allowed` or any `denied` reason above — i.e. on any use of the planted placeholder, before any real value moves. Fields are a strict subset of the triggering event; no secret material, header, body, or query string is added.

```json
{"ts":"2026-05-17T14:32:11.345678+00:00","v":4,"type":"honeytoken_triggered","request_id":"01HXY...","binding_name":"DECOY_AWS_PROD","dest_host":"s3.amazonaws.com","underlying_reason":"destination_not_in_binding"}
```

### 4.5 BWS integration

- Dedicated BWS machine account, scoped to one Project containing only the secrets in `bindings.yaml`.
- Token at `/etc/kow/bws-token`, mode `0440 root:kow` - root owns, `kow` group reads.
- `bitwarden-sdk` Python bindings (in-process), not a shell-out.
- EU and US regions supported via explicit `api_url` / `identity_url`.
- Cache: in-memory `OrderedDict` with LRU eviction, TTL 300 s ± 30 s jitter per entry (jitter clamped to `ttl/2`). Capacity bounded by `cache.max_entries` (default 100). A backend failure is not cached (`BackendUnavailableError`): the fetch raises and the request fails closed — the placeholder forwards verbatim, no stale value is served.

### 4.6 Calling-shell environment

The canonical, copy-paste version of this block lives in [usage.md](usage.md); the version here is annotated for the threat model. The calling shell needs four things:

```bash
# Route HTTPS through the proxy
export HTTPS_PROXY="http://127.0.0.1:14322"
export HTTP_PROXY="http://127.0.0.1:14322"

# Trust the proxy CA — multiple env vars cover different client libraries
export NODE_EXTRA_CA_CERTS="/etc/kow/ca.pem"
export SSL_CERT_FILE="/etc/kow/ca.pem"
export REQUESTS_CA_BUNDLE="/etc/kow/ca.pem"
export CURL_CA_BUNDLE="/etc/kow/ca.pem"

# Bypass for loopback and any internal mesh (Tailscale, VPN, LAN peers).
# Without this, every local-service call gets sent to the proxy, denied
# or forwarded pointlessly, and breaks the legitimate caller.
export NO_PROXY="localhost,127.0.0.1,::1,*.ts.net,*.local,10.0.0.0/8,192.168.0.0/16"

# Export placeholders, NOT real values
export ANTHROPIC_API_KEY="sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
export OPENAI_API_KEY="sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
```

`NO_PROXY` semantics differ by tool. Recent curl supports CIDR; some Node libraries match by hostname substring; Python's `requests` requires explicit hosts. The combo above covers most real cases. Tailor it to your environment.

## 5. Hardening checklist

| Item | Why |
|---|---|
| `User=kow Group=kow`; bws-token `0440 root:kow` | Containment if proxy is exploited |
| `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectKernelLogs`, `ProtectHostname`, `ProtectClock` | Standard systemd sandboxing |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `NoNewPrivileges=yes` | Reduce attack surface |
| `SystemCallFilter=@system-service ~@privileged ~@resources ~@mount` | Reduce syscalls available |
| `chattr +a` on audit log | Append-only at filesystem level |
| Hash-pin all Python deps (`uv pip compile --generate-hashes`); dep updates require human review | Dominant compromise vector for Python services |
| Per-host CA generation (separate CA per machine) | Limit blast radius of proxy CA leak |
| NTP sync precondition (`timedatectl show -p NTPSynchronized`), refuse to serve if clock unsynchronized | Cache TTL math, audit timestamps, JWT validation |
| Rotate proxy CA every 6 months | Audit-logged manual ritual |
| Logrotate with `copytruncate` + `chattr -a` orchestration via privileged helper | Prevent disk-fill DoS without losing audit integrity |

**Deliberately NOT in this list:**

- `MemoryDenyWriteExecute=yes`: cffi (used by `mitmproxy` and `bitwarden-sdk`) needs W+X for callback trampolines. Documented trade-off.
- nft / iptables rules at the host level: egress policy is the operator's stack
- `kernel.unprivileged_userns_clone=0`, `kernel.yama.ptrace_scope=2`, same reason
- AppArmor for the proxy daemon - nice-to-have; the systemd sandbox is sufficient

## 6. Supply-chain controls

The proxy holds every bound secret in flight. Compromising its dependency graph is the cleanest path to all of them at once (R1). The controls below are all in force at the build, install, and update boundaries.

### 6.1 Install-time

| Control | What it does |
|---|---|
| `pip install --require-hashes -r requirements{,-dev}.lock` | Every transitive dependency (production AND dev) is pinned to a specific version AND its file hash. A registry-poisoning attack against any package in the graph fails the install. Dev deps are pinned because pytest + ruff load arbitrary Python at test time, a poisoned dev dep would execute in CI just like a poisoned prod dep would in production. |
| `pip install --only-binary :all:` | Refuses source distributions. Wheels cannot run scripts at install time by format spec: this is the Python equivalent of `npm install --ignore-scripts`. |
| `bitwarden-sdk` in-process, not shell-out | One process boundary, not two. The BWS SDK never spawns `bws` CLI on demand, so a `$PATH`-shadowing attack on the operator's shell can't substitute a hostile binary at fetch time. |

### 6.2 Lockfile regeneration

| Control | What it does |
|---|---|
| `uv pip compile --generate-hashes --exclude-newer "<7d ago>"` | Refuses any package version released in the last 7 days. Compromised releases (Shai-Hulud-style worms, account takeovers, typosquats) typically get yanked or flagged within that window. |
| Lockfile-drift CI gate | The test workflow re-compiles the lockfile in CI with the same `--exclude-newer` cutoff and fails if it doesn't match what's committed. Bypassing the cooldown requires an explicit code change to the workflow, not a quiet `uv pip compile` on someone's laptop. |

### 6.3 Build-time

| Control | What it does |
|---|---|
| Every GitHub Action SHA-pinned | Action references are pinned to commit hashes (not version tags), so a maintainer move on `@v1` cannot change CI behavior. Enforced by `pinact` in pre-commit and re-validated by `zizmor` in CI. |
| `permissions:` blocks scoped per-job | The default repo token is read-only at the top level; only the publish job gets `id-token: write` (for PyPI OIDC), only the release job gets `contents: write`. |
| `pull_request`, never `pull_request_target` | Fork PRs run in their own context with no secrets. The release workflow does not trigger on PRs at all. |
| OIDC publishing to PyPI | No long-lived API token in repo secrets. PyPI's trusted-publisher flow validates the GitHub OIDC token against the configured workflow + environment. |
| `persist-credentials: false` on every checkout | `.git/config` never contains the workflow token, so it can't end up in artifacts. |

### 6.4 Continuous

| Control | What it does |
|---|---|
| OSV-Scanner weekly + on every PR | CVE feed match against both lockfiles. Non-zero exit on findings fails the job. |
| Bandit on every PR | Python-specific SAST, catches hardcoded credentials, eval/exec, yaml.load, subprocess shell=True, weak crypto. |
| Semgrep on every PR | Pattern SAST via the `p/security-audit` + `p/python` + `p/secrets` community rulesets: covers OWASP top-10 surface, common API misuse, secret patterns. |
| TruffleHog on every PR | Full-history secret scan with `--only-verified` (active issuer-side validation). Catches credentials that slip in via rebases. |
| Zizmor on every PR | Workflow-security audit, including a self-audit of the security workflow itself. |
| `actions/dependency-review-action` on every PR | Surfaces the CVE delta a PR introduces, blocks merge on moderate-or-higher findings, and rejects AGPL/GPL deps for license-compatibility hygiene. |

### 6.5 Operational

| Control | What it does |
|---|---|
| Pre-commit hook chain | Identical lint, format, security, and pinning checks run locally before commit. Passing pre-commit means CI won't complain about the same things. |
| `dependabot.yml` (recommended for forks) | Optional but recommended: weekly check for dep updates. Updates land as PRs and run through the cooldown gate above before they can merge. |

## 7. Premortem

| # | Failure | Likelihood | Mitigation |
|---|---|---|---|
| F1 | Cache TTL too long → rotated secret stays stale | M | TTL 300 s default; admin flush command (future) |
| F2 | Cache TTL too short → BWS rate-limit during burst → 503 storms | M | TTL 300 s conservative; jitter 30 s |
| F3 | mitmproxy hot-reload imports broken addon → service degrades | M | `configure()` validation + try/except; keep old in-memory addon on error |
| F4 | SNI/Host check too strict → CDN-fronted services break | M | Per-secret `allow_sni_host_mismatch: true` escape hatch (off by default) |
| F5 | Operator adds wildcard bindings to "make it work" → defeats purpose | H | Config-load lint: warn on wildcards exceeding depth 1 |
| F6 | Audit log fills disk → `fail_on_unwritable: true` = outage | H | Logrotate + monitoring |
| F7 | CA install drifts when launcher / sandbox profile is regenerated | M | CA install + caller env in the same managed unit |
| F8 | A subprocess doesn't honor `HTTPS_PROXY` | M | Documented limitation; file upstream issues when found |
| F9 | BWS SDK has a bug that leaks secret to logs | L | Never `print()` returns; zero cache entries on eviction |
| F10 | Operator hand-writes a malformed / too-short placeholder → weak or ambiguous match | L | Fixed-format + min-length (24) + uniqueness / no-substring-overlap validation at config load; reject with clear error |
| F11 | Upstream adds cert pinning → proxy MITM fails | M | Per-secret `bypass: true` escape hatch; documented limitation |
| F12 | First OAuth need surfaces, design has no extension point | H | `inject:` block extensible; OAuth injector type can be added |
| F13 | NTP drift → cache TTL math negative, JWT validation fails | M | Startup precondition `timedatectl show -p NTPSynchronized=yes` |
| F14 | Supply-chain compromise of a Python dep → RCE at proxy UID | M-H | Hash-pinned deps + diff review (privileged operation) |
| F15 | Prompt-injection laundering through bound destination (T-1.5) | H → MITIGATED | Per-binding method/path scope |
| F16 | Operator regenerates the calling-env config, CA env vars lost → agent TLS errors → `--insecure` set | M | Caller env owned by the same config management as the daemon; periodic CA-mount healthcheck |
| F17 | Multi-machine CA cross-contamination | L-M | Per-host CA (no shared CA across deployments) |

## 8. Test plan, verifies G1–G9

| Test | Verifies |
|---|---|
| Boot proxy. Issue request with placeholder. Capture: agent core, lo tcpdump, egress tcpdump, audit log. | G1, G2, G6, G7 |
| Modify agent to send `CONNECT api.anthropic.com:443` then `Host: evil.com` inside tunnel | G3 |
| Send placeholder to a host bound to a *different* secret | G5 |
| Stop BWS / break BWS token / make audit unwritable | G4 |
| Rotate secret in BWS, observe stale until TTL, fresh after | G8 |
| `kill -9` proxy mid-session, restart, verify audit log integrity + `proxy_restart` event | G9 |
| From a non-proxy-configured shell, attempt to use proxy directly → TLS verify must fail | G7 |

The pytest suite covers config validation, addon hooks, BWS client behavior, and the scope-matching logic. Run `pytest` to execute it.

### 8.1 Policy regression fixtures + the `decide()` core — ADR-0013

The verdict taxonomy in §4.4 is computed by a pure function `decide(...) -> Decision` in
`policy.py` — the single source of truth for an `inject_decision`'s `decision` / `reason` /
`secret_name` / slot. It takes the config plus the request facts (host, port, method, path,
CONNECT host, a header accessor) and does no I/O and no flow mutation; the addon EXECUTES the
returned `Decision` (fetch, render, inject, and the G6-ordered audit). Each fixture asserts an
expected decision against this verdict.

- **Fixtures** are spec-derived YAML under `tests/fixtures/policy/`, each pinning the `T-`/`G-` id
  it guards (a fixture is an executable threat-model assertion). They assert
  `{decision, reason, secret_name, injected}`; composite / multi / body cases additionally snapshot
  the `rendered:` output computed from fixed fake static-backend values. Fixtures are **not**
  recorded from the audit log — §4.4 audit minimization omits the raw request, so record-replay is
  structurally impossible; declarative also avoids locking in buggy captured behavior.
- **Two test surfaces, one engine:** `pytest` runs the fixtures through the live addon
  (`test_policy_fixtures.py`), and a parity test (`test_policy_decide.py`) runs every fixture
  through BOTH the addon and `decide()` directly, asserting the verdicts agree. An operator-facing
  `kow test` / `kow validate` CLI over the same engine is planned, not yet shipped.
- **Test-mode invariants:** static backend only (BWS backend uninstantiable — no real secret in the
  process), clock pinned, jitter off, `ts`/`request_id` excluded from the compared record.
- **Scope:** fixtures + `decide()` own policy correctness; transport + `inject_decision` fsync ordering
  (G2/G6) stay with the docker-e2e + smoke layers, with one e2e smoke retained per injector type.
  The addon's live path delegates to `decide()` behind the parity test — see ADR-0013.

## 9. Rollback

Three independent dimensions:

1. **Stop the service.** `sudo systemctl stop kow`. With env-var-only routing, the agent's outbound TLS will fail (connection refused on loopback). Restart to recover.
2. **Unset proxy env.** Clear `HTTPS_PROXY` / `NO_PROXY` / CA env vars in the calling shell. The agent reverts to direct egress (subject to whatever the host firewall says).
3. **Full teardown.** Remove the systemd unit, `/opt/kow`, `/etc/kow`. Preserve `/var/log/kow/audit.jsonl` for forensics.

Because there's no kernel egress lock to "leave on," the rollback model is simple.

## 10. Open questions

- **AWS access:** SigV4 shipped as `inject.type: sigv4` (ADR-0027; S3 `x-amz-content-sha256` + client `x-amz-*` header signing hardened in ADR-0036). Still open: STS-scoped signing so the proxy holds short-lived, downscoped credentials instead of a static key (ADR-0036 Phase 2).
- **gh CLI OAuth path:** OAuth refresh tokens land in `~/.config/gh/hosts.yml`. The `oauth2_refresh` injector (ADR-0017) covers the grant itself; wiring gh's device-flow tokens through it is still open.
- **Admin port form factor:** Unix socket, filesystem-touch protocol, or local-MCP server? Deferred to burn-in feedback.

## 11. Out of scope (re-stated)

- Host root resistance
- Same-UID attacker resistance (proxy UID is the new vault; intentionally accepted)
- **Egress filtering / kernel-level network policy**: the host's firewall handles this
- Streaming/chunked SigV4 payloads, presigned-URL flows, and SigV4a (ECDSA multi-region) — request signing itself shipped (`sigv4` / `hmac` / `jwt_bearer`); these specific modes are deliberately not served, to keep the "agent never holds any AWS credential" invariant (ADR-0036)
- K8s deployment (single-host design)
- Cross-agent multi-tenancy
- DNS spoofing defense
- Side-channel resistance
- Application-layer secret leakage in upstream responses

## 12. Accepted residual risks

**R1 [HIGH] - Supply chain to proxy UID = total compromise of all bound secrets.**
Mitigation: hash-pinned deps + human-reviewed dep updates. Stronger mitigation (future): out-of-process BWS broker on a separate host. The operator must accept this before deploy.

**R2 [HIGH → MITIGATED], Laundering through bound destinations.**
Originally HIGH. Closed by per-binding method/path scope. Bindings may declare optional `methods: [GET, …]` and `paths: ["/repos/*"]`; out-of-scope requests have their placeholder forwarded verbatim (G5 preserved) and emit a `binding_scope_violation` audit event.

**R3 [MED] - G5 omission leaks placeholder format / agent intent to attacker-controlled destinations** (only if a binding is loose, e.g., `*.s3.amazonaws.com` covering attacker buckets). Future mitigation: per-deployment placeholder randomization (HMAC of secret name with per-host key).

**R4 [MED], Off-host vault is partial mitigation, not magic.** Even with a separate host serving BWS, an attacker with host-root on the proxy host can exfil during normal operation. Off-host adds physical separation but doesn't defend against in-band exfil.

**R5 [MED], Operational maintenance load is real.** Hash-pinned deps need periodic refresh; CA rotation is manual; audit log monitoring is the operator's responsibility.

**R6 [MED]: Response-side echo can leak the real secret back to the agent.** kow injects the real credential on the *request* side and returns the upstream response to the agent unmodified. If an upstream endpoint reflects the `Authorization` header (or the request body containing it) in its *response*, debug `/echo` endpoints, verbose 5xx error envelopes, certain SDK request-tracing modes - the agent receives the real secret in the response and the isolation collapses for that exchange. Mitigation: prefer well-behaved upstreams (production-grade APIs from major vendors don't reflect auth headers); operator-side response sanitization at a higher layer if a reflecting endpoint is unavoidable. Out of scope for the proxy itself, response scrubbing requires per-endpoint knowledge of what the response might contain and would add a complex, fail-open path right next to the injection point.

## 13. Deployment lessons learned

Things that turned out non-obvious in real deploys. Recorded for whoever picks this up next.

1. **Fixed system user beats `DynamicUser=yes`.** Dynamic UIDs can't read a fixed-path `0440 root` token file without `LoadCredential=`, which would require addon-side code changes. `User=kow` is simpler.

2. **`MemoryDenyWriteExecute=yes` breaks cffi.** Both `mitmproxy` and `bitwarden-sdk` use cffi for callback trampolines; cffi needs W+X memory. Symptom: `MemoryError: Cannot allocate write+execute memory for ffi.callback()` in the journal. Remove the directive.

3. **`HOME` matters more than you'd think.** mitmproxy generates its CA at `$HOME/.mitmproxy/mitmproxy-ca-cert.pem` on first proxied request. With `ProtectHome=yes` and no explicit `Environment=HOME=`, the daemon has nowhere writable to put the CA. Set `Environment=HOME=/var/lib/kow` so the CA lands in a `ReadWritePaths` location.

4. **EU vs US Bitwarden regions need explicit URLs.** Default SDK behavior targets `.com`; EU users get auth failures with no clear error. Add `api_url` + `identity_url` overrides in `bindings.yaml`.

5. **`*.claude.com` is a real domain.** Anthropic routes Claude Code traffic through subdomains of `claude.com`. Without `*.claude.com` in the `ANTHROPIC_API_KEY` binding, the CLI fails to start with no useful error message.

6. **`mcp-proxy.anthropic.com` is the cloud-MCP gateway.** Gmail/Calendar/Drive MCPs route through this host. Same Bearer token as the main API. Add to the `ANTHROPIC_API_KEY` binding if you want cloud MCPs to work.

7. **`NO_PROXY` semantics differ by tool.** Recent curl supports CIDR; some Node libraries match by hostname substring; Python's `requests` requires explicit hosts. A safe combo: `localhost,127.0.0.1,::1` plus your internal mesh's domains and CIDRs.

8. **mitmproxy `-s` script loading uses a synthetic module name.** Relative imports (`from .audit import …`) in the addon fail with `ModuleNotFoundError: No module named '__mitmproxy_script__'`. Use absolute imports (`from kow.audit import …`) throughout.

9. **`pip install $REPO` is a no-op when the version is unchanged.** Add `--force-reinstall --no-deps` to deploy scripts so code edits in the repo actually land in the installed venv on re-run.

10. **`systemctl enable --now` is a no-op when the service is already running.** Re-runs that change the unit file need an explicit `systemctl restart` to pick up the new unit.

11. **`chattr +a` blocks `chown` / `chmod`.** First-run sequence is `touch; chown; chmod; chattr +a`. Re-run sequence is `chattr -a; chown; chmod; chattr +a`. Idempotent scripts must strip `+a` before modifying.
