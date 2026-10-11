# NoteSchema — the annotation format + auth-pattern catalog

The binding lives in a secret's per-backend metadata: BWS **Notes** field, GSM **`kow-binding`** annotation, or the equivalent on a future backend. The parser is backend-agnostic.

**Marker line (ADR-0025):** a note/annotation is parsed as a binding **only when its first non-blank line is exactly `# kow-binding`**. That line is stripped; the remainder parses under the grammar below. Unmarked metadata is a human description → ignored (a host-shaped unmarked note logs a load-time warning); a marked note with an empty or non-hostname body fails loud. Every note example below leads with the marker; the config-file-source blocks do not (they are not notes).

## Allowed keys (flat YAML)

Exactly these, any others are a typo and fail closed:

| Key | Meaning | Default |
|-----|---------|---------|
| `host` | hostname the credential is sent to — a single string **or a list** (`hosts:` alias also accepted) | required |
| `placeholder` | exact sentinel the consumer emits (ADR-0029) — minted by `kow binding new`, format `avp-PLACEHOLDER-` + 21–64 lowercase-base32 chars; wins over salt derivation; uniqueness enforced fail-closed at resolve | salt-derived |
| `header` | HTTP header to inject into | `Authorization` |
| `format` | header value template; MUST contain `{secret}` | `Bearer {secret}` |
| `methods` | list of HTTP methods to bind (scope) | all — but **always write it explicitly**, see AddSecret §1.4 |
| `paths` | list of URL path globs to bind (scope) | all |

`{secret}` is the only substitution token — the note has no name key because the secret *is* the value. Bare-host shorthand: after the `# kow-binding` marker line, a note of just `host: api.example.com` uses the header/format defaults.

> ### ⚠ A note can only inject a static value into a HEADER. That is not all kow does.
>
> The keys above are the **whole** note grammar (`_ALLOWED_NOTE_KEYS` in `notes_binding.py`), and an unknown key fails closed. There is no `inject:` or `type:` key, so **no injector type is expressible as a note**. Reading this table as the product's full capability is a documented failure mode: a session once concluded kow "cannot broker OAuth2 client-credentials at all" and reported a gap the product does not have.
>
> kow ships **ten injector types**; notes cover the first one only:
>
> | Injector | What it does | Source |
> |---|---|---|
> | static header | substitute a secret into a header | **note** or file |
> | `body` | streaming placeholder replacement **inside the request body**, optional `content_type` filter | file only |
> | `oauth2_client_credentials` | exchanges a vault-held client id + secret for an access token, injects it | file only |
> | `oauth2_refresh` | refresh-token grant, with rotation write-back | file only |
> | `github_app` | App JWT → installation access token | file only |
> | `sigv4` / `hmac` / `jwt_bearer` | request signing | file only |
> | `gcp_service_account` | mints a Google access token by impersonation; declares authority rather than forwarding a held secret | file only |
> | `multi` | several of the above on one request | file only |
>
> **Decision rule.** Anything needing *two secrets*, a *token URL*, a *signature*, or injection somewhere other than a header is **config-file source**. Check `bindings.example.yaml` and `config_models.py` before declaring a credential unbrokerable.
>
> **Precedence trap.** With `binding_source: both` a note **wins over** a file binding for the same secret, so a leftover note silently disables the file-source injector you just wrote. Delete the note when migrating a secret from note to file source.

## Two-part credentials — probe the upstream BEFORE designing the binding

A note holds ONE secret and injects into a header, so a two-part credential (OAuth2 `client_id` + `client_secret`, `email:token`, key-pairs) is notes-expressible **only if the upstream accepts both parts pre-encoded into a single header value** — in practice, HTTP Basic.

RFC 6749 §2.3.1 says authorization servers MUST support Basic. **That is not evidence that a given server does.** One provider's token endpoint ignores the `Authorization` header entirely and answers `400 "client_id was not specified"`; a notes-only Basic binding was authored on the RFC's authority and was inert.

Probe with **fake** credentials — you never need the real secret to settle the shape:

```bash
curl -sS -X POST https://<host>/<token-path> \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=probe-fake-id&client_secret=probe-fake-secret'
```

Read the error *class*, not the status code:

| Response | Meaning | Route |
|---|---|---|
| Names a **missing parameter** | The server never parsed that location. | Try the other location. |
| Names **bad credentials** | It parsed them and rejected the values. | That location works. |
| A `200` | Should be impossible with FAKE credentials. | Stop and investigate the endpoint, not the binding. Only a probe with REAL credentials can confirm Basic issues a token. |

When the parts must reach the **body**, use a file-source `body` injector. Two things to decide deliberately:

- **`content_type` trades one failure mode for another.** Setting it means a mismatch forwards the body unmodified — a silent no-op that reads as "kow isn't injecting". Leaving it unset removes that trap but genuinely **widens** which requests can receive the secret, so unset is not "tighter" in a security sense. Unset suits an upstream accepting several encodings when `methods` + `paths` already pin the request; set it when you know the one content type. (Injection is also placeholder-triggered, so a request carrying no sentinel is never a candidate either way — but that is a separate gate, not a substitute for scope.)
- **Substitution is byte-for-byte and format-blind.** kow does not escape the secret for JSON, form or multipart syntax, so a value containing a quote, backslash or ampersand can produce a malformed body in one encoding while working in another.

## Auth-pattern catalog

**Bearer** (most APIs):
```yaml
# kow-binding
host: api.example.com
header: Authorization
format: "Bearer {secret}"
```

**`token` scheme** (some git/forge APIs):
```yaml
# kow-binding
host: api.example.com
format: "token {secret}"
```

**Custom header / X-API-Key**:
```yaml
# kow-binding
host: api.example.com
header: X-API-Key
format: "{secret}"
```

**Basic (single pre-encoded secret)** — store `base64("user:pass")` as the secret value:
```yaml
# kow-binding
host: api.example.com
header: Authorization
format: "Basic {secret}"
```

**Composite Basic (`email:token` from two secrets)** — NOT expressible in a note (a note holds one secret). Use the kow **config file source** with `compose:` + `inject_template`, e.g.:
```yaml
# config file source only — not a note
EXAMPLE_API_BASIC:
  placeholder: "ex_PLACEHOLDER_0000000000"
  inject_header: "Authorization"
  inject_template: "Basic {{ (EXAMPLE_EMAIL + ':' + EXAMPLE_TOKEN) | b64encode }}"
  compose: [EXAMPLE_EMAIL, EXAMPLE_TOKEN]
  bindings:
    - host: api.example.com
```

**Scoped (narrow blast radius)**:
```yaml
# kow-binding
host: api.example.com
header: Authorization
format: "Bearer {secret}"
methods: [GET, POST]
paths: ["/v1/**"]
```

## Multi-host credentials

`host` accepts a single hostname **or a list** (a `hosts:` alias also works); a list fans out to
one binding per host under a single injector. Use it for a token that spans several hosts:

```yaml
# kow-binding
host:
  - api.example.com
  - cdn.example.com
format: "Bearer {secret}"     # REQUIRED for a multi-host list — see rules
```

A list of **>1 host fails closed unless**:
- **explicit `format`** — the bare-Bearer default is never applied silently across hosts;
- **no curated host** in the list — a host with built-in defaults (`api.github.com` GET-only,
  Anthropic `x-api-key` + version header, Linear, etc.) must bind in its own single-host note;
- **no wildcard element** — a `*.suffix` inside a list is rejected (bind a wildcard on its own).

`methods`/`paths` apply **uniformly** to every host. For per-host scope, or to mix in a curated
host, use the **file source** (its `bindings:` list is per-host) or separate notes:
```yaml
# file source only — per-host scope / curated hosts
EXAMPLE_TOKEN:
  placeholder: "ex_PLACEHOLDER_0000000000"
  inject_header: "Authorization"
  inject_format: "Bearer {EXAMPLE_TOKEN}"
  bindings:
    - host: api.example.com
    - host: cdn.example.com
```

**Note the download-host caveat:** for model/file *downloads* (e.g. HuggingFace), the bytes flow
over the LFS/CDN hosts (`cdn-lfs.huggingface.co`, `cas-bridge.xethub.hf.co`) — NOT
`api-inference` / `datasets-server`. Bind the hosts the traffic actually uses.

## Gotchas (detail)

- **Fail-closed:** no annotation ⇒ never injected. Silent "auth didn't happen" almost always means the note didn't parse (wrong key, bad YAML).
- **Placeholder: stored wins over derived (ADR-0029).** A note may pin its placeholder via the `placeholder:` key — always minted by `kow binding new`, never hand-typed (the format gate rejects anything but `avp-PLACEHOLDER-` + ≥21 lowercase-base32 chars, so weak strings can't parse). Without the key kow derives from the per-install salt and the consumer must discover the value via `kow env`. Collisions (equal or substring-overlapping) fail closed at resolve with thief-loses semantics — a note claiming a derived- or file-placeholder secret's placeholder unbinds only itself; two stored claimants of the same string both drop; every drop is audited with both names.
- **`both` precedence:** notes win over file for the same secret; file-only bindings may be dropped under `both` unless pinned `:file`.
- **Wildcard hosts** require `allow_wildcard_hosts` opt-in; keep hosts exact otherwise.
- **Annotation-trust (ADR-0018):** metadata-write must be locked to the value-read trust tier — a metadata-only writer can redirect the credential (confused-deputy). `kow doctor` warns.
- **Deployed vs repo version:** notes support and schema evolve; if a note won't activate, check the running daemon version, not just the docs.
