# Troubleshooting — "kow isn't injecting"

The audit answers this. Read it before forming a theory about the note, the marker, the encoding or
the placeholder. A 2026-09-06 investigation spent eleven rounds re-examining a binding that was
perfect, because nobody asked the audit what it saw.

```bash
sudo grep -i <host-fragment> /var/log/agent-vault-proxy/audit.jsonl \
  | jq -c '{type, decision, reason, secret_name, destination}' | tail -20
```

## What the audit can say

| What you see for the host | What it means | Where to look next |
|---|---|---|
| `inject_decision` · `binding_matched` | **Injection works.** The binding is fine. | The upstream rejected the credential, or you are reading the wrong request. |
| `inject_decision` · `secret_unavailable:SecretNotFoundError` | **Routing matched; the NAME did not resolve.** kow matched host, method and path, then found no secret under the configured name. | Two possibilities, and the audit cannot tell them apart: the secret genuinely does not exist yet, or the binding names it wrongly (typo, or the wrong vault/project). Compare `secret_name` in the audit against the vault before creating anything. If the name is right, create the secret — no config change and no restart, since secrets resolve per request. |
| `inject_decision` · `secret_unavailable:BackendUnavailableError` | Binding correct, vault unreachable. | Backend credentials/network, not the binding. |
| `inject_decision` · `secret_fetch_error:<Exception>` | An *unexpected* backend exception. Deliberately a distinct reason so this class can be grepped apart from the ordinary "missing/unreachable" one. | A bug, in kow or the backend adapter. |
| `inject_decision` · `render_failed` / `header_control_characters` | Binding matched; the rendered value was rejected. | The `format`/`template`, or a secret containing control characters. |
| `tls_passthrough` · `unbound_destination` | The host is genuinely unbound. | The note is missing, unmarked, or names a different host. |
| `inject_decision` · any other `reason` | Binding seen, injection refused for a reason not listed above (`binding_scope_violation`, `destination_not_in_binding`, `ambiguous_placeholder_match`, `sni_host_mismatch`, `invalid_binding_metadata`, the `composite_*` family…). | The `reason` string names the cause — read it, don't guess. Treat this row as the catch-all: the set grows, so a reason missing from this table is not a reason to improvise. |
| **Host absent from the audit entirely** | **Probably** the request never reached kow. | Client side first: `NO_PROXY`, or a process that never inherited `HTTPS_PROXY`. Before concluding that, rule out the boring alternatives — wrong instance, wrong time window, log rotation, or a failed audit write. A TLS failure occurring before any host-bearing event is logged also leaves no trace. |

**Absence is not passthrough.** A tunnelled connection *logs* a `tls_passthrough` naming the host,
so "the host never appears" rules the passthrough theory out rather than supporting it.

## Fail-closed signatures: the same failure looks different per injector

kow never forwards a placeholder verbatim when a secret cannot be fetched (invariant G6). But what
the *upstream* subsequently sees depends on which injector was bound, and each shape gets
misread as a different bug:

| Injector | Client-visible behaviour on a missing secret |
|---|---|
| **header** | kow answers the client itself with **`503`**. The request never leaves the proxy. |
| **body** | The request IS sent, with a body **truncated at the point of failure**. |

The body case is the confusing one, and the truncation detail matters. The replacer streams: each
call emits the processed prefix and holds back a short tail, so **chunks already emitted before the
failing chunk have gone upstream**. After the failure every later chunk returns `b""`. For a small
body that fits one buffer — a typical OAuth2 token request — nothing was emitted yet, so the
upstream sees an **empty** body. For a large multi-chunk body it sees a **prefix**. Either way it is
not the placeholder, which is the invariant that matters.

A truncated or empty body makes the upstream complain that its *first
required field* is missing. A real example: an OAuth2 client-credentials token request came back
`400 {"code":"invalid_request","message":"grant_type was not specified"}` even though the client
had plainly sent `grant_type`. That is not body corruption and not the upstream rejecting the
sentinel — it is `injectors/body.py` failing closed, exactly as designed. The audit line beside it
read `secret_unavailable:SecretNotFoundError`.

**So: an upstream 4xx naming a missing first field, next to a `secret_unavailable` denial, means
create the secret. It does not mean rewrite the binding.**

## You often cannot run a "bypass the proxy" control

The instinct on a confusing upstream error is to re-send the request without the proxy and compare.
On a host configured for kow this control is usually invalid, and silently so:

- `HTTPS_PROXY`/`HTTP_PROXY` are typically exported environment-wide, so `curl` **without** `-x`
  still goes through kow. Two "different" requests are then the same request.
- Strip the proxy variables and a locked-down host may have no direct egress at all, returning
  `HTTP 000`.

A 2026-09-22 session compared proxied against "unproxied", got byte-identical responses, and
concluded the upstream was at fault. Both had been proxied. **The audit is the control.** If you do
need a true bypass, prove it — check `env | grep -i proxy` and confirm the connection log shows no
`Establishing HTTP proxy tunnel`.

## Testing a binding at all

kow substitutes only where a known placeholder **appears in the request you send**. An
unauthenticated request through the proxy is forwarded untouched and comes back anonymous; that is
the design working, not a broken binding. Always send the placeholder in the test:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  --proxy http://127.0.0.1:14322 --cacert /etc/agent-vault-proxy/ca.pem \
  -H "Authorization: Bearer <THE-PLACEHOLDER>" https://<host>/<path>
```

## Two-part credentials: probe the upstream before designing the binding

A note holds one secret and injects a static value into a **header**. A two-part credential
(OAuth2 `client_id` + `client_secret`) is therefore notes-expressible only if the upstream accepts
both parts pre-encoded into one header — in practice, HTTP Basic. RFC 6749 §2.3.1 says
authorization servers MUST support Basic; that is not evidence that a given server does.

Probe it with **fake** credentials — you never need the real secret to settle the shape:

```bash
curl -sS -X POST https://<host>/<token-path> \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&client_id=probe-fake-id&client_secret=probe-fake-secret'
```

Read the error *class*, not the status code:

| Response | Meaning | Route |
|---|---|---|
| Names a **missing parameter** | The server never parsed that location. | Try the other location. |
| Names **bad credentials** | It parsed them and rejected the values, so that location IS read. | Build the binding for that location. |

A `200` is not an outcome here: fake credentials must never authenticate. If one does, stop and
investigate the endpoint rather than the binding.

**The probe narrows the shape; it does not prove it.** A server may return a generic authentication
failure for both cases, validate fields in an order that hides the distinction, or reject an unknown
client before ever looking at its secret. Confirm against the provider's documented auth methods,
and confirm the response came from the endpoint you meant — on a proxy-configured host, see the
invalid-control warning above.

### Worked example — a body-source binding (verified live against a real provider)

Some OAuth2 servers ignore the `Authorization` header entirely and require the credentials in the
request body, so no header-injecting binding — and therefore no note — can satisfy them. The working
shape is a file-source `body` injector:

```yaml
  PROVIDER_CLIENT_SECRET:
    placeholder: "kow-PLACEHOLDER-<minted, never hand-typed>"
    inject:
      type: body
      format: "{PROVIDER_CLIENT_SECRET}"
    bindings:
      - host: "api.example.com"
        methods: ["POST"]
        paths: ["/v1/oauth2/token"]
```

The client sends the public `client_id` inline and the placeholder where `client_secret` goes; kow
substitutes it in the body in flight. Two design notes that generalise:

- **`content_type` trades one failure mode for another; pick deliberately.** Setting it means a
  mismatch forwards the body *unmodified* — a silent no-op that reads as "kow isn't injecting".
  Leaving it unset removes that trap but genuinely **widens** which requests can receive the secret,
  so it is not the "tighter" option in a security sense. Unset is reasonable when the upstream
  accepts several encodings and `methods` + `paths` already pin the request; set it when you know
  the single content type and want the narrower blast radius.
- **Substitution is byte-for-byte and format-blind.** kow replaces the placeholder with the raw
  secret and does not escape it for JSON, form or multipart syntax. A secret containing a quote,
  backslash or ampersand can therefore produce a malformed body in one encoding while working in
  another. Prefer placeholders in positions where the raw value is already legal.
- **Scope is not the only gate.** Injection is placeholder-triggered, so a request to the same path
  that carries no sentinel is never a candidate in the first place.

## Migrating a secret from note source to file source

Under `binding_source: both` a marked **note wins over** a file binding for the same secret. A
leftover note therefore silently disables the file-source injector that replaced it. Delete the note
as part of the migration, not afterwards.

## The module was renamed (ADR-0045)

The import path is `kow.*`. `agent_vault_proxy.*` is gone — verified absent in both 1.0.0 and 1.2.0. External
health checks, config validators and deploy tooling that still import the old path fail with
`ModuleNotFoundError` — one such stale validator silently blocked config deploys for weeks. The
current config-validation one-liner is:

```bash
<venv>/bin/python -c "import sys; from kow.config import load_config; load_config(sys.argv[1])" <path>
```
