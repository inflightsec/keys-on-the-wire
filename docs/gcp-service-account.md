# Google service accounts

Give an application the authority of a Google service account without giving it
the service account. Design: [ADR-0050](adrs/ADR-0050-gcp-service-account-credentials.md).

There are two halves. The **injector** mints the real credential and puts it on
the upstream request. The **credential endpoint** is how an ordinary application
finds a credential at all, since Google client libraries, `gcloud` and Terraform
resolve Application Default Credentials before they build a request.

Use both together and an app that has never seen a key authenticates as a service
account, while the only thing inside its process is a placeholder.

## The short version

Let the tool write it. One command produces the config block, tells you what (if
anything) goes in the vault, and prints the consumer wiring:

```bash
kow binding gcp \
  --target agent-runner@my-project.iam.gserviceaccount.com \
  --host bigquery.googleapis.com \
  --scope bigquery.readonly \
  --methods GET,POST \
  --project my-project
#   stdout → the bindings.yaml block below, with a freshly minted placeholder
#   stderr → the vault instruction + the four environment variables the app needs
```

The block is validated through the daemon's own config model before it prints, so
it cannot emit something the daemon would reject.

### Why this one lives in the config file, not a vault note

Every other kow secret is added entirely in the vault: value plus a `kow-binding`
note, no config edit — and a note **can** declare a binding for a host that appears
nowhere in `bindings.yaml`. That is the zero-config model working as intended.
(An earlier revision of this page said notes may only *narrow* an existing binding
and cited [ADR-0024](adrs/ADR-0024-notes-host-allowlist.md). That was wrong on both
counts: `notes_host_allowlist` is **opt-in and absent by default**, and ADR-0024 §1
states that with it unset the behaviour is byte-identical to no restriction.)

The actual limit is narrower: a note can only express the **plain header injector**,
because `notes_binding.py` emits `inject: {type: header, …}` and accepts only the keys
`host`/`hosts`, `header`, `format`, `methods`, `paths`, `placeholder`. So
`gcp_service_account` (like `oauth2_refresh`, `sigv4` and `github_app` before it)
lives in `bindings.yaml`.

**Why that limit survives the obvious objection.** It is tempting to argue that anyone
who can write a secret's metadata could have written the secret itself, so gating the
binding buys nothing — and for a *header* binding that is largely true. ADR-0024 says
as much: the confused-deputy risk "is not exploitable on BWS (which does not separate
note-write from value-read) and is moot in a single-operator project". The asymmetry
is not about who holds which permission; it is about what the binding is bounded by. A
header injector can only ever misdirect the one secret it names. A **minting** injector
need not name a secret at all: `gcp_service_account` in `impersonate` mode with
`source: adc` mints from the daemon's own identity, so there is no secret whose
creation implied the authority. Note-write alone would become the power to mint
credentials for every principal the daemon can impersonate.

What the tool produces:

```yaml
secrets:
  GCP:
    # Shaped like a Google token: some SDKs check the prefix before using one.
    placeholder: "ya29.kow-PLACEHOLDER-ypf2d5fn4uvibadxuebtyutdpm"
    inject:
      type: gcp_service_account
      mode: impersonate                 # default: no key exists anywhere
      service_account_email: agent-runner@my-project.iam.gserviceaccount.com
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
    bindings:
      - host: bigquery.googleapis.com

credential_endpoint:
  enabled: true
  binding: GCP
  service_account_email: agent-runner@my-project.iam.gserviceaccount.com
  project_id: my-project
```

Then point the application's ADC at it:

```bash
export GCE_METADATA_HOST=127.0.0.1:14380   # Go, Node, .NET, Java, gcloud
export GCE_METADATA_IP=127.0.0.1:14380     # additionally required by Python
export GCE_METADATA_ROOT=127.0.0.1:14380   # additionally read by gcloud
export HTTPS_PROXY=http://127.0.0.1:14322  # the kow proxy itself
```

## The three modes

| `mode` | Key required | Network calls | Use when |
|---|---|---|---|
| `impersonate` (default) | **none** | one, to `iamcredentials.googleapis.com` | the daemon has a Google identity. This is the recommended posture. |
| `jwt_bearer_grant` | service-account key in the vault | one, to `oauth2.googleapis.com` | the daemon has no Google identity to mint from |
| `self_signed_jwt` | service-account key in the vault | **none** | the target API accepts a self-signed assertion and you want zero egress |

### Which backend can hold the key

Only relevant to the two key-bearing modes, and it is a hard constraint rather
than a preference:

| Backend | Can hold a service-account PEM? |
|---|---|
| Bitwarden Secrets Manager, Google Secret Manager, AWS Secrets Manager | yes |
| static file | yes |
| **macOS Keychain**, default (`use_helper: off`) | **no** |
| **macOS Keychain** with `use_helper: require` | yes |

By default the Keychain backend refuses any value containing a newline, because
the `security -i` line protocol it writes through would truncate at the first one
and store a prefix of the key. Refusing is the right call: a silently shortened
signing key produces assertions that fail at Google with an error pointing
nowhere near the cause. A PEM is ~28 lines, so it is refused at the API boundary
before any child process runs.

That is a property of the transmit path, not of the Keychain. Setting
`use_helper: require` routes the backend through the signed `kow-keyd` helper,
which passes the value as raw bytes on stdin, and a PEM stores fine. It costs a
build step, a `sudo install`, and re-adding any secrets you already hold — see
[keychain-helper.md](keychain-helper.md).

**Prefer that over reaching for `source: adc` on a workstation.** It is tempting
to read "no key at all" as the safer answer, and on a Mac laptop it is usually the
opposite. `google.auth.default()` resolves ADC to
`~/.config/gcloud/application_default_credentials.json` — a plaintext file holding
a long-lived **user** refresh token, readable by any process running as you, and
carrying your own identity rather than one service account's narrow mint rights.
A seat key in the Keychain is a smaller credential than that, and it is not
sitting in a dotfile. `source: adc` is the right answer where the daemon runs on
GCE, GKE or Cloud Run and ADC resolves to the metadata server, or where it is a
federation config — there, no key exists anywhere.

### `impersonate`

kow calls `generateAccessToken` on the target service account using its own
identity. No key is created for the target at all, which is what Google's own
guidance asks for.

The source identity comes from one of two places:

```yaml
      mode: impersonate
      source: adc            # the daemon's Application Default Credentials
```

```yaml
      mode: impersonate
      source: seat_key       # a dedicated impersonation seat held in the vault
      source_service_account_email: kow-seat@my-project.iam.gserviceaccount.com
      private_key_secret: GCP_SEAT_KEY
```

Grant the source the right to mint for each target, and nothing else:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  agent-runner@my-project.iam.gserviceaccount.com \
  --member="serviceAccount:kow-seat@my-project.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

**Say the honest thing out loud:** on a host that is not itself on Google
infrastructure, the seat's own credential is one long-lived artefact that has to
exist somewhere. It lives in your vault, never on an agent host, and it carries
no data access of its own — a thief who takes it gains exactly the mint rights
you granted above. That is a much smaller blast radius than a key per
application, but it is not zero, and calling this setup "keyless" would be a lie.

### `jwt_bearer_grant`

Signs an RFC 7523 assertion with a vault-held key and exchanges it for an access
token. Covers the whole Google API surface.

```yaml
      mode: jwt_bearer_grant
      service_account_email: agent-runner@my-project.iam.gserviceaccount.com
      private_key_secret: GCP_SA_KEY     # the PEM from the key JSON, in the vault
      scopes: "https://www.googleapis.com/auth/bigquery.readonly"
```

Store the `private_key` value from the downloaded JSON, not the whole file.

Domain-wide delegation (acting as a user in a Workspace domain) needs `subject:`
plus an explicit `allow_domain_wide_delegation: true`. It is gated because one
such binding can act as *any* user in the domain.

### `self_signed_jwt`

The signed assertion is the credential; there is no token endpoint call at all.
Only some Google APIs accept this, so verify against the API you actually use.

```yaml
      mode: self_signed_jwt
      service_account_email: agent-runner@my-project.iam.gserviceaccount.com
      private_key_secret: GCP_SA_KEY
      audience: "https://bigquery.googleapis.com/"
```

## The credential endpoint

`credential_endpoint:` runs a loopback listener that answers the Compute Engine
metadata protocol, so ADC-based clients believe they are on a Google VM.

**It never returns a usable credential.** The `access_token` it serves is the
binding's placeholder; the injector substitutes the real token on egress. A
placeholder scraped off that port is inert anywhere else, and on-box it is still
subject to the binding's host, method and path scope. That property is what makes
an unauthenticated local listener acceptable, and it is why the endpoint must
never be changed to serve a real token.

```yaml
credential_endpoint:
  enabled: true
  host: 127.0.0.1       # loopback only; anything else is refused at config load
  port: 14380
  binding: GCP          # whose placeholder to serve
  service_account_email: agent-runner@my-project.iam.gserviceaccount.com
  project_id: my-project
  scopes: "https://www.googleapis.com/auth/bigquery.readonly"
  expires_in_seconds: 3600
```

Check it by hand:

```bash
curl -H "Metadata-Flavor: Google" \
  http://127.0.0.1:14380/computeMetadata/v1/instance/service-accounts/default/token
# {"access_token": "ya29.kow-PLACEHOLDER-ypf2d5fn4uvibadxuebtyutdpm", "expires_in": 3600, ...}
```

A request without the `Metadata-Flavor: Google` header gets a 403, the same as
the real metadata server.

### Verify it on your machine

Three checks, cheapest first. The first two need no GCP project.

```bash
# 1. The endpoint answers, and answers with a placeholder.
curl -s -H "Metadata-Flavor: Google" \
  http://127.0.0.1:14380/computeMetadata/v1/instance/service-accounts/default/token

# 2. A real Google SDK accepts it. This is the check that proves the probe-path
#    set is right, because google-auth asks for what it actually needs.
export GCE_METADATA_HOST=127.0.0.1:14380 GCE_METADATA_IP=127.0.0.1:14380
python -c "
import google.auth, google.auth.transport.requests
creds, project = google.auth.default()
creds.refresh(google.auth.transport.requests.Request())
print('token:', creds.token, '| project:', project)
"
# Expect the placeholder back. If it prints one, every ADC client works.

# 3. End to end against a real API, through the proxy.
export HTTPS_PROXY=http://127.0.0.1:14322
python -c "
from google.cloud import bigquery
print([d.dataset_id for d in bigquery.Client().list_datasets()])
"
# A result means the placeholder was substituted for a token minted by
# impersonation, and the process never held a service-account credential.
```

For `gcloud`, add `export GCE_METADATA_ROOT=127.0.0.1:14380` and try
`gcloud auth application-default print-access-token`.

### Known limits

- **Every local process can ask, and the placeholder is a capability.** The
  endpoint authenticates nobody, exactly like the real metadata server. Be precise
  about what that costs: the placeholder is not a credential (it is worthless off
  this host), but through kow it *is* an on-box bearer capability — any local
  process that fetches it can make authenticated Google calls within the binding's
  host, method and path scope. This narrows credential *theft* to zero while
  leaving credential *use* open to the host. If that matters, put kow and the agent
  in a shared network namespace or container so "the host" means "the sandbox";
  loopback plus placeholders is not an authentication boundary and this document
  will not pretend it is.
- **Client-side caching delays revocation.** A client holds the placeholder for
  the advertised lifetime. Your lever is kow refusing to substitute, which takes
  effect on the client's next call rather than instantly.
- **A reload is not atomic for in-flight endpoint requests.** The listener is
  replaced on every config load, but a request already being served can return the
  previous placeholder. The client then caches a string kow no longer substitutes
  and fails upstream until it refreshes.
- **gRPC transports are unverified.** Credential resolution is HTTP and works, but
  several Google client libraries carry API traffic over gRPC, which this has not
  been measured against. Where a library offers a REST transport, prefer it until
  that measurement exists.
- **One account per endpoint.** The metadata protocol models a single instance
  identity. Multiple service accounts means multiple endpoints on separate ports.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Client ignores the endpoint | Python needs `GCE_METADATA_IP` too; `gcloud` also reads `GCE_METADATA_ROOT` |
| `401` from the Google API | kow forwarded the placeholder verbatim, meaning no binding matched the destination. Check `bindings.host` |
| `503` from the proxy | A mint failure. The audit log's `token_exchange` outcome names the leg that failed |
| `caller lacks tokenCreator` | The source identity has no `serviceAccountTokenCreator` on the target |
| SDK rejects the token format | Give the binding a placeholder starting `ya29.` |
