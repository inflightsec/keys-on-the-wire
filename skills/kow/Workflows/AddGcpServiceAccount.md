# Workflow: AddGcpServiceAccount

Give an app the authority of a Google service account without the app ever holding
one. Design: ADR-0050. Reference: `docs/gcp-service-account.md`.

> **Rule 1 (notes-first) does not apply here, and that is by design.** A vault note
> can only express the plain header injector — `notes_binding.py` hardcodes
> `type: header`, because ADR-0024 keeps vault-side metadata able to *narrow* scope
> and never to declare a new minting binding. Every minting injector (oauth2,
> sigv4, github_app, and this one) therefore lives in `bindings.yaml`. Say this to
> the user if they expect the notes flow; do not try to author a GCP binding as a
> note, it will be ignored.
>
> Rules 2 (never handle the secret) and 3 (wire the consumer, blocking) apply in
> full.

## 1. Interview (ask only what's unknown; recommend a default each time)

1. **Which service account should the app act as?** The full
   `name@project.iam.gserviceaccount.com`. This is the *target*.
2. **Which Google APIs?** Get the hostnames (`bigquery.googleapis.com`,
   `storage.googleapis.com`, …). Never propose `*.googleapis.com`: one binding
   covering every enabled API is the opposite of scoping.
3. **Which scopes?** Narrowest that works. Bare names are fine —
   `bigquery.readonly` expands to the full URL.
4. **Where does the kow daemon run, and what is its own Google identity?** This
   decides layer 1 and it is the question people get wrong.
   - **On GCE / GKE / Cloud Run** → `--source adc`. ADC resolves to the metadata
     server, so **no key exists anywhere**. This is the recommendation *here*.
   - **Anywhere else** (a laptop, a VPS) → an *impersonation seat*: one service
     account whose only power is to be impersonated, holding no data access. Its
     PEM goes in the vault, `--source seat_key`.
     Do **not** substitute `--source adc` on such a host to avoid storing a key:
     there ADC is `~/.config/gcloud/application_default_credentials.json`, a
     plaintext long-lived user refresh token with the operator's full identity,
     readable by any process running as them. It is a bigger credential than the
     seat key it replaced, in a worse place.
   - The user insists on a plain key for the target → `--mode jwt_bearer_grant`.
     Tell them plainly that Google's own guidance is not to create service-account
     keys, and that this is the fallback, not the destination.
5. **Does the app use a Google client library, `gcloud`, or Terraform?** Almost
   always yes → keep the credential endpoint (the default). Only a hand-rolled
   REST caller that can be handed a placeholder should use `--no-endpoint`.

## 2. Emit the exact artifact — with the tool, never by hand

```bash
kow binding gcp \
  --target agent-runner@my-project.iam.gserviceaccount.com \
  --host bigquery.googleapis.com \
  --scope bigquery.readonly \
  --methods GET,POST \
  --project my-project
#   stdout → the bindings.yaml block to paste (secret + credential_endpoint)
#   stderr → what to put in the vault (if anything) AND the consumer wiring — CAPTURE IT
```

Useful flags: `--source seat_key --seat <email> --key-secret <VAULT_NAME>` for the
seat; `--mode jwt_bearer_grant --key-secret <VAULT_NAME>` for a target key;
`--mode self_signed_jwt --audience <endpoint>` for the no-egress variant;
`--paths` to scope; `--no-endpoint` for hand-wired callers; `--name` to rename the
binding (default `GCP`).

The block is validated through the daemon's own `Config` model before printing, so
anything it emits will load. If it refuses, the message is the real parser's.

## 3. The vault half (rule 2 — propose, never apply)

- **`--source adc`:** nothing goes in the vault. Instead the user runs one grant:
  ```bash
  gcloud iam service-accounts add-iam-policy-binding <TARGET> \
    --member="serviceAccount:<THE DAEMON'S OWN SA>" \
    --role="roles/iam.serviceAccountTokenCreator"
  ```
- **`--source seat_key` / `--mode jwt_bearer_grant`:** tell the user to store the
  **`private_key` value** from the downloaded key JSON (the PEM block, not the whole
  file) as the vault entry named in `--key-secret`. Never paste the key yourself,
  and never ask them to paste it into this session.

## 4. Paste and reload

The block goes into `bindings.yaml` (`secrets:` entry, plus the top-level
`credential_endpoint:` section if present — there is one endpoint per daemon, so if
one already exists, keep it and add only the secret). Then reload the daemon; the
config is read at `configure()` only.

## 5. Wire the consumer (BLOCKING — the binding does nothing without it)

**With the credential endpoint (default): no code change, four env vars.**

```bash
export GCE_METADATA_HOST=127.0.0.1:14380   # Go, Node, .NET, Java, gcloud
export GCE_METADATA_IP=127.0.0.1:14380     # additionally required by Python
export GCE_METADATA_ROOT=127.0.0.1:14380   # additionally read by gcloud
export HTTPS_PROXY=http://127.0.0.1:14322  # the kow proxy
```

The app's ADC lookup now finds kow, believes it is on a Compute Engine VM, and gets
a **placeholder** shaped like a Google token. It sends that placeholder to the API
through the proxy, where the real minted token is substituted. Write these lines
into the app's `.env`/unit file yourself, the same as any other placeholder wiring.

**With `--no-endpoint`:** wire `export <NAME>='ya29.kow-PLACEHOLDER-…'` and the app
must send it as the bearer token itself.

## 6. Verify before declaring success

```bash
# 1. The endpoint answers with the placeholder (not a credential):
curl -s -H "Metadata-Flavor: Google" \
  http://127.0.0.1:14380/computeMetadata/v1/instance/service-accounts/default/token

# 2. A real SDK accepts it (this is the check that proves the probe paths):
python -c "import google.auth,google.auth.transport.requests as r; c,_=google.auth.default(); c.refresh(r.Request()); print(c.token)"

# 3. A real call through the proxy returns data.
```

If step 3 returns 401, kow forwarded the placeholder verbatim: no binding matched
the destination. Check the host. If it returns 503, the mint failed — the audit
log's `token_exchange` outcome names which leg.

## Gotchas

- **The macOS Keychain needs `use_helper: require` to hold a key.** By default it
  refuses any value with a newline (the `security -i` protocol would truncate it)
  and a PEM is ~28 lines. The fix is `use_helper: require`, which routes the
  backend through the signed `kow-keyd` helper — a build step, a `sudo install`,
  and re-adding existing secrets. Point the user at `docs/keychain-helper.md`.

- **Do NOT reach for `--source adc` just to dodge that.** On a workstation ADC
  resolves to `~/.config/gcloud/application_default_credentials.json`: a plaintext
  long-lived **user** refresh token, readable by any process running as them, with
  their whole identity behind it — strictly worse than a seat key whose only power
  is to be impersonated. `--source adc` is the keyless answer when the daemon runs
  **on** GCE/GKE/Cloud Run (ADC hits the metadata server, nothing on disk) or when
  ADC is a federation config. Say which of those applies before recommending it.

- **One service account per endpoint.** The metadata protocol models a single
  instance identity. A second service account needs a second endpoint on another
  port, and a client can only point at one.
- **Every local process can ask the endpoint for the placeholder.** Say this out
  loud rather than letting the user discover it, and say it precisely: the
  placeholder is worthless off the box, but on the box it is a usable capability,
  because any process holding it can make authenticated calls through kow within
  the binding's scope. Credential theft goes to zero; credential use is open to
  the host. Tighter than that means putting kow and the agent in one network
  namespace or container.
- **gRPC transports are unmeasured.** Credential resolution is HTTP and works; some
  client libraries carry API traffic over gRPC. Prefer a REST transport until that
  is measured.
- **Client-side caching delays revocation.** The app holds the placeholder for the
  advertised lifetime; your lever is kow refusing to substitute.
- **Impersonation does not support domain-wide delegation.** That needs
  `--mode jwt_bearer_grant` plus an explicit `allow_domain_wide_delegation: true`,
  because one such binding can act as any user in the Workspace domain.
