# Usage: pointing your agent at the proxy

## Compatibility matrix

kow is an HTTPS proxy with its own CA, so every client needs two things: route through the proxy, and trust the CA. Different stacks read different variables.

| Stack | Routes via | Trusts the CA via | Set by `kow run`? |
|---|---|---|---|
| Claude Code, Codex, Cursor and other Node-based agents | `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1` (Node 24+) | `NODE_EXTRA_CA_CERTS` (adds to defaults) | Yes |
| Python `httpx` (OpenAI and Anthropic SDKs) | `HTTPS_PROXY` | `SSL_CERT_FILE` | Yes |
| Python `requests` | `HTTPS_PROXY` | `REQUESTS_CA_BUNDLE` | No, set it yourself (bundle below) |
| curl | `HTTPS_PROXY` | `CURL_CA_BUNDLE`, or `--cacert` | Proxy yes, CA no |
| Anything else | `HTTPS_PROXY` | its own CA setting | Proxy yes |

`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` *replace* the trust store rather than adding to it. Point them at a bundle of the system roots plus kow's CA, built as shown below, not at kow's CA alone.

## Setting the variables by hand

With the daemon running (either install path), any HTTPS client can route through the proxy. In the calling shell - typically the shell that launches your agent:

```bash
# 1. Route through the proxy and trust its CA
export HTTPS_PROXY="http://127.0.0.1:14322"
export HTTP_PROXY="http://127.0.0.1:14322"
export NODE_USE_ENV_PROXY="1"   # Node 24+ ignores *_PROXY env without this
export NODE_EXTRA_CA_CERTS="/etc/kow/ca.pem"   # additive: Node appends to its defaults

# SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE REPLACE the trust store
# rather than adding to it. Pointing them at ca.pem alone leaves the shell
# trusting ONLY kow's CA, which breaks every host kow does not broker (it
# tunnels those through untouched, so the genuine upstream certificate is what
# arrives) — `pip install` and `curl https://pypi.org` start failing with
# "unable to get local issuer certificate". Build a bundle instead:
mkdir -p ~/.config/kow

# Point SYS_ROOTS at your platform's root store, then concatenate. Pick one:
SYS_ROOTS=/etc/ssl/certs/ca-certificates.crt        # Debian/Ubuntu
# SYS_ROOTS=/etc/pki/tls/certs/ca-bundle.crt        # RHEL/Fedora
# macOS keeps no PEM bundle on disk — export from the keychains instead. Include
# System.keychain, not just the Apple roots, or any enterprise/MDM-installed CA
# is dropped and corporate TLS breaks:
#   { security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain
#     security find-certificate -a -p /Library/Keychains/System.keychain; } > /tmp/roots.pem
# SYS_ROOTS=/tmp/roots.pem

cat "$SYS_ROOTS" /etc/kow/ca.pem > ~/.config/kow/ca-bundle.pem
export SSL_CERT_FILE="$HOME/.config/kow/ca-bundle.pem"
export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
export CURL_CA_BUNDLE="$SSL_CERT_FILE"

# Bypass the proxy for loopback and any internal mesh (Tailscale, VPN, LAN peers).
# Without this, local-service calls get routed at the proxy pointlessly and the
# legitimate caller breaks. NO_PROXY semantics differ by tool; tailor to your env.
export NO_PROXY="localhost,127.0.0.1,::1,*.ts.net,*.local,10.0.0.0/8,192.168.0.0/16"

# 2. Export the PLACEHOLDER — never the real value
export OPENAI_API_KEY="sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"

# 3. Use any HTTPS client. The proxy substitutes the placeholder for the real
#    secret on the way out, matching by binding scope (host + method + path).
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models
```

Why several CA variables: the proxy presents its own TLS certificate (signed by its CA) so it can read and rewrite the request, so every client has to trust that CA. Different HTTPS stacks read it from different env vars: Node from `NODE_EXTRA_CA_CERTS`, OpenSSL-based tools from `SSL_CERT_FILE`, Python `requests` from `REQUESTS_CA_BUNDLE`, curl from `CURL_CA_BUNDLE`. Set the ones your agent's stack uses. They are **not** equivalent: `NODE_EXTRA_CA_CERTS` is additive, while the other three replace the trust store outright - which is why the block above hands them a bundle containing the system roots *and* kow's CA, not kow's CA alone. This bundle is a point-in-time copy: re-run the `cat` after a kow CA rotation **and** whenever the system roots change (a `ca-certificates` package update, or an enterprise/MDM root being added or revoked). A stale bundle fails in a confusing way - some hosts verify, others do not. This is the canonical env-var block (including `NO_PROXY`): other docs point here for the full set.

The proxy records every substitution decision in an append-only JSONL audit log at `/var/log/kow/audit.jsonl`.

### Excluding a host from the proxy (and why)

`NO_PROXY` is **host-scoped**: only the hosts you list bypass the proxy: every other host still goes through it and still gets its credential injected. This is important for a common case: **your agent's own model/control-plane endpoint.** An LLM API the agent talks to (e.g. its own provider) authenticates itself and usually has *no* brokered secret here, so routing it through the proxy buys nothing: and it makes the agent depend on the proxy being up. Add that host to `NO_PROXY` and the agent reaches it directly, so a proxy restart or outage can never take the agent down, and you aren't terminating TLS on a stream you have no secret to inject into.

Crucially, this does **not** turn the proxy off for the agent's children. A script the agent spawns inherits `HTTPS_PROXY`/`NO_PROXY`, so any call it makes to a *brokered* host (your GitHub, cloud, or SaaS credentials) still routes through the proxy and is injected on the wire - only the excluded hosts go direct. Exclude the narrowest set that works; list the exact host, and add a leading-dot form (`.example.com`) if the client must also bypass subdomains. `NO_PROXY` matching differs by client (curl supports CIDR; Node/undici and Python `requests` match by host/suffix), so verify with the stack your agent actually uses.

> Caveat: if you launch the agent via `kow run`, it **strips** `NO_PROXY` (and `no_proxy`) from the child environment on purpose: otherwise an injected agent could set `NO_PROXY=*` to escape the proxy. To exclude a host under `kow run`, set the exclusion in the agent's own launch environment (the wrapper/service that starts it), not inside the `kow run` child.

## Configuration

YAML at `/etc/kow/bindings.yaml`. Re-read on service restart. Minimal example:

```yaml
version: 1

secrets:
  GITHUB_PAT:
    placeholder: "ghp_PLACEHOLDER_WORK_01HXY1234567890"
    inject:
      header: "Authorization"
      format: "token {GITHUB_PAT}"
    bindings:
      # Read-only on the REST API — POSTs and PATCHes forward the placeholder
      # verbatim, so a prompt-injected agent cannot create gists or open issues.
      - host: "api.github.com"
        methods: [GET]
      - host: "uploads.github.com"
```

Path globs: `*` matches one URL segment, `**` matches any number. Empty `methods: []` is rejected (deny-all-methods must be intentional: remove the binding instead). See [`bindings.example.yaml`](../bindings.example.yaml) for the full grammar and reference patterns for Anthropic, OpenAI, GitHub, Groq, Mistral, DigitalOcean, and others.

### Honeytokens (tripwire bindings)

Mark any binding `honeytoken: true` to turn it into a canary. Plant its placeholder somewhere tempting, a decoy `.env`, a fake `~/.aws/credentials`, and bind it to a trap host you control:

```yaml
secrets:
  DECOY_AWS_PROD:
    placeholder: "AKIA-PLACEHOLDER-DECOY-01HXY1234567890"
    honeytoken: true
    inject:
      header: "Authorization"
      format: "{DECOY_AWS_PROD}"
    bindings:
      - host: "canary.your-domain.example"
```

The agent only ever holds the *placeholder*, never the real secret (that is the whole point of the proxy), so the honeytoken's real value is never in the agent's address space. But the moment anything steers that placeholder anywhere, the proxy emits a `honeytoken_triggered` audit event alongside the normal decision - on *any* use (injected, denied, scope-violated, or aimed at the wrong host), before any real value moves. Shipped off-box (below), a single `honeytoken_triggered` anywhere in the fleet means that machine is being walked for credentials. The event carries no secret material (see [architecture §4.4](architecture.md)).

### Off-box audit shipping

The audit log is a local, fail-closed source of truth. To forward it to a central collector for fleet-wide alerting (honeytoken triggers, bursts of denied / exfil-attempt decisions), the Ansible role stands up a **separate** shipper sidecar: a distinct systemd unit and user with read-only access to the log. The proxy's own process, sandbox, and egress surface are untouched.

Enable it per host in inventory:

```yaml
agent_vault_proxy_shipping_enabled: true
agent_vault_proxy_shipper_collector_host: "collector.your-tailnet.ts.net"
# Pinned + checksum-verified at provision time (never a runtime fetch):
agent_vault_proxy_shipper_fluentbit_url: "https://.../fluent-bit"
agent_vault_proxy_shipper_fluentbit_sha256: "<sha256>"
```

The default shipper is **Fluent Bit** (~15 MB, ~10% of the deployed footprint). Switching to Vector later is a per-host swap - set `agent_vault_proxy_shipper: vector` once that path lands; `vector` / `native` currently fail fast with a "not yet implemented" message so the seam is explicit. The design, transport (Tailscale node identity, no mTLS), and threat model are in [ADR-0019](adrs/ADR-0019-off-box-audit-shipping.md).

#### Shipping to a hosted log service

Fluent Bit can fan out to the major log platforms at the same time as (or instead of) the collector. **GCP Cloud Logging** is first-class - just set the role vars:

```yaml
agent_vault_proxy_shipper_gcl_enabled: true
agent_vault_proxy_shipper_gcl_project_id: "your-gcp-project"
agent_vault_proxy_shipper_gcl_credentials_path: "/etc/kow-audit-shipper/gcl.json"
```

For any other service, paste the vendor's `[OUTPUT]` block into `agent_vault_proxy_shipper_extra_outputs`, one variable, any number of sinks, no per-vendor role code. Source tokens from vault (the rendered config is root-owned `0640`). **Datadog** and **Splunk**:

```yaml
agent_vault_proxy_shipper_extra_outputs: |
  [OUTPUT]
      Name        datadog
      Match       kow.audit
      Host        http-intake.logs.datadoghq.com
      TLS         on
      compress    gzip
      apikey      YOUR_DATADOG_API_KEY        # from vault
      dd_source   kow-audit
      dd_service  keys-on-the-wire

  [OUTPUT]
      Name          splunk
      Match         kow.audit
      Host          your-hec.splunkcloud.com
      Port          8088
      TLS           on
      Splunk_Token  YOUR_SPLUNK_HEC_TOKEN      # from vault
```

Elasticsearch (`Name es`), AWS CloudWatch (`Name cloudwatch_logs`), and the rest follow the same one-block pattern, see the [Fluent Bit outputs](https://docs.fluentbit.io/manual/pipeline/outputs) catalog.

## Recommended layout for ongoing changes

After install, every new credential is "add to BWS + a few lines of YAML + restart." If you're using an AI coding agent (Claude Code, Codex, Cursor) to help write those bindings, you want a `git diff` review window between the agent's edit and your restart - that diff is what stops a prompt-injected edit from going live. (Threat: a single added `host:` entry under an existing binding can route a real secret to an attacker-controlled destination. See [`CLAUDE.md`](../CLAUDE.md) for the operating envelope.)

**Recommended: a small private git repo containing just your bindings.**

The repo itself is operational hygiene: version history, multi-host scale-out, a place for `git diff` to live. **It is not a security control.** The security control is (a) the operator reading the diff before restart and (b) only the operator being able to restart. The private-repo recommendation just makes both of those easier.

- **One repo, separate from this one.** Do not fork the kow source repo for your config - your bindings have nothing to do with the upstream code and you'd inherit fork-maintenance for no benefit.
- **Path matters.** Put the repo where `npm` / `pip` / build tools don't traverse - typically not `~/projects/` and not the agent's CWD. Something like `~/.config/kow-bindings/` is fine. `chmod 0700` the directory so non-kow-UID processes (like a postinstall hook from an unrelated `npm install`) can't read it.
- **Diff review is mandatory.** The agent edits `bindings.yaml` in your repo; you read the diff before restarting. Restart is your job, never the agent's. Treat `.gitignore`, any deploy script, and any `bindings.*` file as part of the diff review surface, the daemon reads exactly one file (`bindings.yaml`), so if your deploy script reads more than that, you've widened the gate.
- **No auto-restart.** Don't reach for `fswatch`, `inotify`, a `Makefile restart` target Claude can shell into, a post-commit hook, or a CI auto-deploy. All of them collapse the diff-review window to zero - exactly what the credential-isolation model relies on. If diff review feels tedious, the fix is better diff tooling, not automation around the restart.
- **`.gitignore` always:** `secrets/bws-token`, `ca.pem`, anything containing real values. Real values stay in the configured backend (Bitwarden or Google Secret Manager): the whole point of this proxy.
- **Multi-host:** branches or directories per host (e.g., `laptop/bindings.yaml`, `ci-runner/bindings.yaml`). Make sure your deploy command binds explicitly to the host it's targeting: accidentally shipping `laptop/bindings.yaml` to `ci-runner` cross-contaminates two hosts that were supposed to stay isolated.
- **Deploy step:** whatever fits your setup - `scp` + `systemctl restart` for systemd, `docker compose restart` for Docker, `ansible-playbook` for fleet. Keep it a one-line script you run by hand. The manual step IS the review gate.
