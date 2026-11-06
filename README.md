# Keys on the Wire

**Your AI agent never holds your API keys. It sends a placeholder; the real secret is swapped in on the wire.**

Credential stealers like Shai-Hulud and the poisoned LiteLLM 1.107.0 on PyPI dump every env var they can reach. Behind kow, they get placeholders that are worthless anywhere else. Prompt-injected agents get the same nothing.

[![PyPI](https://img.shields.io/pypi/v/keys-on-the-wire.svg)](https://pypi.org/project/keys-on-the-wire/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![CI](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml/badge.svg)](https://github.com/inflightsec/keys-on-the-wire/actions/workflows/test.yml)

**[keysonthewire.com](https://keysonthewire.com)** has the demo, a comparison against Vault Agent / Doppler / `op run`, and the [FAQ](https://keysonthewire.com/faq).

![Keys on the Wire desktop walkthrough: ask, paste one note, done](docs/desktop-demo.gif)

## Works with

**Agents:** Claude Code · Codex · Cursor · any terminal agent, script or app that speaks HTTPS

**Vaults:** Bitwarden Secrets Manager · Google Secret Manager · AWS Secrets Manager · macOS Keychain · local file (no vault needed)

`kow run -- <command>` sets the proxy and CA variables for that one process. What each stack reads, and which you set yourself, is in the [compatibility matrix](docs/usage.md#compatibility-matrix).

## How it works

![How Keys on the Wire substitutes secrets on the wire](docs/how-it-works-animated.svg)

1. Your agent sends a request with a *placeholder*, not the key.
2. kow, a loopback HTTPS proxy, fetches the real secret from your vault just in time and swaps it in, only for the hosts (and optionally methods and paths) you bound it to.
3. The agent never holds the real bytes. Unbound hosts get the placeholder or a 403, never the key, and every decision lands in an append-only audit log.

Bearer, `token`, X-API-Key, Basic, OAuth2 refresh and client-credentials, JWT bearer, GitHub App, HMAC and AWS SigV4 are all supported, and so are [MCP servers](docs/adrs/ADR-0040-mcp-server-credential-broker.md) (`kow mcp install`).

## Try it in two minutes, no vault

```bash
uv tool install keys-on-the-wire     # or pipx install, or brew install inflightsec/keys-on-the-wire/keys-on-the-wire
sudo kow setup --static              # service user, CA, and a starter EXAMPLE_API_KEY bound to example.com
kow run -- curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/kow/ca.pem \
  -H "Authorization: Bearer example_PLACEHOLDER_0001" https://example.com
sudo tail -n1 /var/log/kow/audit.jsonl
# macOS paths: /usr/local/etc/kow/ca.pem and /usr/local/var/log/kow/audit.jsonl
```

The audit line shows kow swapping the placeholder for the real value on the way to `example.com`. The `static` backend keeps that value in a file owned by root and readable only by the `kow` service user, so neither you nor your agent can read it. It is for trying kow out. For real keys, use a vault.

## Use it for real

1. **Set up your vault:** `sudo kow setup --bws`, `--gsm`, `--aws`, or `--keychain` (macOS). [Prerequisites](docs/prerequisites.md) covers the vault side.
2. **Broker a key.** Paste this to your agent:
   ```
   Read https://keysonthewire.com/install and set up kow for me.
   ```
   It mints the placeholder and prints a one-line `# kow-binding` note to paste into the secret's Notes field. It never sees your key. In Claude Code you can use the [bundled skill](skills/kow/) instead: `/plugin marketplace add inflightsec/keys-on-the-wire`, then `/plugin install kow@keys-on-the-wire`.
3. **Run your agent through it:** `kow env && kow run claude`.

The [Quickstart](docs/quickstart.md) walks the same path in full.

## Before you point it at production keys

- **It stops theft, not misuse.** A hijacked agent can still *use* a bound key within its scope while it runs. Narrow bindings with `methods:` and `paths:`. [Is it for you?](docs/is-it-for-you.md) draws the full boundary.
- **Fail-closed is the only mode.** If kow is down, routed calls fail; they never go out with a real key by accident.
- **Trial it behind one process.** `kow run` keeps the variables out of your login shell. See [Single process](docs/single-process.md).

## Docs

**Start here:** [Is it for you?](docs/is-it-for-you.md) · [Quickstart](docs/quickstart.md) · [Prerequisites](docs/prerequisites.md) · [Concepts](docs/concepts.md)

**Install and operate:** [Usage](docs/usage.md) · [Linux](docs/install-systemd.md) · [Docker](docs/docker.md) · [macOS](https://github.com/inflightsec/homebrew-keys-on-the-wire) · [Google Secret Manager](docs/gcp-secret-manager.md) · [Isolation on Linux](docs/linux-isolation.md) / [macOS](docs/macos-isolation.md) · [Troubleshooting](docs/troubleshooting.md)

**Reference:** [Architecture and threat model](docs/architecture.md) · [bindings.example.yaml](bindings.example.yaml) · [Adapters](docs/adapter-architecture.md) · [Comparison](docs/comparison.md) · [Terminal demo](docs/demo.cast) · [CHANGELOG](./CHANGELOG.md) · [SECURITY](./SECURITY.md) · [CONTRIBUTING](./CONTRIBUTING.md)

## Open source, no lock-in

Apache-2.0, no paid tier, no hosted service, no telemetry. kow only talks to your vault and the APIs your agent calls. The optional Bitwarden backend depends on [`bitwarden-sdk`](https://pypi.org/project/bitwarden-sdk/), which is not open source; see [NOTICE](NOTICE).
