# Quickstart

kow is a local proxy that swaps a placeholder for the real secret in flight, so your agent never holds the credential. This page takes you from install to a brokered key in two stages: a no-vault trial, then a real vault.

## 1. Install

```bash
brew install inflightsec/keys-on-the-wire/keys-on-the-wire   # macOS
pipx install 'keys-on-the-wire[bitwarden]'                   # anywhere with Python 3.12+
```

Drop `[bitwarden]` if you won't use Bitwarden.

## 2. Try it with no vault

```bash
sudo kow setup --static
```

This creates the `kow` service user, the proxy CA, and a starter config with one secret, `EXAMPLE_API_KEY`, bound to `example.com` with the placeholder `example_PLACEHOLDER_0001`. The value lives in a file owned by root and readable only by the `kow` service user, so your shell and your agent can't read it.

Send the placeholder through the proxy and check the audit log:

```bash
kow run -- curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/kow/ca.pem \
  -H "Authorization: Bearer example_PLACEHOLDER_0001" https://example.com
sudo tail -n1 /var/log/kow/audit.jsonl
# macOS paths: /usr/local/etc/kow/ca.pem and /usr/local/var/log/kow/audit.jsonl
```

The last line is an `inject_decision` for `EXAMPLE_API_KEY` to `example.com`. Point the same placeholder at any other host and kow forwards it unchanged; the real value never leaves.

`static` is for trying kow out and for tests. It keeps values in plaintext on disk, so move to a vault before you use real keys.

## 3. Switch to your vault

Re-run setup with the vault you already use:

| Vault | Command | What you need first |
|---|---|---|
| Bitwarden Secrets Manager | `sudo kow setup --bws` | a machine-account token ([Prerequisites](prerequisites.md)) |
| Google Secret Manager | `sudo kow setup --gsm` | a service account ([GSM guide](gcp-secret-manager.md)) |
| AWS Secrets Manager | `sudo kow setup --aws` | temporary credentials via SSO, Roles Anywhere or an instance profile |
| macOS Keychain | `sudo kow setup --keychain` | nothing; add values with `kow secret add` |

## 4. Broker a real key

Paste this to Claude Code, Codex, Cursor or any terminal agent:

```
Read https://keysonthewire.com/install and set up kow for me.
```

Or, in Claude Code, install the bundled skill and just ask ("add my `GROQ_API_KEY` to kow"):

```
/plugin marketplace add inflightsec/keys-on-the-wire
/plugin install kow@keys-on-the-wire
```

Either way you get the placeholder and a short `# kow-binding` note. Create the secret in your vault with the real value and paste the note into its **Notes** field. kow re-reads the vault every 60 seconds (`notes_refresh_seconds`), so there's no restart.

## 5. Run your agent through it

```bash
kow env && kow run claude
```

`kow env` writes the placeholders to `~/.config/kow/env`; `kow run` loads them and sets the proxy and CA variables for that one process. `kow doctor` checks the setup. If your stack needs variables `kow run` doesn't set, see the [compatibility matrix](usage.md#compatibility-matrix).

Going deeper: [Concepts](concepts.md) · [Usage](usage.md) · [Linux install details](install-systemd.md) · [bindings.example.yaml](../bindings.example.yaml)
