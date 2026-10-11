# macOS: how kow is meant to be deployed

kow keeps real API keys out of the agent's environment. That only means something if the agent cannot go and read the keys some other way. On macOS the thing that makes it hold is **a separate user account** — not the Keychain, not the proxy.

This page is the companion to [Linux: composing kow with a filesystem sandbox](linux-isolation.md).

## The short version

```
┌─ your account ──────────────────┐        ┌─ sandvault-$USER ───────────┐
│                                 │        │                             │
│  kow (LaunchAgent)              │◀───────│  claude / codex / agent     │
│    └─ login keychain            │  loop  │    HTTPS_PROXY=127.0.0.1    │
│         OPENAI_API_KEY  ········│  back  │    sees: sk-PLACEHOLDER-…   │
│         (encrypted at rest)     │        │    cannot read your $HOME   │
└─────────────────────────────────┘        └─────────────────────────────┘
```

The agent asks for a URL with a placeholder in the header. kow swaps in the real credential inside the TLS session, on the way out. The agent gets **use** of the credential and never **possession** of it.

The account split is what makes "never possession" true. Everything else is bookkeeping.

## Recommended setup

[SandVault](https://github.com/webcoyote/sandvault) (Apache 2.0) does the macOS half for you: it creates a dedicated limited account `sandvault-$USER` and additionally wraps the process in `sandbox-exec`. From its own description, the agent:

- runs as a **different macOS user**,
- **cannot access other users' home directories** under `/Users/*`,
- gets a shared workspace at `/Users/Shared/sv-$USER`,
- cannot reach `/Volumes/*`.

That is exactly the shape kow wants. Then:

1. **Install kow in your account** and run it as a **LaunchAgent** — not a LaunchDaemon. A keychain belongs to a login session; a daemon running as a service account has no access to yours (and cannot use the data-protection keychain at all, per Apple TN3137).
2. **Store the secrets in your login keychain**: `kow secret add OPENAI_API_KEY`.
3. **Point the sandboxed agent at the proxy** — `HTTPS_PROXY=http://127.0.0.1:14322`, plus kow's CA in `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS`. Loopback is shared across accounts on the same Mac, so the agent reaches the proxy even though it cannot reach your files.

## What if both run under the same user?

Then the Keychain buys you **almost nothing**, and it is important to be blunt about that.

A keychain item's ACL binds to a *code-signing identity*. Distributed through PyPI or Homebrew, kow is not a Developer-ID-signed application, so the identity on the ACL is `/usr/bin/security` itself. Any process running as your user can therefore read every kow item with one command:

```
security find-generic-password -s kow -a OPENAI_API_KEY -w
```

No prompt, once the keychain is unlocked — which it is, from the moment you log in. A prompt-injected agent running as you does not need to attack kow at all; it just asks the Keychain. It can equally read kow's memory, its config, and its CA key, because it is the same uid.

So, precisely:

| Property | Separate account | Same account |
|---|---|---|
| Agent can read the keychain item | **No** — per-user encryption, `/Users/*` denied | **Yes** — one command |
| Agent can read kow's memory / CA key | **No** | **Yes** — same uid |
| Agent can *use* bound credentials via the proxy | Yes (by design) | Yes |
| Credential is plaintext on disk | No | No |
| **Net effect** | **Use without possession — kow works** | **A `0400` file with encryption at rest** |

The right-hand column is not worthless: nothing is in cleartext on disk, it is encrypted at rest when locked, and you get a GUI view. It is *better than a plaintext file*. It is **not an isolation boundary**, and kow prints a startup warning saying so whenever the keychain backend is selected.

If you genuinely cannot split accounts, the honest options are:

- accept that the keychain is at-rest protection only, and rely on kow's per-host bindings + audit log to bound and record what the agent can *use*;
- or wait for the signed-helper tier (a Developer-ID-signed binary against the data-protection keychain with Touch ID per release), which is the only way to make "only kow can read this" enforceable on one account.

> **This is NOT the `kow-keyd` helper that ships in 1.2.0.** That helper exists to carry
> raw bytes so a multi-line secret survives the transmit path ([ADR-0051](adrs/ADR-0051-keychain-helper-transmit-path.md));
> it buys **transport, not access control**. It has no caller authentication, so any process
> running as the operator can invoke it and be handed the secret, and the default self-signed
> identity's private key sits in the operator's own login keychain with `codesign` authorised
> against it. Turning `use_helper: require` on does not narrow the boundary described above:
> on one account it remains the macOS user account, exactly as [ADR-0046](adrs/ADR-0046-macos-keychain-backend.md) says.

## Keychain practices worth following

- **Never use `-A`.** It makes an item readable by any process with no prompt, permanently. kow never passes it.
- **Prefer the login keychain over the System keychain** for user credentials. Items in `/Library/Keychains/System.keychain` are readable by anything with `sudo`, and `sudo` is exactly what a social-engineering prompt injection asks for.
- **Do not put the keychain password anywhere.** `security unlock-keychain -p <password>` puts it on `argv`, which is world-readable through the process table — the same hole kow closes for credential writes. Unlock interactively, or let login unlock it.
- **A dedicated keychain does not isolate you from yourself.** Lock state lives in `securityd` and is per-user, not per-process: once unlocked, every process of that user can read it. A separate keychain file is useful for scoping and backup, not for defence against a same-user agent.
- **Watch for "Always Allow" fatigue.** Each click permanently widens an item's ACL. If you find yourself clicking it repeatedly, something is wrong with the setup, not with your patience.
- **The Keychain is not a fleet vault.** The login keychain never syncs. Two Macs means two copies and two rotations; use `bws`, `gsm`, or `aws-secrets-manager` when more than one machine is involved.

## One thing the account split does not solve

Any local account that can reach `127.0.0.1` can use the proxy, and kow does not authenticate its clients. That is deliberate — the agent has to be able to use it — but it means the proxy is a **capability** available to every account on the machine, not just the sandboxed one. On a single-operator Mac this is fine. On a shared machine, bind the listener where only the intended account can reach it, and rely on per-host bindings and the audit log to bound and record use.
