# Storing a multi-line secret in the macOS Keychain

By default the Keychain backend refuses any value containing a newline. That is
not a limitation of the Keychain — a keychain item holds arbitrary bytes — it is
a limitation of how kow writes: it passes the value through `security -i`, whose
interactive parser treats a newline as end-of-command. A PEM would be stored
truncated, so it is refused instead.

If you need to store a service-account PEM (ADR-0050's impersonation seat) or any
other multi-line credential, route the backend through `kow-keyd`, a small signed
helper that passes the value as raw bytes on stdin.

Design and rationale: [ADR-0051](adrs/ADR-0051-keychain-helper-transmit-path.md).

## Read this first

**The helper is not an access-control boundary.** Its ACL names the helper's
code identity, and anyone who can run the helper satisfies that ACL — it is a
CLI with no caller authentication, so any process running as you can invoke
`kow-keyd get` and be handed the secret.

The security boundary is, and remains, the **macOS user account**. Run kow in its
own account and keep agent workloads out of it — see
[macos-isolation.md](macos-isolation.md). What the helper buys is transport, and
that is all it buys.

## 1. Build and sign it

The signature is the mechanism, not decoration: a keychain item's ACL records the
designated requirement of the process that created it, so the helper's code
identity has to be stable across rebuilds. An ad-hoc signature gets a fresh code
hash every build and invalidates every ACL, so `build.sh` refuses to use one.

```bash
sh helper/make-signing-identity.sh     # one-off: a local self-signed identity
sh helper/build.sh                     # builds and signs ./kow-keyd
```

A self-signed certificate is sufficient here. Apple's TN2206 is explicit that
most of macOS cares only that a program is validly signed and stable, not who
issued the certificate.

## 2. Install it where only root can replace it

kow will not execute a helper that it, or anything else running as you, could
have swapped out — the write path hands the credential to this binary on stdin.
The candidate paths are fixed in the source (`KEYD_CANDIDATES`) and are not
configurable, for the same reason `/usr/bin/security` is not configurable.

```bash
sudo install -o root -g wheel -m 0755 kow-keyd /usr/local/libexec/kow-keyd
```

Homebrew prefixes are deliberately not candidates: `/opt/homebrew` belongs to the
installing user on Apple Silicon, which is exactly the writability this check
exists to refuse.

## 3. Turn it on

```yaml
backend:
  type: keychain
  config:
    type: keychain
    service: kow
    use_helper: require
```

`require` is the only mode that uses the helper. There is no `auto`: which
transmit path is active determines whether existing items can be read at all, and
picking that from the presence of a file on disk is how an upgrade silently
strands a keychain full of credentials.

kow probes the helper at startup, so a missing or broken install fails at
configuration time rather than at the first credential fetch.

## 4. Migrate your existing secrets — old transport deletes, new transport adds

**Items written before you turned this on are not readable afterwards.** Their
ACL names `/usr/bin/security`, not the helper, so the helper is refused. The same
is true in reverse.

The order matters, and "just re-add it" is not enough: adding re-reads the item
first, and that read is refused by the same ACL that is the problem. **The
transport that owns the item has to be the one that deletes it.** So, per secret:

```bash
# 1. with use_helper still OFF, let security(1) remove its own item
kow secret remove MY_TOKEN

# 2. now set use_helper: require, then add it back
kow secret add MY_TOKEN --stdin-raw < /path/to/value
```

Going the other way, delete while `require` is still set, then switch to `off`.

There is no automatic migration, by design: kow rewriting every item's access
control on your behalf during a restart is not a thing it should do quietly.

## Storing a PEM

With `use_helper: require`, a multi-line value is just a value — but use
`--stdin-raw`, not `--stdin`:

```bash
kow secret add GCP_SEAT_KEY --stdin-raw < seat-key.pem
```

`--stdin` reads **one line** and strips its terminator. That is right for an API
key and silently destructive for a PEM: it would store
`-----BEGIN PRIVATE KEY-----`, the backend's read-back would confirm that
truncated value, and you would be told the write succeeded. `--stdin-raw` reads
to EOF and strips nothing, including the trailing newline, which is part of the
file.

Verify it round-tripped whole rather than assuming:

```bash
kow secret get GCP_SEAT_KEY | openssl pkey -noout -text | head -2
```

## What can still go wrong

**"the keychain is locked, or this item's ACL does not list the helper"** — the
helper exited 51. Either unlock the keychain, or the item predates the helper and
needs re-adding.

**A duplicate `(service, account)` pair refuses the write.** Two items with the
same pair make every lookup ambiguous, and a write would collapse them and
destroy one. Remove the duplicate in Keychain Access and retry. On this path the
check runs *before* the write and fails closed.

**Uninstalling the helper locks you out.** Items it wrote are readable only
through it. Re-add them under `use_helper: off` if you want to go back, before
removing the binary.

**A rebuild with a different signing identity invalidates every ACL.** Keep the
identity; if you must change it, re-add the secrets.

## When not to bother

If every secret you hold is a single-line API key, none of this applies. Leave
`use_helper: off`, which is the default, and nothing changes.
