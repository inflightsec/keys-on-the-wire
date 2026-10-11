# VM end-to-end

Boots a throwaway Debian VM under QEMU/KVM with **real systemd** and follows
`docs/install-systemd.md` step by step for the static backend, then asserts the
whole chain on the wire.

**Linux** — boots a throwaway Debian VM under QEMU/KVM. Needs `qemu-system-x86_64`
and `/dev/kvm`; nothing else, and nothing of yours is touched.

```bash
bash tests/vm-e2e/run.sh                 # systemd leg (default), ~4 min
bash tests/vm-e2e/run.sh all             # all six Linux legs, ~25 min
bash tests/vm-e2e/run.sh pypi            # build + install from a mock PyPI index
bash tests/vm-e2e/run.sh readme          # walk the README quickstart
bash tests/vm-e2e/run.sh tls             # TLS interception only
bash tests/vm-e2e/run.sh docker          # container path only
bash tests/vm-e2e/run.sh rootless        # unprivileged install only
bash tests/vm-e2e/run.sh --keep all      # leave it up: ssh -F /dev/null -p 2222 debian@127.0.0.1
```

**macOS** — run these **directly on a Mac**, Intel or Apple Silicon. No VM.

```bash
bash tests/vm-e2e/macos-e2e.sh                            # unprivileged: no sudo, no residue, ~3 min
bash tests/vm-e2e/macos-e2e.sh --keychain                 # the keychain backend, throwaway keychain, ~4 min
bash tests/vm-e2e/macos-e2e.sh --gcp                      # ADR-0050: Keychain-held key, minted assertion, ~4 min
bash tests/vm-e2e/macos-keyd-e2e.sh                       # the signed helper scopes the ACL to kow, ~3 min
KOW_E2E_CONSENT=1 bash tests/vm-e2e/macos-e2e.sh --system # the documented system install, ~6 min
bash tests/vm-e2e/macos-e2e.sh --system --keep            # leave it installed to poke at
KOW_FORMULA=/path/to/keys-on-the-wire.rb \
  bash tests/vm-e2e/guest-brew.sh                         # the real tap formula, ~15 min
```

The default mode needs no admin rights: a venv and config in a scratch
directory, the proxy run as you, everything deleted on exit. **Start there.**

`--system` performs the real documented install — a `_kow` service account, a
LaunchDaemon, directories under the Homebrew prefix, an append-only audit log —
and reverses all of it on exit, reporting any residue. Because it mutates the
machine it refuses to start without `KOW_E2E_CONSENT=1`, and refuses outright if
a kow install already exists, so it can never damage a real deployment. Prefer a
disposable machine for it.

`--keychain` exercises the macOS Keychain backend against the real
`/usr/bin/security`. It creates a throwaway keychain, **never touches your login
keychain**, and deletes it on exit. It needs no admin rights and no consent flag,
and it is unprivileged by construction rather than by choice: a keychain belongs
to a login session, so this leg running as you *is* the LaunchAgent constraint
demonstrated. The unit suite runs on Linux against a fake `security`; this leg is
where the interactive quoting protocol, exit-44 item-not-found, prompt-free
enumeration, and locked-keychain behaviour are answered by the actual tool.

CI runs the unprivileged, keychain and system modes on `macos-13` (Intel) and
`macos-14` (Apple Silicon) on every push — see `.github/workflows/macos-e2e.yml`.
Those are the same scripts, so a green CI run and a local run mean the same
thing.

There is no macOS VM path in this repo, deliberately: Apple's licence permits
macOS virtualisation on Apple hardware only, so a VM is a maintainer's private
convenience, never the project's macOS story. Everything above runs natively on
any Mac, and on GitHub's runners.

## The legs

| Leg | Script | Asserts |
|---|---|---|
| systemd | `guest-install.sh` | the documented bare-metal install: service user, `chattr +a`, real unit, journald |
| docker | `guest-docker.sh` | the repo `Dockerfile` builds, runs as unprivileged `kow`, brokers through a published port |
| tls | `guest-tls.sh` | **the core capability**: a real TLS connection intercepted, the credential swapped *inside* the encrypted request, upstream chain genuinely verified |
| rootless | `guest-rootless.sh` | no sudo, no `/etc`, no service account — venv in `$HOME`, config in `$KOW_CONFDIR` |
| pypi | `guest-pypi.sh` | builds sdist+wheel from this tree, serves a PEP 503 index, installs from it — packaging, console scripts, extras |
| readme | `guest-readme.sh` | walks the README quickstart command by command, ending in the README's own end-to-end promise |
| brew | `guest-brew.sh` | the REAL tap formula, repointed at a locally built sdist: `brew install --build-from-source` |
| macOS user | `macos-e2e.sh` | the no-admin path: venv + config in a scratch dir, proxy run as the caller, zero residue |
| macOS keychain | `macos-e2e.sh --keychain` | the keychain backend on the real `security(1)`: CLI write with no value on argv, a shell-hostile value round-tripping byte-identical, prompt-free enumeration, nothing plaintext on disk, locked keychain failing closed without hanging |
| macOS gcp | `macos-e2e.sh --gcp` | ADR-0050 end to end with no network and no GCP project: a multi-line PEM round-tripping through the `security -i` quoting protocol byte-identically (every other kow credential is one line), the credential endpoint serving the placeholder with the content types `google-auth` requires, and an upstream receiving an assertion that VERIFIES against the public key while the caller held only a placeholder |
| macOS kow-keyd | `macos-keyd-e2e.sh` | the signed helper scopes the ACL: builds and self-signs `kow-keyd`, then asserts `security(1)` AND a Python script are both refused while the helper reads its own item, and that a rebuild keeps the same designated requirement |
| macOS system | `macos-e2e.sh --system` | `dscl` account, Homebrew prefix, `chflags sappnd`, launchd — then full teardown |

Every leg ends with the same four wire assertions: healthz 200, a real placeholder
swapped for a real secret upstream, an unbound destination refused 403, and **no
secret bytes in any log**.

### Why the tls leg matters

Every other harness here — and `tests/local-e2e` — asserts substitution over
plain HTTP. The tls leg is the only proof that kow does the thing it exists for.
It stands up an HTTPS upstream behind a real CA, points kow at that CA with
`ssl_verify_upstream_trusted_ca` (**not** `--ssl-insecure`, so the upstream hop
is genuinely verified), and then proves interception actually happened: a client
trusting *only* the upstream CA must FAIL, because kow re-signs with its own.

### Rootless is a convenience, not the hardened deployment

The rootless leg runs kow as the calling user — no root anywhere. That is useful
where you have no admin rights, but it puts the proxy and the agent at the **same
UID**, which dissolves the boundary the design rests on (`docs/architecture.md`:
anything at the agent's UID can use the proxy as its own authenticated channel,
and can also just read the config). Use the system install for a real deployment.

The legs share one VM and are independent: docker publishes on its own host port
so it cannot collide with a running systemd unit, and the rootless leg snapshots
`/etc` first so a system install from another leg is never mistaken for its own.

### The macOS legs run natively, not in a VM

`macos-e2e.sh` is self-contained and location-agnostic: it resolves the Homebrew
prefix at run time (`/usr/local` on Intel, `/opt/homebrew` on Apple Silicon —
hardcoding either one broke the install on half the Macs in existence), finds any
Python >= 3.12, and takes its source tree from `KOW_SRC` or its own location. The
same script therefore runs on a laptop, on a CI runner, and inside a VM.

`run-macos.sh` is a **maintainer convenience** that ships those scripts into a
local macOS VM over ssh. It is deliberately not the documented path: Apple's
licence permits macOS virtualisation on Apple hardware only, so the project's
macOS story is "run it on a Mac, or let CI run it on GitHub's".

## Why a VM and not a container

These cannot be exercised anywhere else:

| Needs a real VM | Why |
|---|---|
| `chattr +a` on the audit log | overlayfs/tmpfs reject the attribute |
| `systemctl enable --now kow` | no PID 1 in a container |
| the hardened unit's sandboxing | `ProtectSystem`, `ReadWritePaths`, `User=avp` |
| `journalctl` secret-leak check | no journald in a container |
| a real service user + 0700 CA confdir | uid separation is the ADR-0012 boundary |

## The documentation is the test

The systemd unit is **extracted from `docs/systemd-unit.md`** at run time, not
copied into the harness, and the install follows the documented commands rather
than calling `kow setup`. A doc that drifts from reality fails here.

`extract_doc_steps.py` dumps the runnable blocks from an install doc
(`python3 tests/vm-e2e/extract_doc_steps.py docs/install-systemd.md --list`).

## Findings this harness has already caught

- `systemctl enable --now keys-on-the-wire` — the documented unit name never
  existed (real unit: `kow.service`); the install could not be followed.
- `kow --version` was documented in `_healthz.py` but the flag did not exist.
- The documented macOS account recipe hardcodes uid/gid **250**, which is the
  stock `_analyticsusers` group on every Mac. `dscl` then leaves the group with
  no `PrimaryGroupID` and `install -d -g _kow` dies with "illegal group name" —
  the macOS install could not be followed on any machine.
- The Python >= 3.12 requirement was documented nowhere; macOS ships 3.9.
- The documented install left `/var/lib/kow/.mitmproxy` at 0755, exposing the CA
  private key directory to other UIDs and failing `kow doctor` (ADR-0012).

## Not yet covered

- The real vault backends (BWS / GSM / AWS) — every leg uses the `static` route.
- The computed injectors (sigv4, hmac, jwt, github-app, oauth2).
- Operational paths: service restart, config reload, CA rotation.


## Prerequisites

| Leg | Needs |
|---|---|
| all Linux legs | `qemu-system-x86_64` + `/dev/kvm`; the Debian cloud image is fetched once into `/tmp/kow-vm` (override with `KOW_VM_WORK`) |
| macOS legs | a Mac with Homebrew and Python >= 3.12 (`brew install python@3.13`). `--system` also needs sudo. |
| brew leg | a checkout of the tap; point `KOW_FORMULA` at its `Formula/keys-on-the-wire.rb` — it tests the REAL formula |
| `run-macos.sh` (maintainers) | a local macOS VM (override its location with `KOW_MACOS_GATE`, the tap with `KOW_TAP`) |

Environment overrides honoured by the macOS legs: `KOW_SRC` (source tree),
`KOW_PY` (interpreter), `KOW_PREFIX` (Homebrew prefix), `KOW_FORMULA` (tap
formula), `KOW_E2E_CONSENT` (unlock `--system`).

Both harnesses are safe to re-run: the Linux legs boot a throwaway overlay and
delete it; `macos-e2e.sh` removes everything it creates in either mode. The brew
leg is the exception — it uninstalls the formula but keeps its scratch tree at
`~/kow-brew` and the local test tap, so prefer a disposable machine for it (and `run-macos.sh` reverts
its VM to the golden snapshot before **and** after, never writing a new one).

Known host gotcha: if `ssh` refuses to start with *"Bad owner or permissions on
/etc/ssh/ssh_config.d/…"*, that is the host's config, not the VM — both runners
already pass `-F /dev/null`.
