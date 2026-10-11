---
status: proposed
date: 2026-09-14
relates_to: ADR-0027/0028 (signing injectors — kow signs with a vault-held key the agent never sees), ADR-0049 (Postgres transport — the terminate-and-reoriginate precedent this deliberately does NOT follow), ADR-0012 (per-uid narrow trust), ADR-0023 (closed audit event set), ADR-0047 (scoping philosophy)
---

# ADR-0053: SSH support — an ssh-agent signing oracle, not a transport

## Context

The ask is SSH support in kow, with Ansible as the driving consumer: playbooks run
from an agent-operated machine against a fleet, and the SSH private keys that
authenticate those connections must never enter the agent's address space. Today the
honest answer in `docs/is-it-for-you.md` is "kow does not gate SSH; look at a
network-layer agent firewall." This ADR replaces that boundary with a design.

SSH is a worse fit for kow's two existing shapes than Postgres was:

- **It is not an injector.** Like SCRAM (ADR-0049), SSH publickey auth never puts the
  credential on the wire. The client signs a server-chosen session identifier with the
  private key; the server verifies against `authorized_keys`. There are no bytes to
  substitute, so the nine-injector taxonomy has nothing to offer.
- **Terminate-and-reoriginate is technically possible and disproportionately
  expensive.** The ADR-0049 move — speak the server side to the agent, the client side
  upstream, splice after auth — would here mean implementing the SSH transport layer
  (RFC 4253 KEX, binary packet protocol, rekeying), userauth (RFC 4252), and
  connection/channel multiplexing (RFC 4254) on both sides. That is an order of
  magnitude more hand-written protocol crypto than SCRAM, in a project whose highest
  risk is already its own handshake code. The obvious libraries are unavailable under
  hard constraint 9: paramiko is LGPL, AsyncSSH is EPL-2.0. And it buys nothing the
  cheaper design below doesn't, because SSH — unlike the Postgres wire — already ships
  a broker protocol.

**That protocol is ssh-agent.** The agent protocol — a de facto standard for two
decades and published as [RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html) in
May 2026 — is a per-user credential broker: private keys live in the agent process;
clients send `SIGN_REQUEST` over `SSH_AUTH_SOCK` and get signatures back; the key
never crosses the socket. Every serious client-side product
in this space is an agent-protocol server: 1Password's SSH agent, Bitwarden's desktop
SSH agent, Secretive (macOS Secure Enclave). It is G1 by construction, and it is the
only pattern in the competitive field where the client holds *nothing*.

The competitive scan (2026-09-14, multi-lane, URLs verified) frames the rest:

- **HashiCorp Vault SSH engine, Teleport, Smallstep step-ca** all converge on the
  *certificate* pattern: the client generates a (ideally ephemeral) keypair locally
  and the broker's CA signs a short-lived certificate (Vault role TTLs, Teleport
  `max_session_ttl` ~8–12 h, step-ca default 16 h). Nobody ships raw private keys to
  clients — Vault's dynamic-key mode, which did, was removed in Vault 1.13. Revocation
  is universally traded for TTL.
- But the certificate pattern hands the client a **live, usable credential** (its own
  key plus a valid cert). ADR-0049 already named this distinction: *zero is a
  different property from short-lived*. A prompt-injected agent with a 16-hour cert
  has 16 hours; an agent that can only ask kow for one signature per policy-checked
  destination has nothing to exfiltrate. It also requires `TrustedUserCAKeys` rollout
  on every target host, which for "my three machines and a VPS" is real friction.
- **OpenSSH destination-constrained keys** (`ssh-add -h`, OpenSSH 8.9+,
  [agent-restrict](https://www.openssh.org/agent-restrict.html)) are the state of the
  art for per-destination policy *inside* the agent protocol: the client sends a
  `session-bind@openssh.com` extension carrying the server's host key, the session
  identifier, and the server's signature over it, before any sign request. The agent
  verifies that signature and refuses signing for non-permitted destinations. This is
  exactly kow's binding model, expressed cryptographically — a destination check
  anchored to *possession of the host key*, strictly stronger than the DNS-name
  matching G3 does on HTTP.
- **Ansible needs nothing special.** Its default `ssh` connection plugin execs the
  OpenSSH client, which honours `SSH_AUTH_SOCK` natively. Pointing that variable at
  kow's socket is the whole integration; no `--private-key`, no key files in the
  inventory.

## Decision

**Ship SSH as a third seam: kow serves the ssh-agent protocol on a loopback Unix
socket and acts as a policy-enforcing signing oracle.** Not an injector, not a
terminated transport. The precedent is ADR-0027/0028: kow already signs requests with
vault-held keys the agent never sees; this extends that stance to the signature
protocol OpenSSH defined for the purpose.

1. **Surface.** A new top-level `ssh:` config section (mirroring `postgres:`,
   ADR-0049), opt-in and marked experimental. kow listens on a Unix-domain socket
   (default under the kow runtime dir, mode `0600`), and `kow env` gains an
   `SSH_AUTH_SOCK=<path>` line. Access control on the client hop is `SO_PEERCRED` uid
   allowlisting, mirroring the ADR-0049 recommendation and ADR-0012's per-uid
   posture — a Unix socket makes this free, where the Postgres TCP listener had to
   mint a client-hop token.

2. **Key custody.** Each SSH binding names a backend secret holding the private key
   (BWS secure note, GSM, keychain — the existing adapter registry). The private key
   is fetched just-in-time per sign request through the normal TTL cache, used to
   produce the signature, and never written to disk or returned on any socket. The
   public half is derived at binding-resolution time (the ADR-0032 refresh boundary)
   so `REQUEST_IDENTITIES` can answer without a per-request vault fetch. v1 supports
   Ed25519 and RSA (SHA-256/512 signature flags) via the `cryptography` package
   (already in the dependency graph via mitmproxy; Apache-2.0/BSD dual — constraint 9
   satisfied). Passphrase-encrypted keys are out of scope in v1: the vault is the
   encryption at rest.

3. **Destination policy is session-bind, required by default.** A sign request is
   honoured only when the connection has previously presented a valid
   `session-bind@openssh.com` for the session being authenticated: kow verifies the
   server's signature over the session identifier, extracts the session ID from the
   to-be-signed userauth blob, matches it against the bound session, and checks the
   presented **host public key** against the binding's pinned `host_keys:` (or a
   pinned host CA). When the client authenticates with OpenSSH's hostbound method
   (`publickey-hostbound-v00@openssh.com`), the destination's host key is embedded in
   the signed blob itself, and kow additionally cross-checks it against the
   session-bind record — the strongest form of the check, from the very bytes being
   signed. Bindings may additionally pin `users:` (the username is in the
   userauth blob, exactly the `ssh-add -h user@host` semantics). This *replaces* G3
   the way ADR-0049's structural routing did: the destination check stops being a
   string comparison against a spoofable name and becomes verification that the far
   end possesses a pinned key. A blob that does not parse as an RFC 4252 publickey
   userauth request is refused — kow is an SSH authentication oracle, not a general
   signing service.

   The escape hatch: clients that never send session-bind (non-OpenSSH
   implementations, OpenSSH < 8.9) fail closed. A per-binding
   `allow_unbound_sessions: true` opt-in restores signing for them with **no
   destination check at all** — stated in config as loudly as that sentence, and
   audited on every use. Ansible on any current distro uses the system OpenSSH client
   and never needs it.

4. **Enforcement by omission, agent-protocol dialect (G5).** Every refusal — unbound
   key, host key not pinned, user mismatch, missing session-bind, vault unreachable,
   malformed blob — returns the protocol's own generic `SSH_AGENT_FAILURE`, which is
   what a plain ssh-agent answers for any unusable key. Denial classes are separated
   only in the audit log. `REQUEST_IDENTITIES` lists only the public keys of resolved
   bindings; there is nothing to probe for beyond what `authorized_keys` on the
   targets already knows. Agent-protocol mutations (`ADD_IDENTITY`,
   `REMOVE_IDENTITY`, `LOCK`) are refused: kow's key set is the operator's binding
   config, not client state.

5. **Audit: new events, contract bump (ADR-0023 process).** `ssh_session_bound`
   (host key fingerprint, forwarding flag), `ssh_sign_allowed` and `ssh_sign_denied`
   (binding name, key fingerprint, destination host-key fingerprint, user, reason
   taxonomy), each with declared field allowlists; never key material, never the
   signed blob. The G6 ordering lands where the credential act is: the
   `ssh_sign_allowed` event is fsynced **before the signature bytes are written back
   to the client socket** — the signature is the injection.

6. **What kow does not control here, stated plainly.** kow authorizes the handshake;
   it is not in the data path. An approved session lives entirely outside kow — there
   is no splice to cut, so ADR-0049's `max_session_age` has no analogue and `kow ssh
   kill` cannot exist. G8 degrades to *authentication-time* freshness: rotating the
   key in the vault stops new sessions within the cache TTL and does nothing to live
   ones. Session teardown is the server's control (`sshd_config`
   `ClientAliveInterval`, or the host's own session limits). Equally, kow cannot see
   or scope *what the session does* — a shell is a shell. The ADR-0047 line holds: the
   narrowing lever is server-side (`authorized_keys` `command=`/`restrict` options, a
   dedicated automation user), not protocol inspection, and `kow doctor` gains a
   check that warns when a bound key lands on `root@` without `users:` pinning.

7. **Ansible is the reference consumer and gets a documented recipe.** One env var:
   `SSH_AUTH_SOCK` from `kow env`; remove `ansible_ssh_private_key_file` /
   `--private-key` from inventory. Two operational notes belong in the doc, not the
   code: OpenSSH connection multiplexing (`ControlPersist`, which Ansible enables by
   default) means one kow-audited authentication can carry many tasks and its
   lifetime is bounded by the ControlPersist timeout, not by kow; and Ansible `forks`
   produce concurrent agent connections, so the listener is concurrent from day one.
   Host-key pinning for bindings comes from the same `known_hosts` reality Ansible
   already depends on — a `kow ssh pin <host>` helper records the fingerprint with an
   explicit operator confirmation, never a silent TOFU.

## Rejected alternatives

**Terminate-and-reoriginate (an SSH ProxyJump kow).** Full transport + userauth +
channel implementation on both legs, hand-written under constraint 9 because the
libraries are LGPL/EPL. It would buy `max_session_age` and a kill switch — real
controls — at the cost of kow becoming an SSH implementation, the single riskiest
class of code it could host. If session-lifetime control ever becomes the dominant
requirement, that is a future ADR and it should probably ship as a separate binary.

**kow as SSH CA (the Vault/Teleport/step-ca pattern).** The industry-convergent
answer, and the right one for fleets that already run a CA and want SSO-gated,
TTL-bounded human access; `docs/comparison.md` should route people there without
embarrassment. Rejected as kow's mechanism because the client ends up holding a live
keypair-plus-certificate — short-lived is not zero — and because it demands
`TrustedUserCAKeys` on every target. The automation variants make the gap concrete:
Teleport's `tbot` and the Vault+AAP validated pattern both materialize the private
key as a *file on the automation host*, exactly the artifact this project exists to
eliminate; their win is ephemerality, not absence. kow's claim stays narrow: the
agent holds nothing, and each use is policy-checked at signing time.

**Vault-style OTP.** Strongest "client holds nothing" variant in the field, but needs
a helper installed on every target host with network reach back to the broker.
Inverts kow's zero-target-footprint property.

**Writing the key to a temp file / `ssh -i` wrapper.** Puts the real key bytes in the
agent-readable filesystem, G1 dies immediately. Named only because it is what every
ad-hoc script does today.

**Doing nothing (point at 1Password/Bitwarden agents).** They prove the pattern but
target interactive desktop use: approval is a human prompt, which is a feature for a
person and a bug for automation — an Ansible run at `forks: 10` is a prompt storm
(Bitwarden's un-honored prompts on forwarded requests are an open issue), and
Bitwarden additionally offers vault keys to servers *sequentially* with no
per-request selection, leaking public keys to every host touched. No per-destination
binding, no audit stream, no vault-side JIT fetch, no headless mode. The gap kow
fills is precisely "agent-protocol custody with kow's binding/audit discipline,
headless, policy instead of prompts."

**Network-identity substitution (Tailscale SSH; EC2 Instance Connect / OS Login /
Cloudflare Access).** The strongest alternative *for hosts inside the operator's own
mesh*, and it deserves the honest sentence: Tailscale SSH removes SSH keys entirely —
auth type `none`, identity and authorization at the WireGuard layer via node keys
and tailnet ACLs, check-mode re-auth for sensitive targets. An operator whose whole
fleet is on the tailnet may not need kow's SSH support at all, and `docs/is-it-for-you.md`
should say so. It is not the same control, though: the *node* becomes the credential,
so any process on the agent machine can SSH wherever the node's ACLs allow, with no
per-use policy decision and no kow-side audit of individual authentications; and it
covers only tailnet destinations — external VPSs, git hosts, and customer machines
stay key-based. The cloud-provider variants (Instance Connect, OS Login, Cloudflare)
are the same idea coupled to one platform. kow's oracle is the answer when the
destination is outside the mesh or when per-authentication policy and audit are the
point.

## Consequences

**Good.** G1 extends to the credential class that guards the operator's own fleet,
with no new crypto handshake — signing primitives kow already ships, inside a
20-year-old protocol whose reference implementation is the policy model (session-bind
verification is *stronger* than HTTP G3). Zero footprint on target hosts. Ansible
integration is one environment variable. The seam generalizes: any future
"agent-held key" protocol with an agent socket (git signing is the same socket)
inherits the policy layer.

**Bad.** A third protocol surface and a second long-lived listener, concurrent from
day one. The T-3 caveat from `docs/architecture.md` carries over in oracle form: a
poisoned dependency at an allowlisted uid can request signatures through kow — it
gains temporary *use*, never *possession*, bounded by destination policy and fully
audited, but while resident it authenticates like the agent does. The destination guarantee depends on client cooperation: session-bind is an
OpenSSH behaviour, and the opt-out for other clients silently reduces kow to
key-custody-without-destination-policy for that binding — the config key and audit
trail have to carry that honesty. kow gains no session-lifetime control at all
(stated in decision 6), which is a *weaker* post-auth story than the Postgres
transport, not a stronger one. And host-key pinning shifts a known_hosts-shaped
maintenance burden into kow config: a re-keyed server is an outage until re-pinned.

**Out of scope (v1).** Certificates (both consuming and minting), FIDO/U2F
(`sk-`) keys, passphrase-protected keys, agent forwarding through kow,
`ssh_config` generation, session recording, and any SSH server or client
implementation. PKCS#11/hardware-backed keys stay where they are — hardware custody
already beats vault custody for that class.

## Open before implementation

- **Agent-protocol conformance set.** Message-level tests from RFC 9987:
  oversized messages, truncated frames, unknown extensions, concurrent connections,
  and the exact `SSH_AGENT_FAILURE` byte behaviour of stock ssh-agent for each
  refused operation (the G5 property is "indistinguishable from ordinary failure,"
  which must be verified against the real thing, not assumed).
- **session-bind verification vectors.** Interop against real OpenSSH clients (8.9,
  9.x, 10.x) including the forwarding flag semantics, plus the OpenSSH 10.5
  locked-agent fix as a regression reference for how this surface rots.
- **Userauth-blob parser bounds.** The RFC 4252 blob is attacker-influenced input;
  parser needs the same bounded-read discipline as ADR-0039.
- **Binding grammar.** `host_keys:` entry format (OpenSSH `known_hosts` line vs
  SHA256 fingerprint), host-CA pinning form, and how `kow ssh pin` interacts with
  the notes-binding source (ADR-0011/0025) for vault-side SSH bindings.
- **Concurrency model.** Socket server shares the process with mitmproxy's event
  loop or runs alongside the Postgres listener's model; pick one and bound
  per-connection state (ADR-0049's "bounds on every per-connection structure"
  applies verbatim).

## Implementation note (v1, 2026-09-16)

Shipped in `src/kow/sshagent/` (wire / keys / userauth / sessionbind / policy /
config / server) with `tests/test_sshagent.py`; audit contract bumped to v5.
Resolutions of the open items above, as built:

- **Concurrency model:** threaded listener owned by the addon, exact
  `CredentialEndpoint` lifecycle (started on configure, stopped on
  reload/shutdown); thread-per-connection, capped by `max_connections`
  (default 64), 30 s idle timeout, 256 KiB message cap, ≤16 session binds per
  connection with a duplicate-id/different-hostkey poison rule.
- **Binding grammar:** `host_keys:` entries are OpenSSH public key lines,
  compared blob-for-blob against the verified session-bind host key; `users:`
  optional; `allow_unbound_sessions` is the audited opt-out. `allowed_uids`
  (SO_PEERCRED) is mandatory — no "any uid" spelling exists.
- **Policy is a pure function** (`decide_sign`), mirroring `decide()`; the
  server executes verdicts and owns the G6 fsync-before-signature ordering.
- **Refusals:** everything answers the single-byte `SSH_AGENT_FAILURE` —
  including ADD/REMOVE/LOCK, unknown extensions, RSA-SHA-1 signature
  requests (refused outright), and vault outages. Verified byte-identical in
  tests across seven denial classes.
- **`kow env`** exports `SSH_AUTH_SOCK` when `ssh:` is enabled.
- Still open for a later pass: interop vectors against real OpenSSH client
  builds (the in-tree vectors are cryptographically real but synthetic), a
  `kow ssh pin` helper, and `kow doctor` checks (root@ warning, socket perms).

## References

- [RFC 9987 — SSH Agent Protocol](https://www.rfc-editor.org/rfc/rfc9987.html) (formerly draft-miller-ssh-agent; constraint extensions incl. `restrict-destination-v00@openssh.com`)
- [OpenSSH agent-restrict design](https://www.openssh.org/agent-restrict.html) — destination constraints, session-bind, hostbound userauth; [OpenSSH 8.9 release notes](https://www.openssh.org/txt/release-8.9)
- [ssh-add(1)](https://man.openbsd.org/man1/ssh-add.1) (`-h` / `-H`), [LWN: Restricting SSH agent keys](https://lwn.net/Articles/880458/)
- RFC 4252 (userauth, publickey method), RFC 4253 (transport — cited to justify *not* implementing it)
- [Vault SSH secrets engine](https://developer.hashicorp.com/vault/docs/secrets/ssh) and [signed certificates](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
- [Teleport authentication architecture](https://goteleport.com/docs/reference/architecture/authentication/) and [Machine & Workload Identity](https://goteleport.com/docs/machine-workload-identity/)
- [Smallstep: DIY SSO for SSH](https://smallstep.com/blog/diy-single-sign-on-for-ssh/)
- [1Password SSH agent security](https://www.1password.dev/ssh/agent/security), [Bitwarden SSH agent](https://bitwarden.com/help/ssh-agent/) + [About SSH](https://bitwarden.com/help/about-ssh/), Secretive — the agent-protocol product field
- [Teleport Machine ID + Ansible](https://goteleport.com/docs/machine-workload-identity/access-guides/ansible/), [Vault SSH + AAP validated pattern](https://developer.hashicorp.com/validated-patterns/vault/integrate-vault-ssh-with-ansible-automation-platform) — both write a key file on the automation host
- [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh) — network-identity substitution; the in-mesh alternative
- [Deno Claw Patrol](https://deno.com/blog/clawpatrol) — network-layer SSH gating, the comparison.md counterpart
- Ansible `ssh` connection plugin docs — `SSH_AUTH_SOCK` inheritance, ControlPersist defaults
