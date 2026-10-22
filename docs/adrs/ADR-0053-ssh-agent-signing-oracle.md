---
status: proposed
date: 2026-09-14
relates_to: ADR-0027/0028 (signing injectors), ADR-0049 (the terminate-and-reoriginate precedent this deliberately does NOT follow), ADR-0012 (per-uid trust), ADR-0023 (closed audit event set), ADR-0047 (scoping philosophy)
---

# ADR-0053: SSH support — an ssh-agent signing oracle, not a transport

## Context

SSH support, with Ansible as the driving consumer: playbooks run from an agent-operated machine, and the keys authenticating those connections must never enter the agent's address space.

SSH fits kow's existing shapes worse than Postgres did. **It is not an injector** — publickey auth never puts the credential on the wire, so there are no bytes to substitute. **Terminate-and-reoriginate is disproportionately expensive**: the ADR-0049 move would mean hand-implementing RFC 4253 transport, RFC 4252 userauth and RFC 4254 channels on both legs, an order of magnitude more handshake crypto than SCRAM, in a project whose highest risk is already its own handshake code. The obvious libraries fail constraint 9 (paramiko LGPL, AsyncSSH EPL-2.0). And it buys nothing, because SSH already ships a broker protocol.

**That protocol is ssh-agent** ([RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)): keys live in the agent, clients send `SIGN_REQUEST` and get signatures back, the key never crosses the socket. It is G1 by construction, and every serious product here is an agent-protocol server.

Vault, Teleport and step-ca converge on the **certificate** pattern, which hands the client a live keypair plus cert — and *short-lived is not zero*, the distinction ADR-0049 already named. A prompt-injected agent with a 16-hour cert has 16 hours; one that can only ask kow for a single policy-checked signature has nothing to exfiltrate.

**OpenSSH destination-constrained keys** are the state of the art for per-destination policy inside the protocol: the client sends `session-bind@openssh.com` carrying the server's host key, session identifier and signature before any sign request, and the agent refuses non-permitted destinations. That is kow's binding model expressed cryptographically — anchored to *possession of the host key*, strictly stronger than the DNS-name matching G3 does over HTTP.

## Decision

**Ship SSH as a third seam: kow serves the ssh-agent protocol on a loopback Unix socket as a policy-enforcing signing oracle.** Not an injector, not a terminated transport. The precedent is ADR-0027/0028 — kow already signs with vault-held keys the agent never sees.

- **Surface.** An opt-in, experimental `ssh:` section; a `0600` Unix socket; `kow env` exports `SSH_AUTH_SOCK`. Client-hop access control is `SO_PEERCRED` uid allowlisting, free on a Unix socket where the Postgres TCP listener had to mint a token.
- **Key custody.** Each binding names a backend secret. The private key is fetched just-in-time per sign request, used, and never written to disk or returned on any socket; the public half is derived at binding-resolution time so `REQUEST_IDENTITIES` needs no vault fetch. v1 is Ed25519 and RSA (SHA-256/512) via `cryptography`. Passphrase-encrypted keys are out of scope: the vault is the encryption at rest.
- **Destination policy is session-bind, required by default.** kow verifies the server's signature over the session identifier, matches the session ID from the to-be-signed blob, and checks the host key against the binding's pinned `host_keys:`. With OpenSSH's hostbound userauth the host key is inside the signed blob itself and is cross-checked against the session-bind record — the strongest form, from the very bytes being signed. Bindings may pin `users:`. A blob that is not an RFC 4252 publickey request is refused: kow is an authentication oracle, not a general signing service. Clients that never send session-bind fail closed; `allow_unbound_sessions: true` restores them with **no destination check at all**, audited on every use.
- **Enforcement by omission (G5).** Every refusal returns the protocol's generic `SSH_AGENT_FAILURE`, exactly what a stock agent answers for an unusable key; classes are separated only in the audit log. `REQUEST_IDENTITIES` lists only resolved bindings' public keys. `ADD_IDENTITY`, `REMOVE_IDENTITY` and `LOCK` are refused — the key set is operator config, not client state.
- **Audit (ADR-0023 contract bump).** `ssh_session_bound`, `ssh_sign_allowed`, `ssh_sign_denied`, with declared field allowlists, never key material or the signed blob. G6 ordering lands where the credential act is: `ssh_sign_allowed` is fsynced **before the signature bytes reach the client socket**, because the signature is the injection.
- **What kow does not control, stated plainly.** kow authorizes the handshake and is not in the data path. An approved session lives entirely outside kow, so there is no splice to cut: `max_session_age` has no analogue and `kow ssh kill` cannot exist. G8 degrades to *authentication-time* freshness — rotating the key stops new sessions within the cache TTL and does nothing to live ones. kow also cannot scope what a session does; per ADR-0047 the narrowing lever is server-side (`authorized_keys` `command=`/`restrict`, a dedicated automation user).

Ansible is the reference consumer: one env var, and remove `ansible_ssh_private_key_file`. Two operational notes belong in the docs — `ControlPersist` means one audited authentication can carry many tasks, bounded by its timeout rather than by kow, and `forks` make the listener concurrent from day one.

## Rejected alternatives

- **Terminate-and-reoriginate.** Buys `max_session_age` and a kill switch at the cost of kow becoming an SSH implementation. A future ADR if session lifetime ever dominates, probably a separate binary.
- **kow as SSH CA.** Right for fleets already running a CA, and `docs/comparison.md` should route people there. Rejected because the client holds a live credential and every target needs `TrustedUserCAKeys`. Teleport's `tbot` and the Vault+AAP pattern both materialize a key *file on the automation host* — their win is ephemerality, not absence.
- **Vault-style OTP.** Needs a helper on every target, inverting kow's zero-target-footprint property.
- **Temp file plus `ssh -i`.** G1 dies immediately. Named because it is what ad-hoc scripts do today.
- **1Password/Bitwarden agents.** They prove the pattern but gate on a human prompt, which is a bug for automation: `forks: 10` is a prompt storm. No per-destination binding, no audit, no headless mode.
- **Network-identity substitution (Tailscale SSH and friends).** The strongest alternative *inside the mesh*, and `docs/is-it-for-you.md` should say so. Not the same control: the *node* becomes the credential, so any local process can SSH wherever ACLs allow with no per-use decision and no audit, and only tailnet destinations are covered.

## Consequences

**Good.** G1 extends to the credential class guarding the operator's own fleet, with no new handshake crypto, inside a 20-year-old protocol whose reference implementation *is* the policy model. Zero footprint on targets. Ansible integration is one environment variable. The seam generalizes to any future agent-socket protocol.

**Bad.** A third protocol surface and a second long-lived listener, concurrent from day one. The T-3 caveat carries over in oracle form: a poisoned dependency at an allowlisted uid gains temporary *use*, never *possession*, bounded and audited, but while resident it authenticates as the agent does. The destination guarantee depends on client cooperation, and the opt-out silently reduces kow to key custody without destination policy for that binding. kow gains no session-lifetime control, a *weaker* post-auth story than the Postgres transport. Host-key pinning imports a known_hosts-shaped maintenance burden: a re-keyed server is an outage until re-pinned.

**Out of scope (v1).** Certificates, FIDO/`sk-` keys, passphrase-protected keys, agent forwarding, `ssh_config` generation, session recording, and any SSH client or server implementation. PKCS#11 stays put, since hardware custody already beats vault custody.

## Implementation note (v1, 2026-09-16)

Shipped in `src/kow/sshagent/` with `tests/test_sshagent.py`; audit contract bumped to v5. Threaded listener, thread-per-connection capped at 64, 30s idle timeout, 256 KiB message cap, ≤16 session binds per connection with a duplicate-id poison rule. `host_keys:` entries are OpenSSH public key lines compared blob-for-blob; `allowed_uids` is mandatory, with no "any uid" spelling. Policy is a pure function (`decide_sign`) mirroring `decide()`, and the server owns the fsync-before-signature ordering. Every refusal answers the single-byte `SSH_AGENT_FAILURE`, verified byte-identical across seven denial classes.

Still open: interop vectors against real OpenSSH builds (in-tree vectors are real but synthetic), a `kow ssh pin` helper, and `kow doctor` checks.

## References

- [RFC 9987 — SSH Agent Protocol](https://www.rfc-editor.org/rfc/rfc9987.html); [OpenSSH agent-restrict](https://www.openssh.org/agent-restrict.html); RFC 4252, RFC 4253 (cited to justify *not* implementing it)
- The certificate pattern: [Vault SSH](https://developer.hashicorp.com/vault/docs/secrets/ssh), [Teleport](https://goteleport.com/docs/reference/architecture/authentication/), [Smallstep](https://smallstep.com/blog/diy-single-sign-on-for-ssh/). Both [Teleport+Ansible](https://goteleport.com/docs/machine-workload-identity/access-guides/ansible/) and [Vault+AAP](https://developer.hashicorp.com/validated-patterns/vault/integrate-vault-ssh-with-ansible-automation-platform) write a key file on the automation host.
- The agent-protocol field: [1Password](https://www.1password.dev/ssh/agent/security), [Bitwarden](https://bitwarden.com/help/ssh-agent/), Secretive. [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh) is the in-mesh alternative.
