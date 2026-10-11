# Is keys-on-the-wire for you?

> The evaluator's page. If you are deciding whether kow fits your setup, start here. For the deeper "why" in plain language see [Concepts](concepts.md); for the complete threat model see [architecture.md §2](architecture.md#2-threat-model); for how it stacks up against Vault Agent, Doppler, `op run`, `superfly/tokenizer` and others see [Comparison](comparison.md).

kow is a small local proxy that keeps API keys out of your AI agent's process. The agent holds a worthless placeholder; kow swaps in the real secret on the wire, on the way out to the upstream API, so a compromised or prompt-injected agent has nothing to steal.

## What it does

- **Keeps real credential bytes out of the calling process.** The agent only ever holds a placeholder like `sk-PLACEHOLDER-...`; the real key is fetched from your vault just-in-time and injected on the outbound connection, where the agent can't see it.
- **Binds each secret to its own destinations.** A secret is injected only for the hosts its binding names, optionally narrowed by HTTP method and URL path, and checked against the connection's *real* TLS host rather than the spoofable `Host:` header. That is what blocks exfil-by-redirect.
- **Fails closed.** Any uncertainty means no real secret is injected, never a guessed or degraded one.
- **Records every decision.** An append-only, local-only audit log notes which secret went where and why, and never records secret values, headers, or bodies.
- **Sources from the vault you already run.** Bitwarden Secrets Manager, Google Secret Manager, or AWS Secrets Manager today. kow never becomes a second place your secrets live.

## What it deliberately does not do

Naming the boundaries matters, because this layer is easy to over-trust:

- **It is not an egress firewall.** It does not decide *where* your agent may connect, only *which secret* may be injected for a destination. Pair it with OpenSnitch, nftables, or firewalld for actual network isolation.
- **It stops theft, not misuse.** If you bind a key to a host with no method or path limits, a prompt-injected agent can still spend that key's authority within scope. Tightening the binding's scope (`methods:` and `paths:`) is the lever that turns a read key into a read-only key.
- **It injects on the request, not the response.** An upstream that echoes your `Authorization` header back in its response body breaks the isolation for that one exchange.
- **It is not a vault, key manager, or rotation system.** It is the wire-substitution layer *between* your existing vault and your agent, nothing more.
- **Same-UID and host-root attackers are out of scope.** Code running as the proxy's own user can use the proxy as an authenticated channel, and kow does not stop it. Narrow each binding's `methods:` and `paths:` to limit what that channel is good for. kow is one layer, not a complete sandbox.

## Why route through it

The payoff is that less is exposed. When, not if, an agent reads a malicious web page, runs a poisoned dependency, or leaks a log, the thing that escapes is a placeholder, not your Stripe key. kow answers two specific and common threats head-on: **prompt injection** (untrusted text steering the agent into leaking secrets) and **software supply-chain compromise** (a malicious dependency reading the process environment, as in Shai-Hulud). In both, the real secret bytes were never in the agent's memory to take.

## When to reach for it, and when not

Reach for kow when:

- You run agents, or any process, on a single host and want the real keys to never enter that process.
- You already run Bitwarden Secrets Manager or Google Secret Manager and would rather not stand up a second vault.
- You want a thin, auditable layer you can read end-to-end, not a platform.

Look elsewhere, or add another tool alongside it, when:

- You need to gate non-HTTP protocols (Postgres, Kubernetes) or want a full allow/deny policy engine with approval chains. A network-layer agent firewall fits that better; see [Comparison](comparison.md). (SSH is the exception: kow can broker SSH keys as an agent-protocol signing oracle — [ADR-0053](adrs/ADR-0053-ssh-agent-signing-oracle.md), experimental. If your whole fleet is on a Tailscale-style mesh, Tailscale SSH removes the keys entirely for in-mesh hosts and may be the better answer there.)
- You need hard network isolation. That is an egress firewall's job, running *alongside* kow, not instead of it.

If those fit, the [Quickstart](quickstart.md) gets you to a visible substitution in about ten minutes.
