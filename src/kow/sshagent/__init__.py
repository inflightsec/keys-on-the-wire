"""kow's ssh-agent signing oracle (ADR-0053).

A third seam beside the HTTP injectors and the (proposed) Postgres transport:
kow serves the SSH agent protocol (RFC 9987) on a loopback Unix socket and
signs userauth challenges with vault-held private keys. The client — Ansible,
git, plain ssh — points ``SSH_AUTH_SOCK`` at the socket and never holds key
bytes. Destination policy rides the ``session-bind@openssh.com`` extension
(OpenSSH 8.9+), pinning host public keys per binding.
"""

from kow.sshagent.config import SshBindingSpec, SshSpec
from kow.sshagent.server import SshAgentServer

__all__ = ["SshAgentServer", "SshBindingSpec", "SshSpec"]
