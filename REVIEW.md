# Open review items

Concerns from `scripts/review-pr.sh` that were accepted but not yet fixed. Each line names
where it lives and why it matters. Delete the line in the commit that fixes it.

Review of `release/1.2.0` (2026-11-05, Oracle cross-vendor pass, checked by hand):

- `credential_endpoint.py`: `_Handler` sets no socket timeout, so a local process can hold
  connections open without sending headers and pin one thread each. Loopback only.
- `credential_endpoint.py`: `credential_endpoint.host` accepts `::1`, but `ThreadingHTTPServer`
  is IPv4, so that host fails at bind (`gaierror: Address family for hostname not supported`).
- `injectors/gcp_service_account.py`: at `assertion_ttl_seconds: 60`, `iat` is backdated 60s and
  `exp = iat + ttl`, so the assertion expires the second it is minted. Raise the floor or
  compute `exp` from now.
- `config.py` `resolve_endpoint`: checks only that the binding is `gcp_service_account`, not that
  it injects `Authorization: Bearer`. A custom `header`/`format` loads, then ADC cannot use it.
- `backends/keychain.py` `_keyd_trust_error`: walks the helper's lexical parents; a parent that
  is a symlink has its target checked but not the target's own ancestors. Unconfirmed; depends
  on the real candidate paths.
- `cli/binding.py` `_warn_note_shadows_file`: the delete-note advice ignores method/path
  restrictions when the host sets match. Not checked.
- Not read by Oracle (its secret gate refused them), so not reviewed by AI at all:
  `sshagent/keys.py`, `sshagent/server.py`, `cli/binding.py`, `.github/workflows/specs.yml`.
