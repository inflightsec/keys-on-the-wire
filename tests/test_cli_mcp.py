"""Tests for `avp mcp install` — the MCP-server credential broker (ADR-0040).

Two load-bearing guarantees, mirrored from the binding-note tests:
1. The emitted vault note round-trips through the daemon's own
   ``parse_notes_binding`` into a valid ``ParsedBinding`` (marker, ``{secret}``,
   host) — the note is a binding the daemon will accept.
2. The per-server env block carries the right proxy/CA/bypass vars for the runtime,
   and the command never carries the real credential — only the placeholder sentinel.
"""

from __future__ import annotations

import shlex
import types

import kow.cli.mcp as mcp
from kow.cli.main import main
from kow.cli.mcp import _client_argv, _env_block
from kow.notes_binding import NOTES_MARKER, ParsedBinding, parse_notes_binding
from kow.placeholders import PLACEHOLDER_PREFIX

_PH = "avp-PLACEHOLDER-test-0000000000"
_GH = [
    "mcp",
    "install",
    "github",
    "--host",
    "api.github.com",
    "--env-var",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
]
_CA = "/etc/kow/mitmproxy-ca-cert.pem"


def _run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _roundtrip(note: str, name: str = "GITHUB_PERSONAL_ACCESS_TOKEN"):
    return parse_notes_binding(secret_name=name, placeholder=_PH, note=note)


# --- ISC-3: note round-trips through the real parser ---


def test_install_note_roundtrips_to_valid_binding(capsys):
    code, out, _ = _run(_GH, capsys)
    assert code == 0
    assert out.splitlines()[0] == NOTES_MARKER  # marker first, always
    result = _roundtrip(out)
    assert isinstance(result, ParsedBinding)
    assert result.spec.bindings[0].host == "api.github.com"


# --- ISC-4: placeholder minted by default; --no-placeholder omits it ---


def test_placeholder_minted_by_default(capsys):
    _code, out, _err = _run(_GH, capsys)
    assert f"placeholder: {PLACEHOLDER_PREFIX}" in out


def test_no_placeholder_omits_it(capsys):
    code, out, err = _run([*_GH, "--no-placeholder"], capsys)
    assert code == 0
    assert "placeholder:" not in out
    assert "kow env" in err  # tells the operator how to resolve the derived placeholder


# --- ISC-5: --format must contain {secret} ---


def test_format_without_secret_token_is_rejected(capsys):
    code, _out, err = _run([*_GH, "--format", "Bearer nope"], capsys)
    assert code != 0
    assert "{secret}" in err


# --- ISC-6/7/8: env block per runtime ---


def _block(runtime):
    return _env_block(
        runtime=runtime,
        proxy_url="http://127.0.0.1:8080",
        ca_cert=_CA,
        env_var="GITHUB_PERSONAL_ACCESS_TOKEN",
        placeholder_value=_PH,
    )


def test_env_block_common_vars_all_runtimes():
    for runtime in ("node", "python", "go", "auto"):
        b = _block(runtime)
        assert b["HTTPS_PROXY"] == "http://127.0.0.1:8080"
        assert b["HTTP_PROXY"] == "http://127.0.0.1:8080"
        assert b["NO_PROXY"] == "localhost,127.0.0.1"
        assert b["GITHUB_PERSONAL_ACCESS_TOKEN"] == _PH


def test_env_block_node():
    b = _block("node")
    assert b["NODE_USE_ENV_PROXY"] == "1"
    assert b["NODE_EXTRA_CA_CERTS"] == _CA
    assert "REQUESTS_CA_BUNDLE" not in b


def test_env_block_python():
    b = _block("python")
    assert b["REQUESTS_CA_BUNDLE"] == _CA
    assert b["SSL_CERT_FILE"] == _CA
    assert "NODE_USE_ENV_PROXY" not in b  # no undici bypass for a python server


def test_env_block_go():
    b = _block("go")
    assert b["SSL_CERT_FILE"] == _CA
    assert "NODE_USE_ENV_PROXY" not in b
    assert "REQUESTS_CA_BUNDLE" not in b


def test_env_block_auto_is_superset():
    b = _block("auto")
    for key in ("NODE_USE_ENV_PROXY", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        assert key in b


# --- ISC-10: client command rendering ---


def test_client_argv_claude_code():
    argv = _client_argv(
        client="claude-code", server="github", env_block=_block("node"), server_cmd=[]
    )
    assert argv[:4] == ["claude", "mcp", "add", "github"]
    assert "--env" in argv
    assert f"GITHUB_PERSONAL_ACCESS_TOKEN={_PH}" in argv
    assert "NODE_USE_ENV_PROXY=1" in argv


def test_client_argv_codex_with_server_cmd():
    argv = _client_argv(
        client="codex",
        server="github",
        env_block=_block("node"),
        server_cmd=["npx", "-y", "server-github"],
    )
    assert argv[0] == "codex"
    assert argv[-3:] == ["npx", "-y", "server-github"]
    assert "--" in argv


# --- ISC-9: propose mode prints both artifacts and writes nothing ---


def test_propose_mode_prints_both_and_writes_nothing(capsys, monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("subprocess.run must not be called without --apply")

    monkeypatch.setattr(mcp.subprocess, "run", _boom)
    code, out, err = _run(_GH, capsys)
    assert code == 0
    assert NOTES_MARKER in out  # the vault note (paste artifact) on stdout
    assert "claude mcp add github" in err  # both client commands on stderr
    assert "codex mcp add github" in err


# --- ISC-11: --apply runs the client CLI, once per client, never with a real secret ---


def test_apply_calls_subprocess_per_client(capsys, monkeypatch):
    calls = []

    def _fake_run(argv, check=False):  # noqa: ARG001
        calls.append(argv)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(mcp.subprocess, "run", _fake_run)
    code, _out, _err = _run(
        [*_GH, "--runtime", "node", "--apply", "--server-cmd", "npx -y server-github"], capsys
    )
    assert code == 0
    assert len(calls) == 2  # claude-code + codex by default
    binaries = {argv[0] for argv in calls}
    assert binaries == {"claude", "codex"}
    for argv in calls:
        assert argv[1:4] == ["mcp", "add", "github"]
        # the injected credential value is the placeholder sentinel, never a real key
        env_pairs = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--env"]
        cred = next(p for p in env_pairs if p.startswith("GITHUB_PERSONAL_ACCESS_TOKEN="))
        assert cred.split("=", 1)[1].startswith(PLACEHOLDER_PREFIX)


def test_single_client_selection(capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(
        mcp.subprocess,
        "run",
        lambda argv, check=False: calls.append(argv) or types.SimpleNamespace(returncode=0),  # noqa: ARG005
    )
    code, _out, _err = _run(
        [*_GH, "--client", "claude-code", "--apply", "--server-cmd", "run-it"], capsys
    )
    assert code == 0
    assert len(calls) == 1
    assert calls[0][0] == "claude"


# --- ISC-13 (Anti): the real credential value is never emitted ---


def test_only_placeholder_sentinel_is_emitted(capsys):
    _code, out, err = _run(_GH, capsys)
    combined = out + err
    # the only credential-shaped token present is the placeholder sentinel
    assert PLACEHOLDER_PREFIX in combined
    # and the internal validation sentinel never leaks into operator output
    assert "mcpinstallvalidatesentinel" not in combined


# --- misuse ---


def test_mcp_with_no_subcommand_errors(capsys):
    code, _out, err = _run(["mcp"], capsys)
    assert code != 0
    assert err


def test_malformed_host_is_refused(capsys):
    code, _out, err = _run(
        ["mcp", "install", "x", "--host", "http://api.x.com", "--env-var", "X_KEY"], capsys
    )
    assert code != 0
    assert "invalid" in err.lower()


# --- CRITICAL: YAML line-injection via note-bound fields must not override the host ---


def test_header_newline_injection_is_rejected(capsys):
    # A newline in --header (derived from untrusted docs) could inject a second
    # `host:` line that, under YAML last-wins, redirects the credential to an attacker.
    code, out, err = _run([*_GH, "--header", "Authorization\nhost: evil.attacker.com"], capsys)
    assert code != 0
    assert out == ""  # nothing printed to paste
    assert "control" in err


def test_methods_newline_injection_is_rejected(capsys):
    code, _out, err = _run([*_GH, "--methods", "GET\nhost: evil.com"], capsys)
    assert code != 0
    assert "control" in err


def test_host_newline_injection_is_rejected(capsys):
    code, _out, err = _run(
        ["mcp", "install", "gh", "--env-var", "X_KEY", "--host", "api.github.com\nhost: evil.com"],
        capsys,
    )
    assert code != 0
    assert "control" in err


def test_apply_with_no_placeholder_is_refused(capsys):
    code, _out, err = _run([*_GH, "--apply", "--server-cmd", "x", "--no-placeholder"], capsys)
    assert code != 0
    assert "no-placeholder" in err


def test_apply_without_server_cmd_is_refused(capsys):
    # Oracle #2: --apply without --server-cmd would register a broken client entry.
    code, _out, err = _run([*_GH, "--apply"], capsys)
    assert code != 0
    assert "server-cmd" in err


def test_printed_command_is_shell_quoted(capsys):
    # Oracle #1: a metachar in --proxy-url must not make the printed copy-paste command
    # injectable — shlex.join keeps it inside a single quoted --env value.
    code, _out, err = _run(
        [*_GH, "--client", "claude-code", "--proxy-url", "http://x;rm -rf ~ #"], capsys
    )
    assert code == 0
    run_lines = [
        line.strip()
        for line in err.splitlines()
        if line.strip().startswith(("claude mcp add", "codex mcp add"))
    ]
    assert run_lines
    tokens = shlex.split(run_lines[0])
    assert "rm" not in tokens  # metachars stayed inside the quoted --env value


# --- H1: Unicode line-break YAML injection (NEL/LS/PS) must be rejected ---


def test_unicode_line_separator_injection_is_rejected(capsys):
    # U+2028 is a PyYAML line break but not ASCII \n; a docs-derived --header using it
    # could inject a methods:/paths: line that widens scope while the host is unchanged.
    payload = "Authorization methods: [GET, POST, PUT, DELETE]"
    code, out, err = _run([*_GH, "--header", payload], capsys)
    assert code != 0
    assert out == ""
    assert "control" in err or "separator" in err


def test_nel_and_ps_injection_rejected(capsys):
    for ch in ("", " "):
        code, _out, err = _run([*_GH, "--methods", f'GET{ch}paths: ["/**"]'], capsys)
        assert code != 0, f"char U+{ord(ch):04X} not rejected"
        assert "control" in err or "separator" in err


# --- correctness blocker: default proxy port must be the canonical 14322 ---


def test_default_proxy_url_is_canonical_port(capsys):
    _code, _out, err = _run([*_GH, "--client", "claude-code"], capsys)
    assert "HTTPS_PROXY=http://127.0.0.1:14322" in err
    assert "127.0.0.1:8080" not in err


# --- multi-host, methods, paths, go runtime land correctly ---


def test_multihost_note_roundtrips(capsys):
    code, out, _ = _run(
        [
            "mcp",
            "install",
            "svc",
            "--host",
            "api.example.com",
            "--host",
            "files.example.com",
            "--env-var",
            "SVC_TOKEN",
            "--format",
            "{secret}",
        ],
        capsys,
    )
    assert code == 0
    result = _roundtrip(out, name="SVC_TOKEN")
    assert isinstance(result, ParsedBinding)
    assert {b.host for b in result.spec.bindings} == {"api.example.com", "files.example.com"}


def test_methods_and_paths_land_in_note(capsys):
    code, out, _ = _run([*_GH, "--methods", "GET,POST", "--paths", "/v1/**,/user"], capsys)
    assert code == 0
    assert "methods: [GET, POST]" in out
    assert "paths:" in out and "/v1/**" in out
    assert isinstance(_roundtrip(out), ParsedBinding)


def test_runtime_go_end_to_end(capsys):
    _code, _out, err = _run([*_GH, "--runtime", "go", "--client", "claude-code"], capsys)
    assert "SSL_CERT_FILE=" in err
    assert "NODE_USE_ENV_PROXY" not in err  # go server gets no node bypass flag


def test_empty_host_is_refused(capsys):
    code, _out, err = _run(["mcp", "install", "x", "--host", "", "--env-var", "X_KEY"], capsys)
    assert code != 0
    assert err


# --- --apply failure semantics + dedup ---


def test_apply_nonzero_exit_propagates(capsys, monkeypatch):
    monkeypatch.setattr(
        mcp.subprocess,
        "run",
        lambda argv, check=False: types.SimpleNamespace(returncode=1),  # noqa: ARG005
    )
    code, _out, err = _run([*_GH, "--apply", "--server-cmd", "run-it"], capsys)
    assert code != 0  # install must not claim success when the client rejected the entry
    assert "exited 1" in err


def test_apply_missing_binary_fails_cleanly(capsys, monkeypatch):
    def _no_binary(argv, check=False):  # noqa: ARG001
        raise FileNotFoundError(2, "No such file or directory", argv[0])

    monkeypatch.setattr(mcp.subprocess, "run", _no_binary)
    code, _out, err = _run([*_GH, "--apply", "--server-cmd", "run-it"], capsys)
    assert code != 0
    assert "not found on PATH" in err  # clean message, not a raw traceback


def test_duplicate_client_is_deduped(capsys, monkeypatch):
    calls = []
    monkeypatch.setattr(
        mcp.subprocess,
        "run",
        lambda argv, check=False: calls.append(argv) or types.SimpleNamespace(returncode=0),  # noqa: ARG005
    )
    code, _out, _err = _run(
        [
            *_GH,
            "--client",
            "claude-code",
            "--client",
            "claude-code",
            "--apply",
            "--server-cmd",
            "run-it",
        ],
        capsys,
    )
    assert code == 0
    assert len(calls) == 1  # deduped, not run twice


# --- robustness: bad --server-cmd quoting + non-loopback proxy warning ---


def test_server_cmd_bad_quoting_fails_cleanly(capsys):
    code, _out, err = _run([*_GH, "--server-cmd", 'npx "unclosed'], capsys)
    assert code != 0
    assert "shell-quoting" in err  # clean _die, not a ValueError traceback


def test_non_loopback_proxy_warns(capsys):
    code, _out, err = _run(
        [*_GH, "--client", "claude-code", "--proxy-url", "http://evil.example:14322"], capsys
    )
    assert code == 0  # fail-closed (only placeholder in env), so warn not refuse
    assert "not loopback" in err


def test_smoke_shell_metachars_are_quoted(capsys):
    # Two layers since the RFC 7230 token-grammar check (2026-10-11). A name
    # carrying ';' or a space is no longer a valid HTTP field name, so it is
    # refused at validation BEFORE any shell could ever see it:
    refused = "X'; curl https://evil #"
    code, _out, _err = _run([*_GH, "--format", "{secret}", "--header", refused, "--smoke"], capsys)
    assert code != 0
    # But backtick, $ and ' ARE legal tchars, so a token-valid name can still
    # be shell-hostile — the printed smoke command must shlex-quote it so a
    # copy-paste cannot execute anything.
    hostile = "X'`id`$PATH"
    code, _out, err = _run([*_GH, "--format", "{secret}", "--header", hostile, "--smoke"], capsys)
    assert code == 0
    smoke_lines = [line for line in err.splitlines() if line.strip().startswith("HTTPS_PROXY=")]
    assert smoke_lines
    line = smoke_lines[0].strip()
    tokens = shlex.split(line)
    assert tokens.count("curl") == 1  # nothing injected a second command
    # And the hostile name survives quoting intact rather than being mangled.
    assert any(hostile in t for t in tokens)


def test_host_with_authority_injection_is_refused(capsys):
    # `@` reinterprets URL authority — the daemon's parser must reject it fail-closed.
    code, _out, err = _run(
        ["mcp", "install", "x", "--host", "evil@real.com", "--env-var", "X_KEY"], capsys
    )
    assert code != 0
    assert err


# --- argv flag-smuggling: server name / env-var must be safe as client argv tokens ---


def test_server_name_with_metachars_is_refused(capsys):
    code, _out, err = _run(
        ["mcp", "install", "bad/name", "--host", "api.github.com", "--env-var", "X_KEY"], capsys
    )
    assert code != 0
    assert "server name" in err


def test_env_var_leading_dash_is_refused(capsys):
    # argparse may catch a bare leading dash first; embed it so our validator is exercised.
    code, _out, err = _run(
        ["mcp", "install", "gh", "--host", "api.github.com", "--env-var", "BAD-VAR"], capsys
    )
    assert code != 0
    assert "env-var" in err


def test_env_var_leading_digit_is_refused(capsys):
    code, _out, err = _run(
        ["mcp", "install", "gh", "--host", "api.github.com", "--env-var", "9BAD"], capsys
    )
    assert code != 0
    assert "env-var" in err
