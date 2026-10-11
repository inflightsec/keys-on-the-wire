from __future__ import annotations

import io
import logging
import secrets
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from kow.cli.main import _build_parser
from kow.cli.secret import (
    run_secret,
    run_secret_add,
    run_secret_list,
    run_secret_remove,
    run_secret_rotate,
)


def _make_static_bindings(tmp_path: Path) -> tuple[str, Path]:
    secrets_path = tmp_path / "static-secrets.yaml"
    secrets_path.write_text("secrets: {}\n")
    secrets_path.chmod(0o600)
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
secrets:
  PLACEHOLDER_ONLY:
    placeholder: "avp-PLACEHOLDER-zzzzzzzzzzzzzzzzzzzzz"
    inject:
      header: "Authorization"
      format: "Bearer {{PLACEHOLDER_ONLY}}"
    bindings:
      - host: "api.example.com"
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {secrets_path}
"""
    )
    return str(config_path), secrets_path


def _make_bws_bindings(tmp_path: Path) -> str:
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
secrets:
  PLACEHOLDER_ONLY:
    placeholder: "avp-PLACEHOLDER-zzzzzzzzzzzzzzzzzzzzz"
    inject:
      header: "Authorization"
      format: "Bearer {{PLACEHOLDER_ONLY}}"
    bindings:
      - host: "api.example.com"
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: bws
  config:
    type: bws
    organization_id: "org-1"
    access_token_path: "{tmp_path / "bws-token"}"
    state_path: "{tmp_path / "bws-state.json"}"
"""
    )
    return str(config_path)


def _load_secret_map(path: Path) -> dict[str, str]:
    raw = yaml.safe_load(path.read_text())
    return raw["secrets"]


def test_add_via_getpass_writes_entry(tmp_path: Path, monkeypatch, capsys) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "alpha")

    rc = run_secret_add("FOO", config_path, False)

    assert rc == 0
    assert _load_secret_map(secrets_path) == {"FOO": "alpha"}
    assert "added secret 'FOO'" in capsys.readouterr().err


def test_add_via_stdin_reads_value(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO("thevalue\n"))

    rc = run_secret_add("FOO", config_path, True)

    assert rc == 0
    assert _load_secret_map(secrets_path) == {"FOO": "thevalue"}


_PEM = (
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n"
    "AgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDu\n"
    "-----END PRIVATE KEY-----\n"
)


def test_stdin_truncates_a_pem_which_is_why_stdin_raw_exists(tmp_path: Path, monkeypatch) -> None:
    """Pins the trap rather than only the fix. `--stdin` reads ONE line, so a
    PEM piped into it stores `-----BEGIN PRIVATE KEY-----` and reports success —
    a truncated signing key that fails at the far end with an unrelated error."""
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PEM))

    assert run_secret_add("FOO", config_path, True) == 0
    assert _load_secret_map(secrets_path) == {"FOO": "-----BEGIN PRIVATE KEY-----"}


def test_add_via_stdin_raw_keeps_every_line(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PEM))

    assert run_secret_add("FOO", config_path, False, raw_stdin=True) == 0
    assert _load_secret_map(secrets_path) == {"FOO": _PEM}


def test_stdin_raw_preserves_the_trailing_newline(tmp_path: Path, monkeypatch) -> None:
    """A PEM ends with one and it is part of the file. `--stdin` strips it, which
    is right there and wrong here."""
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO("value\n"))

    assert run_secret_add("FOO", config_path, False, raw_stdin=True) == 0
    assert _load_secret_map(secrets_path) == {"FOO": "value\n"}


def test_stdin_raw_rejects_empty_input(tmp_path: Path, monkeypatch) -> None:
    config_path, _ = _make_static_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    with pytest.raises(SystemExit):
        run_secret_add("FOO", config_path, False, raw_stdin=True)


def test_stdin_and_stdin_raw_are_mutually_exclusive() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["secret", "add", "FOO", "--stdin", "--stdin-raw"])


def test_add_help_text_contains_no_real_values(capsys) -> None:
    parser = _build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["secret", "add", "--help"])

    out = capsys.readouterr().out
    assert "<value>" in out
    for forbidden in ("sk-", "ghp_", "gsk_"):
        assert forbidden not in out


def test_list_returns_names_only(tmp_path: Path, capsys) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.write_text("secrets:\n  ZETA: z\n  ALPHA: a\n  MIDDLE: m\n")

    rc = run_secret_list(config_path)

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == "ALPHA\nMIDDLE\nZETA\n"
    assert captured.err == ""


def test_list_output_contains_no_values(tmp_path: Path, capsys) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    value = secrets.token_hex(32)
    secrets_path.write_text(f"secrets:\n  FOO: {value}\n")

    rc = run_secret_list(config_path)

    captured = capsys.readouterr()
    assert rc == 0
    assert value not in captured.out
    assert value not in captured.err


def test_remove_deletes_entry(tmp_path: Path) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.write_text("secrets:\n  FOO: old\n  BAR: keep\n")

    rc = run_secret_remove("FOO", config_path)

    assert rc == 0
    assert _load_secret_map(secrets_path) == {"BAR": "keep"}


def test_remove_idempotent_on_missing_name(tmp_path: Path, capsys) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    before = secrets_path.read_text()

    rc = run_secret_remove("FOO", config_path)

    assert rc == 0
    assert secrets_path.read_text() == before
    assert "nothing to do" in capsys.readouterr().err


def test_rotate_remove_then_add(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.write_text("secrets:\n  FOO: old\n")
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "new")

    rc = run_secret_rotate("FOO", config_path)

    assert rc == 0
    assert _load_secret_map(secrets_path) == {"FOO": "new"}
    assert "old" not in secrets_path.read_text()


def test_rotate_errors_on_missing_name(tmp_path: Path) -> None:
    config_path, _secrets_path = _make_static_bindings(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        run_secret_rotate("BAR", config_path)

    assert excinfo.value.code != 0
    assert "not present" in str(excinfo.value)


@pytest.mark.parametrize(
    ("handler", "kwargs"),
    [
        (run_secret_add, {"name": "FOO", "from_stdin": True}),
        (run_secret_list, {}),
        (run_secret_remove, {"name": "FOO"}),
        (run_secret_rotate, {"name": "FOO"}),
    ],
)
def test_refuses_non_static_backend(
    tmp_path: Path,
    monkeypatch,
    handler,
    kwargs: dict[str, object],
) -> None:
    config_path = _make_bws_bindings(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO("value\n"))
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "value")

    with pytest.raises(SystemExit) as excinfo:
        handler(config_path=config_path, **kwargs)

    assert excinfo.value.code != 0
    assert "static" in str(excinfo.value)


def test_atomic_write_preserves_0600_perms(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "alpha")

    run_secret_add("FOO", config_path, False)

    assert secrets_path.stat().st_mode & 0o777 == 0o600


def test_atomic_write_preserves_owner(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    before = (secrets_path.stat().st_uid, secrets_path.stat().st_gid)
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "alpha")

    run_secret_add("FOO", config_path, False)

    after = (secrets_path.stat().st_uid, secrets_path.stat().st_gid)
    assert after == before


@pytest.mark.parametrize("name", ["foo", "FOO-BAR", "1FOO", "FOO BAR", "", "foo_bar"])
def test_name_validation_rejects_invalid(tmp_path: Path, name: str) -> None:
    config_path, _secrets_path = _make_static_bindings(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        run_secret_add(name, config_path, False)

    assert name in str(excinfo.value)


def test_never_logs_or_prints_values(
    tmp_path: Path,
    monkeypatch,
    capsys,
    caplog: pytest.LogCaptureFixture,
) -> None:
    config_path, _secrets_path = _make_static_bindings(tmp_path)
    caplog.set_level(logging.INFO, logger="kow")
    values = [secrets.token_hex(32) for _ in range(10)]
    state = {"value": values[0]}

    def fake_getpass(prompt: str) -> str:
        return state["value"]

    monkeypatch.setattr("kow.cli.secret.getpass.getpass", fake_getpass)
    for index, value in enumerate(values):
        state["value"] = value
        name = f"SECRET_{index}"
        assert run_secret_add(name, config_path, False) == 0
        assert run_secret_list(config_path) == 0
        state["value"] = secrets.token_hex(32)
        assert run_secret_rotate(name, config_path) == 0
        assert run_secret_remove(name, config_path) == 0

    captured = capsys.readouterr()
    for value in values:
        assert value not in captured.out
        assert value not in captured.err
        assert value not in caplog.text


def test_run_secret_dispatches_each_verb(monkeypatch) -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    monkeypatch.setattr(
        "kow.cli.secret.run_secret_add",
        lambda name, config_path, from_stdin, raw_stdin=False: (
            calls.append(("add", (name, config_path, from_stdin))) or 0
        ),
    )
    monkeypatch.setattr(
        "kow.cli.secret.run_secret_list",
        lambda config_path: calls.append(("list", (config_path,))) or 0,
    )
    monkeypatch.setattr(
        "kow.cli.secret.run_secret_remove",
        lambda name, config_path: calls.append(("remove", (name, config_path))) or 0,
    )
    monkeypatch.setattr(
        "kow.cli.secret.run_secret_rotate",
        lambda name, config_path: calls.append(("rotate", (name, config_path))) or 0,
    )

    assert run_secret(Namespace(secret_command="add", name="FOO", config="/c", stdin=True)) == 0
    assert run_secret(Namespace(secret_command="list", config="/c")) == 0
    assert run_secret(Namespace(secret_command="remove", name="FOO", config="/c")) == 0
    assert run_secret(Namespace(secret_command="rotate", name="FOO", config="/c")) == 0
    assert calls == [
        ("add", ("FOO", "/c", True)),
        ("list", ("/c",)),
        ("remove", ("FOO", "/c")),
        ("rotate", ("FOO", "/c")),
    ]


def test_secret_without_nested_subcommand_prints_help(capsys) -> None:
    parser = _build_parser()
    secret_parser = parser._subparsers._group_actions[0].choices["secret"]

    rc = run_secret(Namespace(secret_command=None, _secret_parser=secret_parser))

    assert rc == 2
    assert "usage: kow secret" in capsys.readouterr().err


def test_mutating_ops_fail_when_static_file_not_writable(tmp_path: Path, monkeypatch) -> None:
    config_path, _secrets_path = _make_static_bindings(tmp_path)
    monkeypatch.setattr("kow.cli.secret.os.access", lambda path, mode: False)
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "v")

    with pytest.raises(SystemExit) as excinfo:
        run_secret_add("FOO", config_path, False)
    assert "run with sudo as the service user" in str(excinfo.value)


def test_list_works_when_file_is_read_only(tmp_path: Path, monkeypatch, capsys) -> None:
    # `avp secret list` is read-only — must work for diagnostics even when
    # the operator has read but not write access (e.g. service-group member).
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.write_text("secrets:\n  ALPHA: a\n  BETA: b\n")
    monkeypatch.setattr("kow.cli.secret.os.access", lambda path, mode: False)
    rc = run_secret_list(config_path)
    assert rc == 0
    assert capsys.readouterr().out.split() == ["ALPHA", "BETA"]


def test_refuses_symlinked_secrets_file(tmp_path: Path) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    real = tmp_path / "real-secrets.yaml"
    real.write_text("secrets:\n  FOO: bar\n")
    secrets_path.unlink()
    secrets_path.symlink_to(real)
    with pytest.raises(SystemExit) as excinfo:
        run_secret_list(config_path)
    assert "symlink" in str(excinfo.value)


def test_refuses_group_world_accessible_parent_dir(tmp_path: Path, monkeypatch) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.parent.chmod(0o755)
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "v")
    try:
        with pytest.raises(SystemExit) as excinfo:
            run_secret_add("FOO", config_path, False)
        assert "group/world" in str(excinfo.value)
    finally:
        secrets_path.parent.chmod(0o700)


def test_atomic_write_failure_keeps_original_file_and_cleans_temp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path, secrets_path = _make_static_bindings(tmp_path)
    secrets_path.write_text("secrets:\n  FOO: old\n")
    original = secrets_path.read_text()
    monkeypatch.setattr("kow.cli.secret.getpass.getpass", lambda prompt: "new")
    monkeypatch.setattr(
        "kow.cli.secret.os.replace",
        lambda src, dst: (_ for _ in ()).throw(OSError("boom")),
    )

    with pytest.raises(SystemExit) as excinfo:
        run_secret_add("BAR", config_path, False)

    assert "could not update static secrets file" in str(excinfo.value)
    assert secrets_path.read_text() == original
    assert list(tmp_path.glob(f".{secrets_path.name}.tmp-*")) == []
