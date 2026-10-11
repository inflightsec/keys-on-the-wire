"""ADR-0050 — `kow binding gcp`, the one-command authoring path.

The tool's entire value is that it cannot emit something the daemon would
reject: every block it prints is parsed through the real `Config` model first.
These tests pin that, the mode-coherence guards, and the two wiring stories
(ADC endpoint vs. hand-wired placeholder).
"""

from __future__ import annotations

import pytest
import yaml

from kow.cli.binding import run_binding
from kow.cli.main import _build_parser
from kow.config import Config

_TARGET = "agent-runner@my-project.iam.gserviceaccount.com"
_SEAT = "kow-seat@my-project.iam.gserviceaccount.com"


def _run(*argv: str) -> tuple[int, str, str]:
    parser = _build_parser()
    args = parser.parse_args(["binding", "gcp", *argv])
    import io
    import sys

    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = run_binding(args)
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


def _as_config(block: str) -> Config:
    """Parse the emitted block the way an operator's bindings.yaml would."""
    doc = yaml.safe_load(
        "version: 1\nbinding_source: file\naudit:\n  path: /tmp/x.jsonl\nsecrets:\n" + block
    )
    return Config.model_validate(doc)


def test_emits_a_config_the_daemon_accepts() -> None:
    code, out, err = _run(
        "--target", _TARGET, "--host", "bigquery.googleapis.com", "--scope", "bigquery.readonly"
    )
    assert code == 0
    cfg = _as_config(out)
    spec = cfg.secrets["GCP"]
    assert spec.inject.type == "gcp_service_account"
    assert spec.inject.mode == "impersonate"  # the safe default, unasked
    assert spec.inject.service_account_email == _TARGET
    assert cfg.credential_endpoint is not None
    assert cfg.credential_endpoint.binding == "GCP"
    assert "GCE_METADATA_HOST" in err  # the consumer wiring is never left implicit


def test_placeholder_is_token_shaped_and_unique() -> None:
    """The credential endpoint hands this string to real SDKs, some of which
    check the prefix before using it."""
    _, first, _ = _run("--target", _TARGET, "--host", "h.googleapis.com", "--scope", "x.read")
    _, second, _ = _run("--target", _TARGET, "--host", "h.googleapis.com", "--scope", "x.read")
    ph1 = _as_config(first).secrets["GCP"].placeholder
    ph2 = _as_config(second).secrets["GCP"].placeholder
    assert ph1.startswith("ya29.")
    assert "PLACEHOLDER" in ph1
    assert ph1 != ph2  # minted per invocation, never a fixed string


def test_bare_scope_names_are_expanded() -> None:
    _, out, _ = _run(
        "--target",
        _TARGET,
        "--host",
        "bigquery.googleapis.com",
        "--scope",
        "bigquery.readonly",
        "--scope",
        "https://www.googleapis.com/auth/devstorage.read_only",
    )
    scopes = _as_config(out).secrets["GCP"].inject.scopes
    assert scopes == (
        "https://www.googleapis.com/auth/bigquery.readonly "
        "https://www.googleapis.com/auth/devstorage.read_only"
    )


def test_scoping_flags_reach_the_binding() -> None:
    _, out, _ = _run(
        "--target",
        _TARGET,
        "--host",
        "bigquery.googleapis.com",
        "--scope",
        "bigquery.readonly",
        "--methods",
        "GET,POST",
        "--paths",
        "/bigquery/v2/**",
    )
    binding = _as_config(out).secrets["GCP"].bindings[0]
    assert binding.methods == ["GET", "POST"]
    assert binding.paths == ["/bigquery/v2/**"]


def test_seat_key_mode_names_the_vault_entry() -> None:
    code, out, err = _run(
        "--target",
        _TARGET,
        "--host",
        "bigquery.googleapis.com",
        "--scope",
        "bigquery.readonly",
        "--source",
        "seat_key",
        "--seat",
        _SEAT,
        "--key-secret",
        "GCP_SEAT_KEY",
    )
    assert code == 0
    inject = _as_config(out).secrets["GCP"].inject
    assert inject.source == "seat_key"
    assert inject.source_service_account_email == _SEAT
    assert inject.private_key_secret == "GCP_SEAT_KEY"
    assert "store the service-account PEM in the vault" in err


def test_adc_mode_says_there_is_no_key_to_store() -> None:
    _, _, err = _run(
        "--target", _TARGET, "--host", "bigquery.googleapis.com", "--scope", "bigquery.readonly"
    )
    assert "no key to store" in err
    assert "serviceAccountTokenCreator" in err


def test_no_endpoint_switches_the_wiring_story() -> None:
    code, out, err = _run(
        "--target",
        _TARGET,
        "--host",
        "bigquery.googleapis.com",
        "--scope",
        "bigquery.readonly",
        "--no-endpoint",
    )
    assert code == 0
    assert "credential_endpoint" not in out
    assert "GCE_METADATA_HOST" not in err
    assert "export GCP=" in err  # the caller must present the placeholder itself


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--mode", "jwt_bearer_grant"], "--key-secret is required"),
        (["--source", "seat_key", "--seat", _SEAT], "requires --seat and --key-secret"),
        (["--key-secret", "SOME_KEY"], "meaningless with --source adc"),
    ],
    ids=["key_mode_without_key", "seat_without_key", "adc_with_key"],
)
def test_incoherent_flags_are_refused_before_printing(argv: list[str], expected: str) -> None:
    code, out, err = _run(
        "--target",
        _TARGET,
        "--host",
        "bigquery.googleapis.com",
        "--scope",
        "bigquery.readonly",
        *argv,
    )
    assert code == 1
    assert out == ""  # nothing printed means nothing pasteable
    assert expected in err


def test_invalid_host_is_refused_by_the_real_parser() -> None:
    """The self-validation gate: a block the daemon would reject never prints."""
    code, out, err = _run("--target", _TARGET, "--host", "not a host", "--scope", "x.read")
    assert code == 1
    assert out == ""
    assert "invalid" in err
