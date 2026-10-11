"""macOS Keychain backend (ADR-0046).

Everything here runs against ``_fake_security.py``, a real executable standing
in for ``/usr/bin/security``, so the subprocess boundary — argv, stdin, exit
codes — is genuinely crossed on Linux CI. The live tool is exercised separately
by ``tests/vm-e2e/macos-e2e.sh --keychain``.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kow.backends import (
    BACKEND_REGISTRY,
    BackendUnavailableError,
    BackendWriteConflictError,
    SecretNotFoundError,
    SecretsBackend,
    list_secret_names,
    update_secret,
)
from kow.backends import keychain as kc_mod
from kow.backends.keychain import KeychainBackend, KeychainConfig, _parse_dump, _quote
from kow.secret import Secret
from tests.backends.test_protocol_contract import ProtocolContract

_FAKE = Path(__file__).parent / "_fake_security.py"
SERVICE = "kow-test"


def _install_fake_security(tmp_path, monkeypatch):
    """Install the fake ``security`` as the module's binary and return the
    paths the caller can inspect.

    A plain function rather than only a fixture so ADR-0051's helper tests can
    stand up the *other* transmit path in the same test, which is the only way
    to assert that the two differ in exactly one respect.
    """
    binpath = tmp_path / "security"
    shutil.copy(_FAKE, binpath)
    binpath.chmod(binpath.stat().st_mode | stat.S_IXUSR)
    # The stub has no shebang-portable interpreter guarantee; run it under the
    # same interpreter the tests use by writing a tiny exec wrapper.
    wrapper = tmp_path / "security-wrapper"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{binpath}" "$@"\n')
    wrapper.chmod(0o755)

    store = tmp_path / "store.json"
    argv_log = tmp_path / "argv.log"
    monkeypatch.setattr(kc_mod, "SECURITY_BIN", str(wrapper))
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)
    monkeypatch.setenv("FAKE_SECURITY_STORE", str(store))
    monkeypatch.setenv("FAKE_SECURITY_ARGV_LOG", str(argv_log))
    return {"store": store, "argv_log": argv_log, "bin": wrapper}


@pytest.fixture
def fake_security(tmp_path, monkeypatch):
    return _install_fake_security(tmp_path, monkeypatch)


def build(**kw) -> KeychainBackend:
    kw.setdefault("service", SERVICE)
    return KeychainBackend(config=KeychainConfig(**kw))


def logged_argv(fake) -> list[list[str]]:
    if not fake["argv_log"].exists():
        return []
    return [json.loads(line) for line in fake["argv_log"].read_text().splitlines()]


# ------------------------------------------------------------------ registry


def test_registered_under_keychain() -> None:
    assert "keychain" in BACKEND_REGISTRY
    backend_cls, config_cls = BACKEND_REGISTRY["keychain"]
    assert backend_cls is KeychainBackend
    assert config_cls is KeychainConfig


def test_reset_registry_restores_keychain() -> None:
    from kow.backends import _reset_registry_for_tests

    _reset_registry_for_tests()
    assert "keychain" in BACKEND_REGISTRY


# -------------------------------------------------------------------- config


def test_config_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        KeychainConfig(service="kow", nonsense=1)  # type: ignore[call-arg]


def test_config_surface_is_exactly_seven_fields() -> None:
    """Anti-bloat: the knob list is the API. Adding one is a decision, not a
    reflex, so it has to break this test first. ``use_helper`` was added by
    ADR-0051 and is the only addition since."""
    assert set(KeychainConfig.model_fields) == {
        "type",
        "service",
        "keychain",
        "secret_prefix",
        "self_check",
        "timeout_seconds",
        "use_helper",
    }


@pytest.mark.parametrize("bad", ["", "   "])
def test_config_rejects_empty_service(bad: str) -> None:
    with pytest.raises(ValidationError):
        KeychainConfig(service=bad)


@pytest.mark.parametrize("bad", [0, -1.0])
def test_config_rejects_nonpositive_timeout(bad: float) -> None:
    with pytest.raises(ValidationError):
        KeychainConfig(timeout_seconds=bad)


def test_init_does_no_subprocess(fake_security) -> None:
    build()
    assert logged_argv(fake_security) == []


def test_repr_names_service_and_no_value(fake_security) -> None:
    b = build()
    b.update("TOKEN", "sk-live-secret")
    assert "kow-test" in repr(b)
    assert "sk-live-secret" not in repr(b)


# --------------------------------------------------------------------- reads


def test_fetch_round_trips(fake_security) -> None:
    b = build()
    b.update("OPENAI_API_KEY", "sk-live-abc123")
    assert b.fetch("OPENAI_API_KEY").reveal() == "sk-live-abc123"


def test_fetch_missing_raises_not_found(fake_security) -> None:
    with pytest.raises(SecretNotFoundError):
        build().fetch("NOPE")


def test_fetch_strips_exactly_one_trailing_newline(fake_security) -> None:
    """`security -w` appends one newline. A value that legitimately ends in
    whitespace must survive; .strip() here would silently corrupt it."""
    b = build()
    b.update("PADDED", "value-with-trailing-space  ")
    assert b.fetch("PADDED").reveal() == "value-with-trailing-space  "


@pytest.mark.parametrize(
    "value",
    [
        'has "double" quotes',
        r"has \backslash",
        "has spaces and\ttabs",
        "$(whoami) `id` ${HOME}",
        "unicode: żółć — ok",
        "'single' quotes",
        r'mixed "\" edge',
    ],
)
def test_quoting_round_trip(fake_security, value: str) -> None:
    """The `security -i` line protocol needs quoting, and a quoting bug stores a
    mangled credential while looking like success. update() read-back-compares,
    so a break here surfaces as a raise, not as corruption."""
    b = build()
    b.update("TRICKY", value)
    assert b.fetch("TRICKY").reveal() == value


def test_locked_keychain_names_the_unlock_command(fake_security, monkeypatch) -> None:
    b = build(self_check="off")
    monkeypatch.setenv("FAKE_SECURITY_FAIL", "locked")
    with pytest.raises(BackendUnavailableError) as e:
        b.fetch("ANY")
    assert "unlock-keychain" in str(e.value)


def test_generic_failure_is_unavailable_not_not_found(fake_security, monkeypatch) -> None:
    b = build(self_check="off")
    monkeypatch.setenv("FAKE_SECURITY_FAIL", "boom")
    with pytest.raises(BackendUnavailableError):
        b.fetch("ANY")


def test_missing_binary_names_the_path(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(kc_mod, "SECURITY_BIN", str(tmp_path / "nope"))
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)
    with pytest.raises(BackendUnavailableError) as e:
        build().fetch("ANY")
    assert "nope" in str(e.value)


def test_non_macos_refuses_on_first_fetch_not_construction(monkeypatch) -> None:
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: False)
    b = build()  # construction must succeed — protocol says __init__ does no I/O
    with pytest.raises(BackendUnavailableError) as e:
        b.fetch("ANY")
    assert "macOS" in str(e.value)


def test_timeout_raises_unavailable(fake_security) -> None:
    slow = Path(fake_security["bin"]).with_name("slow")
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(0o755)
    b = build(self_check="off", timeout_seconds=0.3)
    import kow.backends.keychain as m

    m.SECURITY_BIN = str(slow)
    try:
        with pytest.raises(BackendUnavailableError) as e:
            b.fetch("ANY")
        assert "timed out" in str(e.value)
    finally:
        m.SECURITY_BIN = str(fake_security["bin"])


# --------------------------------------------------------------------- lists


def test_list_returns_only_this_service(fake_security) -> None:
    build().update("MINE", "v1")
    other = KeychainBackend(config=KeychainConfig(service="someone-else"))
    other.update("THEIRS", "v2")
    assert build().list_secret_names() == ["MINE"]


def test_list_is_sorted(fake_security) -> None:
    b = build()
    for n in ("ZED", "ALPHA", "MID"):
        b.update(n, "v")
    assert b.list_secret_names() == ["ALPHA", "MID", "ZED"]


def test_list_honours_secret_prefix(fake_security) -> None:
    build().update("KOW_ONE", "v")
    build().update("KOW_TWO", "v")
    scoped = build(secret_prefix="KOW_")
    # Written unscoped, then read through a prefix-bounded backend.
    assert scoped.list_secret_names() == ["KOW_ONE", "KOW_TWO"]
    build().update("OTHER", "v")
    assert scoped.list_secret_names() == ["KOW_ONE", "KOW_TWO"]


def test_list_secret_names_helper_dispatches(fake_security) -> None:
    b = build()
    b.update("HELPER", "v")
    assert list_secret_names(b) == ["HELPER"]


def test_dump_parser_skips_hex_encoded_attributes() -> None:
    """Non-printable attribute values come back as `<blob>=0x...`; guessing at
    them is worse than skipping, and kow names are always plain ASCII."""
    dump = (
        'keychain: "/x"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>=0x4F4B  "OK"\n    "svce"<blob>="kow-test"\n'
        'keychain: "/x"\nclass: "genp"\nattributes:\n'
        '    "acct"<blob>="GOOD"\n    "svce"<blob>="kow-test"\n'
    )
    assert _parse_dump(dump, "kow-test") == ["GOOD"]


def test_dump_parser_dedupes_repeated_pairs() -> None:
    block = 'keychain: "/x"\nclass: "genp"\n    "acct"<blob>="A"\n    "svce"<blob>="s"\n'
    assert _parse_dump(block * 3, "s") == ["A"]


# -------------------------------------------------------------------- writes


def test_update_keeps_the_value_off_argv(fake_security) -> None:
    """The macOS process table is world-readable. A value on argv is a value
    published to every local user for the life of the call."""
    b = build()
    b.update("TOKEN", "sk-live-NEVER-ON-ARGV")
    for argv in logged_argv(fake_security):
        assert "sk-live-NEVER-ON-ARGV" not in " ".join(argv)


def test_update_uses_interactive_mode(fake_security) -> None:
    build().update("TOKEN", "v")
    assert ["-i"] in logged_argv(fake_security)


def test_update_overwrites_existing(fake_security) -> None:
    b = build()
    b.update("TOKEN", "old")
    b.update("TOKEN", "new")
    assert b.fetch("TOKEN").reveal() == "new"


def test_update_secret_helper_dispatches(fake_security) -> None:
    b = build()
    update_secret(b, "VIA_HELPER", "v")
    assert b.fetch("VIA_HELPER").reveal() == "v"


def test_update_rejects_multiline_values(fake_security) -> None:
    with pytest.raises(BackendUnavailableError) as e:
        build().update("PEM", "-----BEGIN\nkey\n-----END")
    assert "newline" in str(e.value)


def test_update_read_back_mismatch_raises(fake_security, monkeypatch) -> None:
    """Simulate a quoting bug: the write lands mangled. The backend must refuse
    the write rather than report success on a corrupted credential."""
    b = build()

    real_fetch = KeychainBackend.fetch

    def lying_fetch(self, name, ctx=None):  # noqa: ANN001, ANN202
        got = real_fetch(self, name, ctx)
        return Secret(got.reveal() + "-corrupted")

    monkeypatch.setattr(KeychainBackend, "fetch", lying_fetch)
    with pytest.raises(BackendUnavailableError) as e:
        b.update("TOKEN", "value")
    assert "round-trip" in str(e.value)


def test_update_read_back_error_does_not_echo_the_value(fake_security, monkeypatch) -> None:
    b = build()
    monkeypatch.setattr(KeychainBackend, "fetch", lambda self, n, ctx=None: Secret("wrong"))
    with pytest.raises(BackendUnavailableError) as e:
        b.update("TOKEN", "sk-live-TOPSECRET")
    assert "sk-live-TOPSECRET" not in str(e.value)


def test_update_precondition_conflict(fake_security) -> None:
    b = build()
    b.update("TOKEN", "current")
    with pytest.raises(BackendWriteConflictError):
        b.update("TOKEN", "new", expected_current_value="stale")


def test_update_precondition_match_succeeds(fake_security) -> None:
    b = build()
    b.update("TOKEN", "current")
    b.update("TOKEN", "new", expected_current_value="current")
    assert b.fetch("TOKEN").reveal() == "new"


def test_update_precondition_on_missing_item_conflicts(fake_security) -> None:
    with pytest.raises(BackendWriteConflictError):
        build().update("ABSENT", "new", expected_current_value="anything")


def test_delete_removes(fake_security) -> None:
    b = build()
    b.update("TOKEN", "v")
    b.delete("TOKEN")
    with pytest.raises(SecretNotFoundError):
        b.fetch("TOKEN")


def test_delete_is_idempotent(fake_security) -> None:
    build().delete("NEVER_EXISTED")  # must not raise


# --------------------------------------------------------------------- scope


@pytest.mark.parametrize("op", ["fetch", "update", "delete"])
def test_out_of_scope_refused_before_touching_the_keychain(fake_security, op: str) -> None:
    b = build(secret_prefix="KOW_")
    with pytest.raises(SecretNotFoundError):
        if op == "fetch":
            b.fetch("OTHER_KEY")
        elif op == "update":
            b.update("OTHER_KEY", "v")
        else:
            b.delete("OTHER_KEY")
    assert logged_argv(fake_security) == []


def test_out_of_scope_message_does_not_echo_the_value(fake_security) -> None:
    b = build(secret_prefix="KOW_")
    with pytest.raises(SecretNotFoundError) as e:
        b.update("OTHER_KEY", "sk-live-TOPSECRET")
    assert "sk-live-TOPSECRET" not in str(e.value)


# ---------------------------------------------------------------- self-check


def test_self_check_deny_refuses_to_start(fake_security, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_SECURITY_FAIL", "locked")
    with pytest.raises(BackendUnavailableError) as e:
        build(self_check="deny").fetch("ANY")
    assert "refusing to start" in str(e.value)


def test_self_check_warn_logs_and_continues(fake_security, monkeypatch, caplog) -> None:
    b = build(self_check="warn")
    monkeypatch.setenv("FAKE_SECURITY_FAIL", "locked")
    with caplog.at_level("WARNING"), pytest.raises(BackendUnavailableError):
        b.fetch("ANY")  # the fetch itself still fails — but on the fetch, not the check
    assert any("continuing" in r.message for r in caplog.records)


def test_self_check_off_skips_the_probe(fake_security) -> None:
    b = build(self_check="off")
    b.update("TOKEN", "v")
    assert not any(a and a[0] == "show-keychain-info" for a in logged_argv(fake_security))


def test_self_check_runs_once(fake_security) -> None:
    b = build()
    b.update("A", "v")
    b.update("B", "v")
    b.fetch("A")
    probes = [a for a in logged_argv(fake_security) if a and a[0] == "show-keychain-info"]
    assert len(probes) == 1


# ------------------------------------------------------------------ keychain


def test_explicit_keychain_path_is_passed_and_expanded(fake_security, monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/testuser")
    b = build(keychain="~/Library/Keychains/kow.keychain-db", self_check="off")
    with pytest.raises(SecretNotFoundError):
        b.fetch("ANY")
    last = logged_argv(fake_security)[-1]
    assert last[-1] == "/home/testuser/Library/Keychains/kow.keychain-db"


def test_default_keychain_passes_no_positional(fake_security) -> None:
    with pytest.raises(SecretNotFoundError):
        build(self_check="off").fetch("ANY")
    assert logged_argv(fake_security)[-1][-1] == "-w"


# ------------------------------------------------------------------- hygiene


def test_module_never_uses_a_shell() -> None:
    src = Path(kc_mod.__file__).read_text()
    assert "shell=True" not in src


def test_module_imports_no_third_party_keychain_package() -> None:
    src = Path(kc_mod.__file__).read_text()
    for banned in ("import keyring", "import objc", "from keyring", "Security.framework"):
        assert banned not in src


def test_security_binary_is_absolute() -> None:
    assert os.path.isabs(kc_mod.SECURITY_BIN)


def test_quote_escapes_backslash_before_quote() -> None:
    assert _quote(r'a"b\c') == r'"a\"b\\c"'


# ------------------------------------------------------------------ contract


class TestKeychainContract(ProtocolContract):
    @pytest.fixture
    def backend(self):
        return KeychainBackend(config=KeychainConfig(service=SERVICE, self_check="off"))

    def test_is_protocol_instance_explicitly(self, backend) -> None:
        assert isinstance(backend, SecretsBackend)


# ------------------------------------------- advisor-surfaced write hardening


@pytest.mark.parametrize(
    "value",
    ["line\nbreak", "carriage\rreturn", "nul\0byte"],
    ids=["newline", "carriage-return", "nul"],
)
def test_update_refuses_bytes_the_line_protocol_cannot_carry(fake_security, value: str) -> None:
    """A newline ends the command line and a NUL ends the C string: either one
    silently stores a PREFIX of the credential, which is the worst outcome
    available because everything downstream still looks fine."""
    with pytest.raises(BackendUnavailableError):
        build().update("TOKEN", value)


def test_update_refuses_untransmittable_name(fake_security) -> None:
    with pytest.raises(BackendUnavailableError):
        build().update("BAD\nNAME", "v")


def test_refusal_happens_before_any_child_is_spawned(fake_security) -> None:
    with pytest.raises(BackendUnavailableError):
        build(self_check="off").update("TOKEN", "bad\nvalue")
    assert logged_argv(fake_security) == []


@pytest.mark.parametrize("bad", ["kow\nother", "kow\0x"])
def test_config_rejects_untransmittable_service(bad: str) -> None:
    with pytest.raises(ValidationError):
        KeychainConfig(service=bad)


def test_failed_create_removes_the_partial_item(fake_security, monkeypatch) -> None:
    """A botched CREATE can be cleaned up — nobody depended on the value yet,
    and a readable mangled credential is worse than none."""
    b = build()
    real_fetch = KeychainBackend.fetch

    def truncating_fetch(self, name, ctx=None):  # noqa: ANN001, ANN202
        got = real_fetch(self, name, ctx)
        return Secret(got.reveal()[:3])

    monkeypatch.setattr(KeychainBackend, "fetch", truncating_fetch)
    with pytest.raises(BackendUnavailableError) as e:
        b.update("FRESH", "full-value")
    assert "removed" in str(e.value)
    # Restore only `fetch` — monkeypatch.undo() would also revert the fixture's
    # SECURITY_BIN and _is_macos patches and the assertion below would test
    # nothing but a Linux refusal.
    monkeypatch.setattr(KeychainBackend, "fetch", real_fetch)
    with pytest.raises(SecretNotFoundError):
        build().fetch("FRESH")


def test_failed_update_keeps_the_item_and_says_so(fake_security, monkeypatch) -> None:
    """A botched UPDATE must NOT delete: the prior value is already gone, so
    deleting takes the consumer from a wrong credential to no credential."""
    b = build()
    b.update("EXISTING", "v1")
    real_fetch = KeychainBackend.fetch

    def truncating_fetch(self, name, ctx=None):  # noqa: ANN001, ANN202
        got = real_fetch(self, name, ctx)
        return Secret(got.reveal()[:2])

    monkeypatch.setattr(KeychainBackend, "fetch", truncating_fetch)
    with pytest.raises(BackendUnavailableError) as e:
        b.update("EXISTING", "v2-longer")
    assert "removed" not in str(e.value)
    assert "re-set it" in str(e.value)
    monkeypatch.setattr(KeychainBackend, "fetch", real_fetch)
    build().fetch("EXISTING")  # still there — must not raise


def test_duplicate_items_refuse_the_write(fake_security) -> None:
    """`add -U`, `find` and `delete` all act on an unspecified first match, so a
    duplicate pair makes the read-back verify the wrong item."""
    b = build()
    b.update("DUPE", "v")
    # Forge a second item with the same (service, account) directly in the store.
    items = json.loads(fake_security["store"].read_text())
    items.append({"acct": "DUPE", "svce": SERVICE, "value": "other"})
    fake_security["store"].write_text(json.dumps(items))
    with pytest.raises(BackendUnavailableError) as e:
        b.update("DUPE", "v2")
    assert "duplicates" in str(e.value)


def test_write_failure_log_never_carries_the_value(fake_security, monkeypatch, caplog) -> None:
    b = build()
    monkeypatch.setattr(KeychainBackend, "fetch", lambda self, n, ctx=None: Secret("x"))
    with caplog.at_level("ERROR"), pytest.raises(BackendUnavailableError):
        b.update("TOKEN", "sk-live-TOPSECRET")
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "sk-live-TOPSECRET" not in joined
    assert "stored-is-prefix" in joined


def test_parse_dump_tally_mode_keeps_duplicates() -> None:
    block = 'keychain: "/x"\nclass: "genp"\n    "acct"<blob>="A"\n    "svce"<blob>="s"\n'
    assert _parse_dump(block * 3, "s", dedupe=False) == ["A", "A", "A"]


# ------------------------------------------------- Oracle review 2026-08-16 (C1-C7)


@pytest.mark.parametrize("bad", ["/tmp/a\nb.keychain-db", "/tmp/a\rb", "/tmp/a\0b"])
def test_config_rejects_untransmittable_keychain_path(bad: str) -> None:
    """C1: the keychain path rides the SAME interactive command line as the
    value. It was the one input not checked for line-protocol-hostile bytes."""
    with pytest.raises(ValidationError):
        KeychainConfig(keychain=bad)


@pytest.mark.parametrize("bad", ['kow"x', "kow\\x", "kow other", "kow;rm"])
def test_config_rejects_unsafe_service_charset(bad: str) -> None:
    """C4: service travels through the command line AND back out of
    dump-keychain's text format. Constrain it once, at the boundary."""
    with pytest.raises(ValidationError):
        KeychainConfig(service=bad)


@pytest.mark.parametrize("good", ["kow", "kow-e2e", "kow.prod", "kow_1", "KOW-2"])
def test_config_accepts_ordinary_service_names(good: str) -> None:
    assert KeychainConfig(service=good).service == good


def test_noisy_but_successful_write_is_accepted(fake_security, monkeypatch, caplog) -> None:
    """C2: `security -i` can emit stderr on a write that landed. Verification
    must run regardless, and a verified value must not be reported as a failure."""
    b = build(self_check="off")
    real = kc_mod.KeychainBackend._run_interactive

    # Raise AFTER the write has actually happened.
    def write_then_complain(self, cmd):  # noqa: ANN001, ANN202
        real(self, cmd)
        raise kc_mod.KeychainError(0, "security: warning about something harmless")

    monkeypatch.setattr(kc_mod.KeychainBackend, "_run_interactive", write_then_complain)
    with caplog.at_level("WARNING"):
        b.update("NOISY", "the-value")  # must NOT raise
    assert b.fetch("NOISY").reveal() == "the-value"
    assert any("verifies" in r.getMessage() for r in caplog.records)


def test_failed_write_that_created_an_item_still_cleans_up(fake_security, monkeypatch) -> None:
    """C3: cleanup used to be reachable only via the read-back branch, so a
    write that errored *after* creating the item skipped its own compensation."""
    b = build(self_check="off")
    real = kc_mod.KeychainBackend._run_interactive

    def write_partial_then_fail(self, cmd):  # noqa: ANN001, ANN202
        # Land a DIFFERENT (mangled) value, then report failure.
        mangled = [*cmd]
        mangled[mangled.index("-w") + 1] = "truncated"
        real(self, mangled)
        raise kc_mod.KeychainError(1, "security: something went wrong")

    monkeypatch.setattr(kc_mod.KeychainBackend, "_run_interactive", write_partial_then_fail)
    with pytest.raises(BackendUnavailableError) as e:
        b.update("PARTIAL", "the-real-value")
    assert "removed" in str(e.value)
    assert "security" in str(e.value)  # the original cause is carried, not replaced
    monkeypatch.setattr(kc_mod.KeychainBackend, "_run_interactive", real)
    with pytest.raises(SecretNotFoundError):
        b.fetch("PARTIAL")


def test_duplicate_probe_failure_is_logged_not_silent(fake_security, monkeypatch, caplog) -> None:
    """C5: failing open is defensible because read-back is the real guarantee —
    but it must never be silent."""
    b = build(self_check="off")
    b.update("DUP", "v")

    # Bind the ORIGINAL before patching: looking it up through the class inside
    # the replacement would find the replacement and recurse.
    real_run = kc_mod.KeychainBackend._run

    def no_dump(self, cmd):  # noqa: ANN001, ANN202
        if cmd and cmd[0] == "dump-keychain":
            raise kc_mod.KeychainError(1, "security: cannot enumerate")
        return real_run(self, cmd)

    monkeypatch.setattr(kc_mod.KeychainBackend, "_run", no_dump)
    try:
        with caplog.at_level("WARNING"):
            b.update("DUP", "v2")
    finally:
        monkeypatch.setattr(kc_mod.KeychainBackend, "_run", real_run)
    assert any("duplicate" in r.getMessage() for r in caplog.records)


def test_dump_parser_unescapes_blob_values() -> None:
    """C4: an escaped quote or backslash in an attribute must be unescaped, or
    the name silently fails to match the name it was written under."""
    dump = (
        'keychain: "/x"\nclass: "genp"\n'
        '    "acct"<blob>="HAS\\"QUOTE"\n    "svce"<blob>="s"\n'
        'keychain: "/x"\nclass: "genp"\n'
        '    "acct"<blob>="HAS\\\\BACKSLASH"\n    "svce"<blob>="s"\n'
    )
    assert _parse_dump(dump, "s") == ['HAS"QUOTE', "HAS\\BACKSLASH"]
