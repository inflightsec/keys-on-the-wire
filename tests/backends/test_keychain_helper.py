"""Keychain helper transmit path (ADR-0051).

The point of this path is one capability the ``security(1)`` path cannot have:
storing a value the interactive line protocol would truncate, i.e. a PEM. These
tests run against ``_fake_keyd.py``, a real executable implementing the helper's
exit-code contract, so argv, stdin bytes and exit codes are genuinely crossed on
Linux. The real helper against a real keychain is covered by
``tests/vm-e2e/macos-keyd-e2e.sh``.

Read ADR-0051's "What the helper is not" before adding a test that asserts an
access-control property here. The helper is a transport. It is not a boundary
against a same-UID attacker, and a test implying otherwise would be pinning a
false claim.
"""

from __future__ import annotations

import json
import shutil
import stat
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from kow.backends import (
    BackendUnavailableError,
    BackendWriteConflictError,
    SecretNotFoundError,
)
from kow.backends import keychain as kc_mod
from kow.backends.keychain import KeychainBackend, KeychainConfig
from kow.secret import Secret

_FAKE = Path(__file__).parent / "_fake_keyd.py"
SERVICE = "kow-test"

PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
    "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n"
    "-----END PRIVATE KEY-----\n"
)


# --------------------------------------------------------------------- setup


@pytest.fixture
def fake_keyd(tmp_path, monkeypatch):
    """Install the fake helper as the only discovery candidate.

    ``_keyd_trust_error`` is neutered here because the real check demands a
    root-owned path and the suite does not run as root. The check itself is
    tested directly further down, against crafted files.
    """
    binpath = tmp_path / "kow-keyd.py"
    shutil.copy(_FAKE, binpath)
    binpath.chmod(binpath.stat().st_mode | stat.S_IXUSR)
    wrapper = tmp_path / "kow-keyd"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{binpath}" "$@"\n')
    wrapper.chmod(0o755)

    store = tmp_path / "keyd-store.json"
    argv_log = tmp_path / "keyd-argv.log"
    stdin_log = tmp_path / "keyd-stdin.bin"

    monkeypatch.setattr(kc_mod, "KEYD_CANDIDATES", (str(wrapper),))
    monkeypatch.setattr(kc_mod, "_keyd_trust_error", lambda _p: None)
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)
    monkeypatch.setenv("FAKE_KEYD_STORE", str(store))
    monkeypatch.setenv("FAKE_KEYD_ARGV_LOG", str(argv_log))
    monkeypatch.setenv("FAKE_KEYD_STDIN_LOG", str(stdin_log))
    return {"store": store, "argv_log": argv_log, "stdin_log": stdin_log, "bin": wrapper}


def build(**kw) -> KeychainBackend:
    kw.setdefault("service", SERVICE)
    kw.setdefault("use_helper", "require")
    return KeychainBackend(config=KeychainConfig(**kw))


def logged_argv(fake) -> list[list[str]]:
    if not fake["argv_log"].exists():
        return []
    return [json.loads(line) for line in fake["argv_log"].read_text().splitlines()]


def verbs(fake) -> list[str]:
    return [a[0] for a in logged_argv(fake) if a]


def seed(fake, name: str, value: str, *, service: str = SERVICE, times: int = 1) -> None:
    """Put items straight into the fake store, bypassing the backend."""
    items = json.loads(fake["store"].read_text()) if fake["store"].exists() else []
    for _ in range(times):
        items.append({"svce": service, "acct": name, "value": value})
    fake["store"].write_text(json.dumps(items))


# -------------------------------------------------------------------- config


def test_use_helper_defaults_to_off() -> None:
    """ADR-0051 §1: the default must not change the meaning of an existing
    keychain. Anything other than 'off' here is an upgrade that strands items."""
    assert KeychainConfig(service="kow").use_helper == "off"


@pytest.mark.parametrize("bad", ["auto", "on", "yes", "", "REQUIRE"])
def test_config_rejects_unknown_use_helper_mode(bad: str) -> None:
    """'auto' especially: ADR-0051 rejected it by name, so it must not quietly
    become valid again."""
    with pytest.raises(ValidationError):
        KeychainConfig(service="kow", use_helper=bad)  # type: ignore[arg-type]


def test_candidate_list_excludes_user_writable_prefixes() -> None:
    """Homebrew's prefix is owned by the installing user on Apple Silicon, so a
    candidate there is writable by exactly the attacker the check excludes."""
    assert all(
        c.startswith(("/usr/local/libexec/", "/usr/libexec/")) for c in kc_mod.KEYD_CANDIDATES
    )
    assert not any("homebrew" in c or c.startswith("~") for c in kc_mod.KEYD_CANDIDATES)


# ----------------------------------------------------------- the trust check


def test_trust_check_rejects_missing_file(tmp_path) -> None:
    assert kc_mod._keyd_trust_error(tmp_path / "absent") is not None


def test_trust_check_rejects_symlink(tmp_path) -> None:
    real = tmp_path / "real"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    link = tmp_path / "link"
    link.symlink_to(real)
    err = kc_mod._keyd_trust_error(link)
    assert err is not None
    assert "symlink" in err


def test_trust_check_rejects_non_executable(tmp_path) -> None:
    p = tmp_path / "kow-keyd"
    p.write_text("x")
    p.chmod(0o644)
    err = kc_mod._keyd_trust_error(p)
    assert err is not None
    assert "executable" in err


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777])
def test_trust_check_rejects_group_or_other_writable(tmp_path, mode: int) -> None:
    p = tmp_path / "kow-keyd"
    p.write_text("#!/bin/sh\n")
    p.chmod(mode)
    err = kc_mod._keyd_trust_error(p)
    assert err is not None
    assert "writable" in err


def test_trust_check_rejects_non_root_owner(tmp_path) -> None:
    """The suite does not run as root, so a file it creates is owned by the
    wrong uid — which is precisely the condition being pinned."""
    p = tmp_path / "kow-keyd"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    err = kc_mod._keyd_trust_error(p)
    assert err is not None
    # Must object to the FILE. Without this the parent-directory check answers
    # first and the test passes with the ownership check deleted entirely.
    assert err == f"{p} is not owned by root"


def test_trust_check_examines_parent_directories(tmp_path, monkeypatch) -> None:
    """A root-owned binary inside a user-writable directory is replaceable, so
    the chain has to be checked, not just the leaf."""
    p = tmp_path / "kow-keyd"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    # Pretend every *file* check passes; the parent walk must still object.
    monkeypatch.setattr(kc_mod, "_stat_is_root_locked", lambda st: st.st_mode & stat.S_IFDIR == 0)
    err = kc_mod._keyd_trust_error(p)
    assert err is not None
    assert "director" in err


# ----------------------------------------------------------------- the modes


def test_off_mode_never_executes_the_helper(fake_keyd, tmp_path, monkeypatch) -> None:
    """The default path must be byte-for-byte today's behaviour."""
    from tests.backends.test_keychain_backend import _install_fake_security

    _install_fake_security(tmp_path, monkeypatch)
    be = build(use_helper="off")
    be.update("TOKEN", "sk-single-line")
    assert be.fetch("TOKEN") == Secret("sk-single-line")
    assert logged_argv(fake_keyd) == []


def test_require_without_a_helper_refuses_and_names_the_path(monkeypatch) -> None:
    monkeypatch.setattr(kc_mod, "KEYD_CANDIDATES", ("/nonexistent/kow-keyd",))
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)
    be = build(use_helper="require")
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("TOKEN")
    assert "/nonexistent/kow-keyd" in str(e.value)


def test_require_probes_the_helper_at_startup(fake_keyd) -> None:
    """ADR-0051 §12: a broken helper surfaces at configuration time, not at the
    first credential fetch."""
    be = build()
    be._ensure_ready()
    assert verbs(fake_keyd) == ["list"]


def test_startup_probe_failure_is_reported(fake_keyd, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_KEYD_FAIL", "boom")
    be = build()
    with pytest.raises(BackendUnavailableError):
        be.fetch("TOKEN")


def test_no_subprocess_at_construction(fake_keyd) -> None:
    KeychainBackend(config=KeychainConfig(service=SERVICE, use_helper="require"))
    assert logged_argv(fake_keyd) == []


# ------------------------------------------------------------- the round trip


def test_multiline_pem_round_trips(fake_keyd) -> None:
    """The entire reason this path exists."""
    be = build()
    be.update("GCP_SEAT_KEY", PEM)
    assert be.fetch("GCP_SEAT_KEY") == Secret(PEM)


def test_pem_is_stored_whole_not_truncated_at_the_first_newline(fake_keyd) -> None:
    """The specific corruption the security(1) path would produce."""
    be = build()
    be.update("GCP_SEAT_KEY", PEM)
    stored = be.fetch("GCP_SEAT_KEY").reveal()
    assert stored.count("\n") == PEM.count("\n")
    assert stored.endswith("-----END PRIVATE KEY-----\n")


@pytest.mark.parametrize(
    "value",
    [
        "single-line",
        "trailing-space   ",
        "trailing-newline\n",
        "two\nlines",
        "crlf\r\nvalue",
        "embedded\0nul",
        "unicode: ✓ ключ",
        " ",
    ],
    ids=["plain", "trailing-space", "trailing-nl", "multiline", "crlf", "nul", "unicode", "space"],
)
def test_values_round_trip_byte_exact(fake_keyd, value: str) -> None:
    be = build()
    be.update("SECRET", value)
    assert be.fetch("SECRET").reveal() == value


def test_value_never_appears_on_argv(fake_keyd) -> None:
    """The process table is world-readable on macOS. This is the invariant the
    whole helper exists to keep."""
    be = build()
    be.update("GCP_SEAT_KEY", PEM)
    for argv in logged_argv(fake_keyd):
        for token in argv:
            assert PEM not in token
            assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEA" not in token


def test_value_arrives_on_stdin(fake_keyd) -> None:
    be = build()
    be.update("GCP_SEAT_KEY", PEM)
    assert fake_keyd["stdin_log"].read_bytes() == PEM.encode()


def test_fetch_missing_raises_not_found(fake_keyd) -> None:
    be = build()
    with pytest.raises(SecretNotFoundError):
        be.fetch("ABSENT")


def test_delete_is_idempotent(fake_keyd) -> None:
    be = build()
    be.update("SECRET", "v1")
    be.delete("SECRET")
    be.delete("SECRET")
    with pytest.raises(SecretNotFoundError):
        be.fetch("SECRET")


def test_list_returns_only_this_service(fake_keyd) -> None:
    be = build()
    be.update("ALPHA", "a")
    seed(fake_keyd, "FOREIGN", "x", service="somebody-else")
    assert be.list_secret_names() == ["ALPHA"]


def test_list_dedupes_and_sorts(fake_keyd) -> None:
    seed(fake_keyd, "BETA", "b")
    seed(fake_keyd, "ALPHA", "a", times=2)
    assert build().list_secret_names() == ["ALPHA", "BETA"]


def test_list_honours_secret_prefix(fake_keyd) -> None:
    seed(fake_keyd, "KOW_ONE", "1")
    seed(fake_keyd, "OTHER", "2")
    assert build(secret_prefix="KOW_").list_secret_names() == ["KOW_ONE"]


# ----------------------------------------------------------------- the names


@pytest.mark.parametrize(
    ("bad", "label"),
    [("A\nB", "newline"), ("A\rB", "carriage return"), ("A\0B", "NUL byte")],
    ids=["newline", "carriage-return", "nul"],
)
def test_name_still_refuses_untransmittable_bytes(fake_keyd, bad: str, label: str) -> None:
    """ADR-0051 §9: the value is relaxed, the NAME is not. A newline in a name
    would come back from `list` as two accounts and corrupt the duplicate count.
    """
    be = build(secret_prefix=None)
    with pytest.raises(BackendUnavailableError) as e:
        be.update(bad, "value")
    assert label in str(e.value)


def test_helper_path_accepts_a_value_the_other_path_refuses(
    fake_keyd, tmp_path, monkeypatch
) -> None:
    """The two paths differ in exactly one way, and this pins it."""
    from tests.backends.test_keychain_backend import _install_fake_security

    _install_fake_security(tmp_path, monkeypatch)
    with pytest.raises(BackendUnavailableError):
        build(use_helper="off").update("K", PEM)
    build(use_helper="require").update("K", PEM)


def test_multiline_refusal_names_the_helper_as_the_fix(tmp_path, monkeypatch) -> None:
    from tests.backends.test_keychain_backend import _install_fake_security

    _install_fake_security(tmp_path, monkeypatch)
    with pytest.raises(BackendUnavailableError) as e:
        build(use_helper="off").update("K", PEM)
    assert "use_helper" in str(e.value)


# ------------------------------------------------------------- write safety


def test_update_does_not_delete_before_writing(fake_keyd) -> None:
    """ADR-0051 §6. A delete-then-add update has a window where the credential
    does not exist, and a crash inside it destroys the old value for good."""
    be = build()
    be.update("SECRET", "v1")
    fake_keyd["argv_log"].unlink()
    be.update("SECRET", "v2")
    assert "delete" not in verbs(fake_keyd)
    assert "replace" not in verbs(fake_keyd)
    assert be.fetch("SECRET") == Secret("v2")


def test_duplicates_refuse_the_write_before_it_happens(fake_keyd) -> None:
    """ADR-0051 §7. The old post-write count could never fire on this path: the
    write collapses the duplicates, so counting afterwards always says one."""
    seed(fake_keyd, "SECRET", "v1", times=2)
    be = build()
    with pytest.raises(BackendUnavailableError) as e:
        be.update("SECRET", "v2")
    assert "2 items" in str(e.value)
    stored = json.loads(fake_keyd["store"].read_text())
    assert [i["value"] for i in stored] == ["v1", "v1"], "the write must not have happened"


def test_duplicate_check_fails_closed(fake_keyd, monkeypatch) -> None:
    """Unlike the security(1) path, which fails open because its read-back is a
    real backstop. Here it is not, so enumeration failure refuses the write.

    Only `list` is broken, deliberately: a blanket failure would also break the
    read-back and the write would be refused either way, which is the assertion
    passing for the wrong reason.
    """
    be = build()
    be._ensure_ready()
    monkeypatch.setenv("FAKE_KEYD_FAIL", "list:boom")
    with pytest.raises(BackendUnavailableError) as e:
        be.update("SECRET", "v2")
    assert "duplicate" in str(e.value)
    assert not fake_keyd["store"].exists(), "nothing may have been written"


def test_read_back_mismatch_still_raises(fake_keyd, monkeypatch) -> None:
    be = build()
    real_fetch = KeychainBackend.fetch

    def lying_fetch(self, name, ctx=None):  # noqa: ANN001, ANN202
        if getattr(self, "_lied", False):
            return Secret("not-what-was-written")
        return real_fetch(self, name, ctx)

    be.update("SECRET", "v1")
    monkeypatch.setattr(KeychainBackend, "fetch", lying_fetch)
    be._lied = True
    with pytest.raises(BackendUnavailableError):
        be.update("SECRET", "v2")


def test_write_conflict_is_detected(fake_keyd) -> None:
    be = build()
    be.update("SECRET", "v1")
    with pytest.raises(BackendWriteConflictError):
        be.update("SECRET", "v2", expected_current_value="stale")


# ------------------------------------------------------------- exit codes


def test_interaction_exit_names_the_legacy_acl_and_the_remedy(fake_keyd, monkeypatch) -> None:
    """Exit 51 is what an operator hits the moment they flip use_helper on with
    a keychain full of security(1)-written items. It has to explain itself."""
    be = build()
    be._ensure_ready()
    monkeypatch.setenv("FAKE_KEYD_FAIL", "interaction")
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("SECRET")
    msg = str(e.value)
    assert "locked" in msg, "the other thing exit 51 can mean"
    assert "ACL" in msg
    # The remedy has to be the sequence that works. "re-add it" alone does not:
    # update() pre-reads, the pre-read hits the same ACL, and the operator loops.
    # Confirmed on a real Mac — the helper cannot delete a legacy item either
    # (macos-keyd-e2e.sh step 12d), so the OLD transport has to do the deleting.
    assert "secret remove" in msg
    assert "--stdin-raw" in msg


def test_entitlement_exit_is_described_precisely(fake_keyd, monkeypatch) -> None:
    be = build()
    be._ensure_ready()
    monkeypatch.setenv("FAKE_KEYD_FAIL", "entitlement")
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("SECRET")
    assert "errSecMissingEntitlement" in str(e.value)
    # ADR-0051 §11: named as the status it is, NOT as a general "unsigned binary"
    # test, which exit 34 is not.
    assert "unsigned" not in str(e.value)


def test_usage_exit_is_reported_as_a_kow_bug(fake_keyd, monkeypatch) -> None:
    be = build()
    be._ensure_ready()
    monkeypatch.setenv("FAKE_KEYD_FAIL", "usage")
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("SECRET")
    assert "bug" in str(e.value)


def test_stderr_is_bounded_and_single_line(fake_keyd, monkeypatch) -> None:
    be = build()
    be._ensure_ready()
    monkeypatch.setenv("FAKE_KEYD_FAIL", "boom")
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("SECRET")
    assert "\n" not in str(e.value)


# ------------------------------------------------------------------- UTF-8


def test_invalid_utf8_is_an_error_not_a_mangled_secret(fake_keyd) -> None:
    """Reachable in practice: the helper is a public CLI and can store any
    bytes. Silently substituting U+FFFD would hand out a broken credential."""
    items = [{"svce": SERVICE, "acct": "BINARY", "value": "\udcff\udcfe"}]
    fake_keyd["store"].write_text(json.dumps(items))
    be = build()
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("BINARY")
    assert "UTF-8" in str(e.value)


def test_invalid_utf8_error_does_not_leak_the_bytes(fake_keyd) -> None:
    items = [{"svce": SERVICE, "acct": "BINARY", "value": "\udcff\udcfe"}]
    fake_keyd["store"].write_text(json.dumps(items))
    with pytest.raises(BackendUnavailableError) as e:
        build().fetch("BINARY")
    assert "\\udcff" not in str(e.value) and "�" not in str(e.value)


@pytest.mark.parametrize("mode", ["off", "warn"])
def test_probe_failure_refuses_regardless_of_self_check(fake_keyd, monkeypatch, mode) -> None:
    """`require` is not a preference about how loudly to complain. A helper that
    does not answer must not silently hand the work to security(1)."""
    monkeypatch.setenv("FAKE_KEYD_FAIL", "boom")
    be = build(self_check=mode)
    with pytest.raises(BackendUnavailableError) as e:
        be.fetch("TOKEN")
    assert "probe" in str(e.value)


def test_probe_failure_is_cached_and_re_raised(fake_keyd, monkeypatch) -> None:
    """A caller that swallows the first error must not get the security(1) path
    on the second call."""
    monkeypatch.setenv("FAKE_KEYD_FAIL", "boom")
    be = build()
    for _ in range(3):
        with pytest.raises(BackendUnavailableError):
            be.fetch("TOKEN")
    assert be._keyd is None


@pytest.mark.parametrize("op", ["fetch", "delete"])
def test_read_paths_also_reject_a_nul_in_the_name(fake_keyd, op: str) -> None:
    """argv cannot carry a NUL, and subprocess raises ValueError rather than a
    backend error — outside the taxonomy, so it reaches the caller as a crash."""
    be = build()
    with pytest.raises(BackendUnavailableError) as e:
        getattr(be, op)("A\0B")
    assert "NUL byte" in str(e.value)


def test_unencodable_value_is_a_backend_error(fake_keyd) -> None:
    be = build()
    with pytest.raises(BackendUnavailableError) as e:
        be.update("SECRET", "lone surrogate: \udcff")
    assert "UTF-8" in str(e.value)
    assert "\\udcff" not in str(e.value)


def test_trust_gate_consults_the_acl_check(tmp_path, monkeypatch) -> None:
    """Testing _acl_error on its own proves nothing about whether anything calls
    it. Mutation testing found exactly that hole."""
    p = tmp_path / "kow-keyd"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    monkeypatch.setattr(kc_mod, "_stat_is_root_locked", lambda _st: True)
    monkeypatch.setattr(kc_mod, "_acl_error", lambda _paths: "ACL SENTINEL")
    assert kc_mod._keyd_trust_error(p) == "ACL SENTINEL"


def test_trust_gate_accepts_when_the_acl_check_is_happy(tmp_path, monkeypatch) -> None:
    p = tmp_path / "kow-keyd"
    p.write_text("#!/bin/sh\n")
    p.chmod(0o755)
    monkeypatch.setattr(kc_mod, "_stat_is_root_locked", lambda _st: True)
    monkeypatch.setattr(kc_mod, "_acl_error", lambda _paths: None)
    assert kc_mod._keyd_trust_error(p) is None


def test_acl_check_is_skipped_off_macos(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: False)
    assert kc_mod._acl_error([tmp_path]) is None


def test_acl_check_rejects_an_allow_entry(tmp_path, monkeypatch) -> None:
    """A root-owned 0755 binary can still carry an ACE granting the operator
    write. mode bits alone call that safe."""
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)

    class _Proc:
        returncode = 0
        stdout = (
            "-rwxr-xr-x  1 root  wheel  12345 Sep 12 10:00 /usr/local/libexec/kow-keyd\n"
            " 0: user:radek allow write,delete\n"
        )

    monkeypatch.setattr(kc_mod.subprocess, "run", lambda *a, **k: _Proc())
    err = kc_mod._acl_error([Path("/usr/local/libexec/kow-keyd")])
    assert err is not None
    assert "extended ACL" in err


def test_acl_check_allows_deny_only_entries(tmp_path, monkeypatch) -> None:
    """Deny entries only ever subtract access, so they are not a reason to
    refuse a candidate."""
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)

    class _Proc:
        returncode = 0
        stdout = (
            "-rwxr-xr-x  1 root  wheel  12345 Sep 12 10:00 /usr/local/libexec/kow-keyd\n"
            " 0: group:everyone deny delete\n"
        )

    monkeypatch.setattr(kc_mod.subprocess, "run", lambda *a, **k: _Proc())
    assert kc_mod._acl_error([Path("/usr/local/libexec/kow-keyd")]) is None


def test_acl_check_fails_closed_when_unreadable(monkeypatch) -> None:
    monkeypatch.setattr(kc_mod, "_is_macos", lambda: True)

    def boom(*a, **k):
        raise OSError("no ls")

    monkeypatch.setattr(kc_mod.subprocess, "run", boom)
    assert kc_mod._acl_error([Path("/usr/local/libexec/kow-keyd")]) is not None


# ------------------------------------------------------- the helper source


def test_both_denial_statuses_map_to_the_interaction_exit() -> None:
    """A source-level pin, because this cannot be unit-tested off macOS.

    macOS reports an unauthorised keychain read as errSecInteractionNotAllowed
    when the process has no session and as errSecAuthFailed when interaction was
    disabled explicitly — which is what the helper does. Mapping only the first
    made an ACL denial arrive as a generic exit 1, so the operator was told
    "kow-keyd failed" instead of "this item predates the helper, re-add it".
    Caught on a real Mac by macos-keyd-e2e.sh step 12c.
    """
    source = (Path(__file__).parents[2] / "helper" / "kow-keyd.c").read_text()
    mapping = source.split("static int status_to_exit")[1].split("}")[0]
    for status in ("errSecInteractionNotAllowed", "errSecAuthFailed"):
        assert f"case {status}:" in mapping, f"{status} must map to an exit code"
        line = next(ln for ln in mapping.splitlines() if f"case {status}:" in ln)
        assert "EXIT_INTERACTION" in line, f"{status} must map to EXIT_INTERACTION"


def test_set_does_not_probe_existence_before_updating() -> None:
    """A boolean existence probe folds authentication, interaction, parameter
    and database errors into 'absent' and then CREATES the item — turning a
    reportable failure into a spurious add, and a duplicate. The keychain
    answers the question instead: only errSecItemNotFound means create."""
    source = (Path(__file__).parents[2] / "helper" / "kow-keyd.c").read_text()
    assert "static int item_exists" not in source
    body = source.split("static int do_write")[1].split("\nstatic ")[0]
    assert "update_in_place" in body
    assert "errSecItemNotFound" in body


def test_enumeration_never_silently_drops_a_name() -> None:
    """A fixed 512-byte buffer skipped over-long names, which made the
    pre-write duplicate count read zero for the very item being checked."""
    source = (Path(__file__).parents[2] / "helper" / "kow-keyd.c").read_text()
    body = source.split("static int do_list")[1].split("\nstatic ")[0]
    assert "CFStringGetMaximumSizeForEncoding" in body
    assert "char buf[512]" not in body


# --------------------------------------------------------------- the scope


def test_secret_prefix_is_enforced_on_the_helper_path(fake_keyd) -> None:
    be = build(secret_prefix="KOW_")
    with pytest.raises(Exception, match="scope|prefix"):
        be.fetch("OUTSIDE")


def test_keychain_path_is_passed_through(fake_keyd, tmp_path) -> None:
    kc = tmp_path / "custom.keychain-db"
    be = build(keychain=str(kc))
    be.update("SECRET", "v1")
    assert any("--keychain" in argv for argv in logged_argv(fake_keyd))
