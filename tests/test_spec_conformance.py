"""ADR-0054 — fixtures ↔ Quint model conformance + model invariant gates.

Drift control for specs/*.qnt: every ADR-0013 policy fixture is replayed
against the model's ``decideV``/``executeV`` (a generated Quint test), and
the models' invariants are re-checked. A fixture the model disagrees with
fails this test — the spec cannot silently diverge from the corpus that
also drives the real addon (tests/test_policy_fixtures.py).

Requires the quint CLI (node). Local runs without it SKIP (matching the
graceful-degradation convention of the heavy pre-commit tools); CI sets
KOW_REQUIRE_QUINT=1 so absence there is a hard failure, never a silent
green.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).parent.parent
# Applied to EVERY quint invocation including the --version probe (Oracle r2
# C1): a cold npx/bunx cache downloads the package during the probe, and
# lifecycle scripts must already be disabled there, not only in run_quint.
_NO_SCRIPTS_ENV = {**os.environ, "npm_config_ignore_scripts": "true"}
FIXTURE_DIR = REPO / "tests" / "fixtures" / "policy"
SPECS = REPO / "specs"
GENERATED = SPECS / "generated"

pytestmark = pytest.mark.specs


@cache
def quint_cmd() -> tuple[str, ...] | None:
    """Resolve a working quint invocation, or None if unavailable.

    Order: explicit KOW_QUINT override, a `quint` binary on PATH, then
    npx/bunx with the version pinned to what specs/ were authored against.
    """
    candidates: list[tuple[str, ...]] = []
    if os.environ.get("KOW_QUINT"):
        candidates.append(tuple(os.environ["KOW_QUINT"].split()))
    if shutil.which("quint"):
        candidates.append(("quint",))
    for runner in ("npx", "bunx"):
        if shutil.which(runner):
            candidates.append((runner, "-y", "@informalsystems/quint@0.32.0"))
    for cmd in candidates:
        try:
            probe = subprocess.run(  # noqa: S603 — fixed argv, no shell
                [*cmd, "--version"],
                capture_output=True,
                timeout=120,
                env=_NO_SCRIPTS_ENV,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return cmd
    return None


def require_quint() -> tuple[str, ...]:
    cmd = quint_cmd()
    if cmd is None:
        if os.environ.get("KOW_REQUIRE_QUINT") == "1":
            pytest.fail("KOW_REQUIRE_QUINT=1 but no working quint CLI found")
        pytest.skip("quint CLI not available (set KOW_QUINT or install node)")
    return cmd


def run_quint(*args: str) -> subprocess.CompletedProcess[bytes]:
    # _NO_SCRIPTS_ENV: no package lifecycle code ever executes (Oracle C8).
    return subprocess.run(  # noqa: S603 — fixed argv, no shell
        [*require_quint(), *args],
        capture_output=True,
        timeout=600,
        cwd=REPO,
        env=_NO_SCRIPTS_ENV,
    )


# ── fixture → model translation ────────────────────────────────────────────


def _q(s: str) -> str:
    """A Quint string literal (JSON escaping is a superset of Quint's)."""
    return json.dumps(s)


def _cfg_expr(fix: dict[str, Any]) -> str:
    cfg = yaml.safe_load(fix["config"])
    secrets = []
    for name, spec in cfg.get("secrets", {}).items():
        bindings = []
        for b in spec.get("bindings", []):
            methods = ", ".join(_q(m) for m in b.get("methods", []))
            # Oracle C7: the model's path scope is exact-segment, weaker than
            # production prefix matching. Refuse loudly rather than translate
            # unfaithfully — upgrade decide.qnt when the first such fixture
            # lands.
            if b.get("paths"):
                raise AssertionError(
                    f"fixture binds paths: {b['paths']} — decide.qnt models "
                    "path scopes as exact segments; upgrade the model before "
                    "translating this fixture"
                )
            paths = ""
            bindings.append(
                f"{{ host: {_q(b['host'])}, methods: Set({methods}), pathPrefixes: Set({paths}) }}"
            )
        secrets.append(
            f"{{ name: {_q(name)}, placeholder: {_q(spec['placeholder'])}, "
            f"bindings: [{', '.join(bindings)}] }}"
        )
    deny = "true" if cfg.get("unmatched_destination_policy") == "deny" else "false"
    return f"{{ secrets: [{', '.join(secrets)}], unmatchedDeny: {deny} }}"


def _target_headers(inject: dict[str, Any]) -> list[str]:
    """Every header targeted by an inject tree (handles composite children)."""
    found: list[str] = []
    if "header" in inject:
        found.append(str(inject["header"]))
    for child in inject.get("children", []) or []:
        found.extend(_target_headers(child))
    return found


def _req_expr(fix: dict[str, Any]) -> str:
    cfg = yaml.safe_load(fix["config"])
    req = fix["request"]
    headers = {k.lower(): v for k, v in (req.get("headers", {}) or {}).items()}
    # Oracle C6: production matches a placeholder only inside its CONFIGURED
    # target header (policy.build_header_index) — a placeholder loitering in
    # an unrelated header must NOT count as present.
    present = []
    for spec in cfg.get("secrets", {}).values():
        targets = [h.lower() for h in _target_headers(spec.get("inject", {}))]
        if not targets:
            raise AssertionError(
                "fixture secret has no header-targeting inject — extend "
                "_target_headers before adding this fixture to the corpus"
            )
        if any(spec["placeholder"] in headers.get(h, "") for h in targets):
            present.append(spec["placeholder"])
    phs = ", ".join(_q(p) for p in present)
    return (
        f"{{ host: {_q(req['host'])}, connectHost: {_q(req.get('connect', ''))}, "
        f"method: {_q(req.get('method', 'GET').upper())}, "
        f"path: {_q(req.get('path', '/'))}, placeholders: Set({phs}) }}"
    )


def _expected_expr(fix: dict[str, Any]) -> str:
    exp = fix["expect"]
    # Execution-layer reasons carry an exception suffix the model abstracts
    # away ("secret_unavailable:BackendUnavailableError" → "secret_unavailable").
    reason = (exp.get("reason") or "").split(":")[0]
    return (
        f"{{ decision: {_q(exp['decision'])}, reason: {_q(reason)}, "
        f"secretName: {_q(exp.get('secret_name', ''))}, "
        f"status: {exp.get('status') or 0}, "
        f"injected: {'true' if exp.get('injected', False) else 'false'} }}"
    )


def generate_conformance_module() -> Path:
    """Emit one Quint val per fixture + an invariant conjoining them all."""
    checks: list[str] = []
    names: list[str] = []
    for path in sorted(FIXTURE_DIR.glob("*.yaml")):
        fix = yaml.safe_load(path.read_text())
        up = "false" if fix.get("backend", {}).get("fail", False) else "true"
        name = "fx_" + path.stem.replace("-", "_")
        names.append(name)
        checks.append(
            f"  // {path.name} (pins: {fix.get('pins', [])})\n"
            f"  val {name} = executeV({_cfg_expr(fix)}, {_req_expr(fix)}, {up})\n"
            f"    == {_expected_expr(fix)}"
        )
    body = "\n".join(checks)
    conj = " and ".join(names)
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / "conformance.qnt"
    out.write_text(
        "// GENERATED by tests/test_spec_conformance.py — do not edit, do not commit.\n"
        "// One check per tests/fixtures/policy/*.yaml against the ADR-0054 model.\n"
        "module conformance {\n"
        '  import decide_model.* from "../decide"\n\n'
        f"{body}\n\n"
        f"  val allFixtures = {conj}\n\n"
        "  var probed: bool\n"
        "  action init = probed' = allFixtures\n"
        "  action step = probed' = probed\n"
        "  val fixturesHold = probed\n"
        "}\n"
    )
    return out


# ── tests ───────────────────────────────────────────────────────────────────


def test_fixture_conformance() -> None:
    """Every policy fixture's expected outcome matches the model's."""
    module = generate_conformance_module()
    proc = run_quint(
        "run",
        "--invariant=fixturesHold",
        "--max-samples=1",
        "--max-steps=1",
        str(module.relative_to(REPO)),
    )
    assert proc.returncode == 0, (
        "fixture/model drift — a policy fixture disagrees with specs/decide.qnt:\n"
        + proc.stdout.decode()
        + proc.stderr.decode()
    )


def test_decide_gate_invariants() -> None:
    """G3/G4/G5 gates + ADR-0055 note locality over random request space.

    A violation here is a genuine counterexample, never a flake: quint
    prints the trace — file it before touching the invariant.
    """
    proc = run_quint(
        "run",
        "--main=decideSpec",
        "--invariant=allGates",
        "--max-samples=500",
        "--max-steps=25",
        "specs/decide.qnt",
    )
    assert proc.returncode == 0, proc.stdout.decode() + proc.stderr.decode()


def test_snapshot_race_witness_still_reproduces() -> None:
    """The addon.py two-write publish race stays pinned until fixed.

    When the addon moves to a single atomic snapshot swap, this witness
    starts failing BY DESIGN — delete snapshotCurrent + the witness and
    keep snapshotFixed as the checked contract.
    """
    proc = run_quint("test", "--main=snapshotCurrent", "specs/decide.qnt")
    assert proc.returncode == 0, proc.stdout.decode() + proc.stderr.decode()


def test_snapshot_fixed_design_is_coherent() -> None:
    proc = run_quint(
        "run",
        "--main=snapshotFixed",
        "--invariant=servedCoherent",
        "--max-samples=300",
        "--max-steps=15",
        "specs/decide.qnt",
    )
    assert proc.returncode == 0, proc.stdout.decode() + proc.stderr.decode()


def test_rotation_protocol_safety() -> None:
    """ADR-0022 lease+CAS under randomized bounded exploration (not proof).

    quiescent consistency, §4 discard, version bound — including the
    per-request provider class where CAS write-backs actually collide.
    """
    proc = run_quint(
        "run",
        "--main=rotationStrict",
        "--invariant=allSafe",
        "--max-samples=800",
        "--max-steps=40",
        "specs/rotation.qnt",
    )
    assert proc.returncode == 0, proc.stdout.decode() + proc.stderr.decode()


def test_rotation_invariant_is_falsifiable() -> None:
    """noStaleServe is not vacuous: the buggy variant that serves on a CAS
    conflict MUST violate it (Oracle C4 — a safety net you cannot trip
    protects nothing)."""
    proc = run_quint(
        "run",
        "--main=rotationBuggy",
        "--invariant=noStaleServe",
        "--max-samples=800",
        "--max-steps=40",
        "specs/rotation.qnt",
    )
    out = proc.stdout.decode() + proc.stderr.decode()
    assert proc.returncode != 0, (
        "rotationBuggy failed to violate noStaleServe — the invariant has "
        "gone vacuous; check buggyServeOnConflict reachability"
    )
    # Oracle r2 C2: any tool crash also exits nonzero — demand the actual
    # violation verdict, not merely failure.
    assert "[violation]" in out or "Invariant violated" in out, (
        "quint failed for a reason other than an invariant violation:\n" + out
    )


def test_rotation_witnesses() -> None:
    """All three instances: follower rejoin + double-leader (shared), CAS
    conflict (per-request strict), crash-brick terminal (revoking strict),
    forbidden serve (buggy)."""
    for main in ("rotationStrict", "rotationStrictRevoking", "rotationBuggy"):
        proc = run_quint("test", f"--main={main}", "specs/rotation.qnt")
        assert proc.returncode == 0, main + ":\n" + proc.stdout.decode() + proc.stderr.decode()


def test_addon_publish_pattern_tripwire() -> None:
    """Code↔model tether for the snapshot race (Oracle C5).

    The Quint witness pins the RACE DESIGN and cannot observe addon.py.
    This tripwire watches the two-write publish shape in the code: exactly
    two plain assignments to each of _header_index / _header_index_config
    (publish + _index_for rebuild). When this fails, the publish changed —
    re-derive specs/decide.qnt's snapshotRace (flip to snapshotFixed if the
    swap became atomic) and update this count. Green witness + changed code
    without this tripwire would be silent false assurance.
    """
    src = (REPO / "src" / "kow" / "addon.py").read_text()
    # The exact two-line publish sequences the model's publishWrite1/2 mirror
    # (index written FIRST, config second — the write order IS the race).
    publish_pair = "self._header_index = snap.header_index\n"
    publish_pair += "        self._header_index_config = snap.config"
    rebuild_pair = "self._header_index = build_header_index(config)\n"
    rebuild_pair += "            self._header_index_config = config"
    total_writes = src.count("self._header_index = ") + src.count("self._header_index_config = ")
    assert publish_pair in src and rebuild_pair in src and total_writes == 4, (
        "addon.py snapshot-publish shape changed (ordered pairs "
        f"{publish_pair in src}/{rebuild_pair in src}, writes={total_writes}, "
        "expected True/True/4) — re-derive specs/decide.qnt snapshotRace "
        "(reordered or synchronised writes change the race), then update "
        "this tripwire. A heuristic tether, not a semantic proof."
    )
