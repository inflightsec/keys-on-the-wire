#!/usr/bin/env bash
# ADR-0054: fast spec gate for commits touching specs/ — parse + typecheck
# only (no JVM, ~2s). The full conformance + invariant battery runs in
# tests/test_spec_conformance.py (pytest, and CI specs.yml with
# KOW_REQUIRE_QUINT=1). Gracefully skips when no quint runner exists,
# matching the other heavy pre-commit tools — CI is the enforcement gate.
set -euo pipefail

# Never run npm lifecycle scripts when npx/bunx fetch the pinned package
# (Oracle C8 — mirrors CI's npm install --ignore-scripts).
export npm_config_ignore_scripts=true

run_quint() {
  if command -v quint >/dev/null 2>&1; then
    quint "$@"
  elif command -v npx >/dev/null 2>&1; then
    npx -y @informalsystems/quint@0.32.0 "$@"
  elif command -v bunx >/dev/null 2>&1; then
    bunx @informalsystems/quint@0.32.0 "$@"
  else
    echo "precommit-quint: no quint/npx/bunx on PATH — skipping (CI enforces)" >&2
    exit 0
  fi
}

for spec in specs/*.qnt; do
  run_quint typecheck "$spec"
done
echo "precommit-quint: typecheck OK"
