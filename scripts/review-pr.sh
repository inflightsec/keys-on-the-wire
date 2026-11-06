#!/usr/bin/env bash
#
# Pre-merge review for a kow branch: an AI pass over the code diff, then
# a human read of the security-sensitive paths only.
#
#   scripts/review-pr.sh              # this branch vs origin/main
#   scripts/review-pr.sh v1.1.1       # backlog: everything since a tag
#
# Step 1 (AI): the Oracle cross-vendor reviewer, with oracle-rubric.md
# from the repo root as its project rubric. Skipped with a notice when
# Oracle is not installed (set ORACLE_REVIEW to its OracleReview.ts).
# Only code is sent (src, CI, scripts, helper, specs, packaging); tests
# and docs are left to CI. Oracle refuses any payload that looks like it
# holds a secret, and a credential proxy is full of fake keys and key
# headers, so each file is gate-checked on its own first: clean files go
# to Oracle in one call, refused files are moved to the human list.
#
# Step 2 (human): src/, every specific path in .github/CODEOWNERS, and
# the files Oracle refused. Shown through difftastic when it is
# installed, plain git diff otherwise.

set -euo pipefail

base="${1:-origin/main}"
cd "$(git rev-parse --show-toplevel)"
git rev-parse --verify --quiet "$base^{commit}" >/dev/null || { echo "unknown base: $base" >&2; exit 2; }
range="$base...HEAD"

echo "== Reviewing $range: $(git rev-list --count "$range") commits"
git diff --stat "$range" | tail -1

mapfile -t sensitive < <(awk '!/^#/ && NF >= 2 && $1 != "*" { sub(/^\//, "", $1); print $1 }' .github/CODEOWNERS)
sensitive=(src/ "${sensitive[@]}")

# --- Step 1: AI review ------------------------------------------------
oracle="${ORACLE_REVIEW:-${PAI_DIR:-$HOME/.claude}/skills/Oracle/Tools/OracleReview.ts}"
if [[ -f "$oracle" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  echo "== Step 1: Oracle review (gate-checking files first)"
  mapfile -t code < <(git diff --name-only --diff-filter=d "$range" -- \
    src .github scripts helper specs Dockerfile pyproject.toml docker-compose.yml)
  for f in "${code[@]}"; do
    git diff "$range" -- "$f" >"$tmp/one"
    if bun "$oracle" --mode code-review --payload-file "$tmp/one" --dry-run >/dev/null 2>&1; then
      cat "$tmp/one" >>"$tmp/payload"
    else
      echo "   refused by the secret gate, read it yourself: $f"
      sensitive+=("$f")
    fi
  done
  if [[ -s "$tmp/payload" ]]; then
    bytes=$(wc -c <"$tmp/payload")
    # ~4 bytes/token; past ~60k tokens the review gets shallow, so say so.
    if (( bytes > 240000 )); then echo "!! payload is ${bytes} bytes: review smaller ranges for depth" >&2; fi
    bun "$oracle" --mode code-review --payload-file "$tmp/payload" \
      --max-input-tokens $(( bytes / 4 + 2000 )) || echo "!! Oracle exited $?: read its message above" >&2
  else
    echo "   no code for Oracle in this range"
  fi
else
  echo "== Step 1: skipped (Oracle not found at $oracle)"
fi

# --- Step 2: human read of the sensitive paths ------------------------
echo "== Step 2: sensitive paths changed (read these yourself)"
git diff --stat "$range" -- "${sensitive[@]}"
[[ -t 0 ]] || exit 0
read -rp "Open the sensitive diff now? [Y/n] " ans
[[ "$ans" =~ ^[Nn] ]] && exit 0
if command -v difft >/dev/null; then
  GIT_EXTERNAL_DIFF=difft git diff --ext-diff "$range" -- "${sensitive[@]}"
else
  git diff "$range" -- "${sensitive[@]}"
fi
