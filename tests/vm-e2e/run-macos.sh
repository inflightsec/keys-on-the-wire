#!/usr/bin/env bash
# VM transport for the macOS legs. This is a MAINTAINER convenience, not the
# documented way to run them.
#
#   Contributors run the legs directly on their own Mac — no VM, no driver:
#       bash tests/vm-e2e/macos-e2e.sh              # unprivileged, no sudo, no residue
#       KOW_E2E_CONSENT=1 bash tests/vm-e2e/macos-e2e.sh --system
#   CI runs the same scripts on GitHub's macOS runners (.github/workflows/macos-e2e.yml).
#
# This driver exists only for maintainers who keep a macOS VM around. Note that
# Apple's licence permits macOS virtualisation on Apple hardware only, so the
# VM path is deliberately NOT documented as the project's macOS story — it is a
# local tool, and the scripts it ships are the same ones anyone can run natively.
#
# Drives the Sequoia VM used by the Laima iOS gate (~/ios-gate-dev, ADR-0036).
# The VM is a SHARED resource: this always reverts to the golden snapshot before
# and after, and never writes a new one.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="${KOW_MACOS_GATE:-$HOME/ios-gate-dev}"
TAP="${KOW_TAP:-$(dirname "$REPO")/homebrew-keys-on-the-wire}"
GUEST_USER="${KOW_MACOS_USER:-claude}"
LEGS="${1:-system}"; [ "$LEGS" = "all" ] && LEGS="user keychain gcp keyd system brew"
DISK="$GATE/macos-sequoia/disk.qcow2"
VMSSH="$GATE/vmssh"

green(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ -x "$VMSSH" ] || { red "no macOS gate at $GATE — run the legs natively instead: bash tests/vm-e2e/macos-e2e.sh"; exit 1; }

revert() { qemu-img snapshot -a golden "$DISK" >/dev/null 2>&1 && \
           cp "$GATE/macos-sequoia/OVMF_VARS.golden.fd" "$GATE/macos-sequoia/OVMF_VARS-1920x1080.fd" 2>/dev/null; }
stop_vm() { local p; p=$(pgrep -f 'name macos-sequoia,process' | head -1); [ -n "$p" ] && kill "$p" 2>/dev/null; sleep 6; }

cleanup() { stop_vm; revert; echo "VM stopped and reverted to golden"; }
trap cleanup EXIT

echo "==> reverting to golden + booting"
stop_vm; revert
( cd "$GATE" && nohup ./run-vm.sh run >/tmp/kow-macos-boot.log 2>&1 & )

echo -n "waiting for ssh"
for _ in $(seq 1 60); do "$VMSSH" true 2>/dev/null && break; printf .; sleep 10; done
echo
"$VMSSH" true 2>/dev/null || { red "VM never became reachable"; exit 1; }
green "VM up ($("$VMSSH" sw_vers -productVersion 2>/dev/null))"

echo "==> prerequisite: python >=3.12 (macOS ships 3.9)"
"$VMSSH" 'command -v python3.13 >/dev/null 2>&1 || test -x "$(brew --prefix 2>/dev/null)/opt/python@3.13/bin/python3.13" \
          || (export HOMEBREW_NO_AUTO_UPDATE=1; brew install python@3.13 >/tmp/brewpy.log 2>&1)'

echo "==> syncing this tree"
SSHOPT="ssh -F /dev/null -i $GATE/vmkey -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
rsync -a -e "$SSHOPT" --exclude .venv --exclude .git --exclude __pycache__ --exclude .mypy_cache \
      --exclude .pytest_cache --exclude .hypothesis --exclude demo --exclude dist "$REPO"/ "$GUEST_USER@127.0.0.1:kow-src/" || exit 1
# The brew leg tests the REAL tap formula, so ship it from the tap checkout.
SCP="scp -F /dev/null -i $GATE/vmkey -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
if [ -f "$TAP/Formula/keys-on-the-wire.rb" ]; then
  $SCP "$TAP/Formula/keys-on-the-wire.rb" "$GUEST_USER@127.0.0.1:kow-formula.rb" || exit 1
else
  echo "note: no tap checkout at $TAP — the brew leg will be skipped"
fi

# Everything below runs the SAME scripts a contributor runs natively; the only
# difference is that they arrive over ssh and the machine is disposable.
GENV="export KOW_SRC=\$HOME/kow-src KOW_FORMULA=\$HOME/kow-formula.rb"

RC=0
for leg in $LEGS; do
  case "$leg" in
    user)   echo; green "### LEG: unprivileged (no sudo, no residue)"
            "$VMSSH" "$GENV; bash \$HOME/kow-src/tests/vm-e2e/macos-e2e.sh" || RC=1 ;;
    keychain) echo; green "### LEG: keychain backend (throwaway keychain, real /usr/bin/security)"
            "$VMSSH" "$GENV; bash \$HOME/kow-src/tests/vm-e2e/macos-e2e.sh --keychain" || RC=1 ;;
    gcp)      echo; green "### LEG: gcp service account (Keychain-held key, verifiable assertion)"
            "$VMSSH" "$GENV; bash \$HOME/kow-src/tests/vm-e2e/macos-e2e.sh --gcp" || RC=1 ;;
    keyd)   echo; green "### LEG: kow-keyd (signed helper scopes the ACL to kow, not to python)"
            "$VMSSH" "$GENV; bash \$HOME/kow-src/tests/vm-e2e/macos-keyd-e2e.sh" || RC=1 ;;
    system) echo; green "### LEG: system install (dscl account, launchd, chflags sappnd)"
            "$VMSSH" "$GENV KOW_E2E_CONSENT=1; bash \$HOME/kow-src/tests/vm-e2e/macos-e2e.sh --system" || RC=1 ;;
    brew)   echo; green "### LEG: brew (real tap formula, built from source — slow)"
            if "$VMSSH" 'test -f ~/kow-formula.rb'; then
              # brew build-from-source outlives a normal ssh window; detach and poll.
              "$VMSSH" "$GENV; nohup bash \$HOME/kow-src/tests/vm-e2e/guest-brew.sh > ~/brew-e2e.log 2>&1 & echo started" >/dev/null
              for _ in $(seq 1 120); do
                "$VMSSH" 'pgrep -f guest-brew >/dev/null' 2>/dev/null || break
                sleep 15
              done
              "$VMSSH" 'cat ~/brew-e2e.log' || RC=1
              "$VMSSH" 'grep -q "0 failed" ~/brew-e2e.log' 2>/dev/null || RC=1
            else
              red "brew leg skipped (no formula staged)"; RC=1
            fi ;;
    *) red "unknown leg: $leg (want: user, keychain, gcp, keyd, system, brew, all)"; RC=1 ;;
  esac
done

[ "$RC" -eq 0 ] && green "macOS VM E2E: ALL LEGS PASS ($LEGS)" || red "macOS VM E2E: FAILURES"
exit "$RC"
