#!/usr/bin/env bash
# kow macOS end-to-end. Runs on ANY Mac — Intel or Apple Silicon, a
# contributor's laptop, a GitHub runner, or a VM — and cleans up after itself.
#
#   bash tests/vm-e2e/macos-e2e.sh              # unprivileged: no sudo, $HOME only, no residue
#   bash tests/vm-e2e/macos-e2e.sh --keychain   # the keychain backend, in a throwaway keychain
#   bash tests/vm-e2e/macos-e2e.sh --system     # the documented system install (see consent below)
#   bash tests/vm-e2e/macos-e2e.sh --system --keep   # leave it installed for inspection
#
# --system performs the REAL documented install: a _kow service account, a
# LaunchDaemon, directories under the Homebrew prefix, and an append-only audit
# log. It reverses every one of those on exit. Because it mutates the machine it
# is gated on KOW_E2E_CONSENT=1, and refuses outright when a kow install already
# exists, so it can never eat a real deployment.
#
# Both modes end with the same four wire assertions the Linux legs make: healthz
# 200, a placeholder swapped for the real secret upstream, an unbound
# destination refused 403, and no secret bytes in any log.
set -uo pipefail

MODE=user
KEEP=0
for a in "$@"; do
  case "$a" in
    --system)   MODE=system ;;
    --keychain) MODE=keychain ;;
    --gcp)      MODE=gcp ;;
    --keep)   KEEP=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n== %s\n' "$*"; }
red()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "this leg is macOS-only (got $(uname -s))"; exit 2; }

# ---------------------------------------------------------------- environment

# Homebrew moved to /opt/homebrew on Apple Silicon; /usr/local is Intel-only.
# Hardcoding either one breaks the install on half the Macs in existence.
if [ -n "${KOW_PREFIX:-}" ]; then
  case "$KOW_PREFIX" in /*) ;; *) red "KOW_PREFIX must be an absolute path (got '$KOW_PREFIX')"; exit 2 ;; esac
  [ -d "$KOW_PREFIX" ] || { red "KOW_PREFIX does not exist: $KOW_PREFIX"; exit 2; }
  PREFIX="$KOW_PREFIX"
elif command -v brew >/dev/null 2>&1; then PREFIX="$(brew --prefix)"
elif [ -d /opt/homebrew ]; then PREFIX=/opt/homebrew
else PREFIX=/usr/local; fi

# macOS ships Python 3.9; kow needs >=3.12.
#
# ORDER MATTERS — do not re-sort this newest-first. `python3` comes first so we
# honour the interpreter the environment deliberately provisioned (CI's
# setup-python, or a contributor's venv). Then the versions this project
# actually ships wheels for. A newer interpreter than we support is LAST resort:
# picking Homebrew's python@3.14 ahead of CI's 3.13 is what broke the first run
# — pydantic-core has no arm64 wheel for it, so pip fell back to a source build
# and failed. Newest is not safest.
SUPPORTED_PY="3.12 3.13"
_py_mm() { "$1" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null; }
_py_ok() { "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; }

# TWO passes, deliberately. Reordering alone is not enough: on a Mac where
# Homebrew links python3 to 3.14, a single ordered scan that accepts anything
# >=3.12 still picks 3.14 and only warns afterwards — which is the exact failure
# this is meant to prevent. Pass 1 therefore takes only an interpreter whose
# minor version this project ships wheels for; pass 2 is the reluctant fallback.
find_python() {
  local c mm
  # An explicit KOW_PY wins outright — even an unsupported version, because
  # reproducing a version-specific failure is exactly why someone sets it.
  # Handled before the loop so a path containing spaces is not word-split.
  if [ -n "${KOW_PY:-}" ]; then
    if command -v -- "$KOW_PY" >/dev/null 2>&1 && _py_ok "$KOW_PY"; then
      command -v -- "$KOW_PY"; return 0
    fi
    red "KOW_PY=$KOW_PY is not a usable python >=3.12"; return 1
  fi
  local candidates="python3 python3.13 python3.12
    $PREFIX/opt/python@3.13/bin/python3.13 $PREFIX/opt/python@3.12/bin/python3.12
    python3.14 $PREFIX/opt/python@3.14/bin/python3.14"
  # pass 1 — a version we actually ship wheels for
  for c in $candidates; do
    command -v -- "$c" >/dev/null 2>&1 || continue
    mm="$(_py_mm "$c")"
    case " $SUPPORTED_PY " in *" $mm "*) command -v -- "$c"; return 0 ;; esac
  done
  # pass 2 — anything >=3.12; caller warns
  for c in $candidates; do
    command -v -- "$c" >/dev/null 2>&1 || continue
    _py_ok "$c" && { command -v -- "$c"; return 0; }
  done
  return 1
}
PY="$(find_python)" || {
  red "no python >=3.12 found (macOS ships 3.9). Install one: brew install python@3.13"
  exit 2
}

# Natively the tree is right here; inside a VM the runner rsyncs it to ~/kow-src.
SRC="${KOW_SRC:-$(cd "$(dirname "$0")/../.." && pwd)}"
[ -f "$SRC/pyproject.toml" ] || { red "no kow source tree at $SRC (set KOW_SRC)"; exit 2; }

PY_MM="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
printf '%s\n' "mode=$MODE  prefix=$PREFIX  python=$PY ($PY_MM)  src=$SRC"

# Say this out loud rather than letting it surface 200 lines later as an
# inscrutable wheel-build error: outside the shipped range, dependencies may
# have no binary wheel and pip will try to compile them.
case " $SUPPORTED_PY " in
  *" $PY_MM "*) ;;
  *) printf 'warning: python %s is outside this project'"'"'s supported range (%s).\n' "$PY_MM" "$SUPPORTED_PY"
     printf 'warning: dependencies may lack wheels and fall back to a source build. Set KOW_PY to override.\n' ;;
esac

REAL_SECRET="sk-live-MACTEST-$(head -c8 /dev/urandom | xxd -p)"
PLACEHOLDER="sk-PLACEHOLDER-mactest0000111122223333"
ECHO_PORT=18099

# Every file the harness itself writes lives here, so "no residue" is true for
# the logs too — not just the install. Removed by both teardowns.
RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e-run.XXXXXX")"

# ONE exit handler, armed here — before any of the refusal paths below can fire.
# Arming it later (inside the mode functions) leaked RUNDIR on every early exit.
# The mode teardowns self-guard on their own armed state, so this is safe to run
# no matter how far we got.
on_exit() {
  # declare -F guards the window before the mode teardowns are defined; nothing
  # currently exits in it, but a future top-level check might.
  case "$MODE" in
    user)     declare -F cleanup_user     >/dev/null && cleanup_user ;;
    keychain) declare -F cleanup_keychain >/dev/null && cleanup_keychain ;;
    gcp)      declare -F cleanup_gcp      >/dev/null && cleanup_gcp ;;
    system)   declare -F teardown_system  >/dev/null && teardown_system ;;
  esac
  [ "$KEEP" = "1" ] || rm -rf "$RUNDIR"
}
trap on_exit EXIT

# A fixed port that is already busy means the assertions could be answered by
# somebody else's proxy — a false PASS. Refuse rather than test the wrong process.
# Run a command under a wall-clock limit and return 124 if it outlasts it.
# macOS ships no `timeout(1)` — that is GNU coreutils — and reaching for it
# yields exit 127, which reads as "the command failed" and turns a hang into a
# false PASS. Output lands in $RUNDIR/limited.out for the caller to inspect.
run_limited() {
  local secs="$1"; shift
  "$@" >"$RUNDIR/limited.out" 2>&1 &
  local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt "$((secs * 2))" ]; do sleep 0.5; i=$((i + 1)); done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    return 124
  fi
  wait "$pid"
}

require_free_port() {
  local p="$1" what="$2"
  if nc -z 127.0.0.1 "$p" 2>/dev/null || lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    red "port $p ($what) is already in use — refusing to run, the assertions could not be trusted"
    exit 2
  fi
}

# ------------------------------------------------------------ shared upstream

ECHO_PID=""
# Killing a background job makes the shell print a "Terminated: 15" banner with
# the whole heredoc inline, which reads like a crash at the end of a passing
# run. Reap quietly instead.
stop_echo_upstream() {
  [ -n "$ECHO_PID" ] || return 0
  kill "$ECHO_PID" 2>/dev/null
  wait "$ECHO_PID" 2>/dev/null
  ECHO_PID=""
}

start_echo_upstream() {
  "$PY" - "$ECHO_PORT" <<'PY' >"$RUNDIR/echo.log" 2>&1 &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  ECHO_PID=$!
  sleep 2
}

# curl 7.86.0 and later treat localhost as an implicit no-proxy host, so a
# `-x` pointed at the proxy is SILENTLY IGNORED for a 127.0.0.1 upstream and the
# request goes direct. That turns "upstream saw the placeholder unchanged" into
# the expected result of a test that never reached the proxy at all. macOS ships
# curl 8.x, so every proxied request in this file passes --noproxy "" to force
# the proxy back on (verified against curl 8.21 on 2026-09-11).
#
# The four assertions every leg in this suite makes, against a running proxy.
assert_wire_chain() {
  local port="$1" audit="$2" daemon_log="${3:-}" sudo_read="${4:-}"

  step "healthz"
  local hz
  hz=$(curl -s --noproxy "" -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$port" http://healthz.kow.invalid/healthz)
  [ "$hz" = "200" ] && ok "healthz.kow.invalid -> 200" || bad "healthz returned $hz"

  step "real substitution on the wire"
  local seen
  seen=$(curl -s --noproxy "" -x "http://127.0.0.1:$port" -H "Authorization: Bearer ${PLACEHOLDER}" \
              "http://127.0.0.1:$ECHO_PORT/" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
  if [ "$seen" = "Bearer ${REAL_SECRET}" ]; then ok "upstream saw the REAL secret"
  elif [ "$seen" = "Bearer ${PLACEHOLDER}" ]; then bad "no substitution: upstream saw the placeholder unchanged"
  elif [ -z "$seen" ]; then bad "upstream saw nothing (request did not complete)"
  # Never echo the value itself: in a partial-substitution failure it IS the secret,
  # and CI logs are public.
  else bad "upstream saw an unexpected value (${#seen} bytes, withheld)"; fi

  step "deny an unbound destination"
  local code
  code=$(curl -s --noproxy "" -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$port" \
              -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/)
  [ "$code" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $code"

  step "audit + no secret bytes in any log"
  $sudo_read grep -q inject_decision "$audit" && ok "inject_decision audited" || bad "no inject_decision"
  if $sudo_read grep -q "$REAL_SECRET" "$audit" 2>/dev/null; then bad "SECRET IN AUDIT LOG"; else ok "no secret bytes in audit log"; fi
  if [ -n "$daemon_log" ]; then
    if $sudo_read grep -q "$REAL_SECRET" "$daemon_log" 2>/dev/null; then bad "SECRET IN DAEMON LOG"; else ok "no secret bytes in daemon log"; fi
  fi
}

write_bindings() {
  local conf="$1" secrets="$2" audit="$3"
  cat <<YAML
version: 1
binding_source: file
secrets:
  MACTEST_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {MACTEST_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: static
  config:
    type: static
    path: ${secrets}
audit:
  path: ${audit}
unmatched_destination_policy: deny
YAML
}

# ============================================================ unprivileged leg

# Deliberately NOT `local`: an EXIT trap fires after the function has returned,
# so anything scoped to it is already gone by teardown time. A teardown that
# silently sees unset paths is worse than no teardown at all.
U_BASE=""; U_PROXY_PID=""

cleanup_user() {
  if [ -n "$U_PROXY_PID" ]; then kill "$U_PROXY_PID" 2>/dev/null; wait "$U_PROXY_PID" 2>/dev/null; fi
  stop_echo_upstream
  [ -z "$U_BASE" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s (logs: %s)\n' "$U_BASE" "$RUNDIR"
  else rm -rf "$U_BASE"; fi
}

run_user_mode() {
  # mktemp, not a $$-predictable name: this path is recursively removed on exit,
  # and on a shared machine a pre-created dir or symlink here would be collateral.
  U_BASE="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e.XXXXXX")"
  local base="$U_BASE"
  local venv="$base/venv" audit="$base/audit.jsonl" log="$base/proxy.log"
  local port=14399
  export KOW_CONFDIR="$base/config"


  [ "$(id -u)" -ne 0 ] || { red "unprivileged mode must not run as root"; exit 2; }
  require_free_port "$port" "kow proxy"
  require_free_port "$ECHO_PORT" "test upstream"
  ok "running unprivileged (uid $(id -u)), nothing outside $base will be touched"

  mkdir -p "$KOW_CONFDIR/static" "$base/state"
  chmod 0700 "$base" "$base/state" "$KOW_CONFDIR" "$KOW_CONFDIR/static"

  step "1. user-local venv + install from this tree (no sudo anywhere)"
  "$PY" -m venv "$venv" >/dev/null 2>&1
  if "$venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip.log" 2>&1; then
    ok "installed into \$HOME without sudo"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip.log"; return
  fi
  "$venv/bin/kow" --version >/dev/null 2>&1 && ok "\`kow --version\` works" || bad "kow --version failed"

  step "2. config under \$KOW_CONFDIR (no /etc, no ${PREFIX})"
  # The static backend refuses a secrets file looser than 0600 in a 0700 parent.
  printf 'secrets:\n  MACTEST_KEY: "%s"\n' "$REAL_SECRET" > "$KOW_CONFDIR/static/secrets.yaml"
  chmod 0600 "$KOW_CONFDIR/static/secrets.yaml"
  write_bindings "$KOW_CONFDIR" "$KOW_CONFDIR/static/secrets.yaml" "$audit" > "$KOW_CONFDIR/bindings.yaml"
  chmod 0600 "$KOW_CONFDIR/bindings.yaml"
  ok "bindings.yaml + static secrets written under \$KOW_CONFDIR"

  step "3. run the proxy directly (no launchd, no service account)"
  HOME="$base/state" "$venv/bin/python" -m kow \
      --listen-host 127.0.0.1 --listen-port "$port" \
      --set kow_config="$KOW_CONFDIR/bindings.yaml" >"$log" 2>&1 &
  U_PROXY_PID=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$port" http://healthz.kow.invalid/healthz && break
    sleep 1
  done
  kill -0 "$U_PROXY_PID" 2>/dev/null && ok "proxy running as the calling user (pid $U_PROXY_PID)" \
    || { bad "proxy died on startup"; tail -12 "$log"; return; }

  start_echo_upstream
  assert_wire_chain "$port" "$audit" "$log" ""
}

# ================================================================ keychain leg
#
# The keychain backend (ADR-0046) against the REAL /usr/bin/security. The unit
# suite runs on Linux against a fake `security`, so everything that can only be
# answered by the actual tool is answered here: does `security -i` accept a
# quoted value on stdin, does exit 44 mean item-not-found, does dump-keychain
# enumerate without prompting.
#
# Unprivileged by construction, and not by accident: a keychain belongs to a
# login session, so a LaunchDaemon running as a service account has no access to
# the operator's. This leg running as the calling user IS the LaunchAgent
# constraint, demonstrated.
#
# Never touches the login keychain. Everything happens in a throwaway keychain
# created for the run and deleted on exit.

K_BASE=""; K_PROXY_PID=""; K_KEYCHAIN=""
K_SERVICE=kow-e2e

cleanup_keychain() {
  if [ -n "$K_PROXY_PID" ]; then kill "$K_PROXY_PID" 2>/dev/null; wait "$K_PROXY_PID" 2>/dev/null; fi
  stop_echo_upstream
  if [ -n "$K_KEYCHAIN" ] && [ "$KEEP" != "1" ]; then
    security delete-keychain "$K_KEYCHAIN" 2>/dev/null
    if [ -e "$K_KEYCHAIN" ]; then
      red "  RESIDUE LEFT: $K_KEYCHAIN"
    else
      printf '  clean: throwaway keychain deleted\n'
    fi
  fi
  [ -z "$K_BASE" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s (logs: %s)\n' "$K_BASE" "$RUNDIR"
  else rm -rf "$K_BASE"; fi
}

run_keychain_mode() {
  K_BASE="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e-kc.XXXXXX")"
  local base="$K_BASE"
  local venv="$base/venv" audit="$base/audit.jsonl" log="$base/proxy.log"
  local port=14377
  export KOW_CONFDIR="$base/config"

  [ "$(id -u)" -ne 0 ] || { red "the keychain leg must not run as root — a keychain belongs to a login session"; exit 2; }
  require_free_port "$port" "kow proxy"
  require_free_port "$ECHO_PORT" "test upstream"

  mkdir -p "$KOW_CONFDIR" "$base/state"
  chmod 0700 "$base" "$base/state" "$KOW_CONFDIR"

  step "1. throwaway keychain (the login keychain is never touched)"
  K_KEYCHAIN="$base/kow-e2e.keychain-db"
  # Password for a keychain that exists for ~60 seconds and holds only test
  # values. It is on argv; the credentials the backend stores are not, which is
  # the property this leg is here to prove.
  local kcpw; kcpw="e2e-$(head -c12 /dev/urandom | xxd -p)"
  security create-keychain -p "$kcpw" "$K_KEYCHAIN" \
    && ok "created $K_KEYCHAIN" || { bad "create-keychain failed"; return; }
  security set-keychain-settings "$K_KEYCHAIN"      # no auto-lock timeout
  security unlock-keychain -p "$kcpw" "$K_KEYCHAIN" \
    && ok "unlocked" || { bad "unlock-keychain failed"; return; }
  # create-keychain does not join the search list. Assert it, because a leaked
  # entry there outlives the file and confuses every later `security` call.
  if security list-keychains | grep -q "kow-e2e"; then
    bad "throwaway keychain entered the search list"
  else
    ok "not in the keychain search list"
  fi

  step "2. user-local venv + install from this tree"
  "$PY" -m venv "$venv" >/dev/null 2>&1
  if "$venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip.log" 2>&1; then
    ok "installed into \$HOME without sudo"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip.log"; return
  fi

  step "3. bindings.yaml pointing at the keychain backend"
  cat > "$KOW_CONFDIR/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  MACTEST_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {MACTEST_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: keychain
  config:
    type: keychain
    service: ${K_SERVICE}
    keychain: ${K_KEYCHAIN}
    self_check: deny
audit:
  path: ${audit}
unmatched_destination_policy: deny
YAML
  chmod 0600 "$KOW_CONFDIR/bindings.yaml"
  ok "bindings.yaml written (backend.type: keychain)"

  step "4. \`kow secret add\` writes through the CLI"
  printf '%s\n' "$REAL_SECRET" | "$venv/bin/kow" secret add MACTEST_KEY --stdin \
      --config "$KOW_CONFDIR/bindings.yaml" >/dev/null 2>&1 \
    && ok "kow secret add MACTEST_KEY" || bad "kow secret add failed"

  # The real `security` is the authority on whether the value landed intact.
  local direct
  direct=$(security find-generic-password -a MACTEST_KEY -s "$K_SERVICE" -w "$K_KEYCHAIN" 2>/dev/null)
  [ "$direct" = "$REAL_SECRET" ] && ok "security agrees the stored value is byte-identical" \
    || bad "stored value differs from what was written"

  step "5. the \`security -i\` quoting protocol, against the real tool"
  # The whole no-argv write path rests on security's interactive parser handling
  # a quoted value. A value with a space, a double quote, a backslash and a
  # dollar sign is where a naive implementation corrupts the credential.
  local tricky='a b"c\d $HOME `id` end'
  printf '%s\n' "$tricky" | "$venv/bin/kow" secret add MACTEST_TRICKY --stdin \
      --config "$KOW_CONFDIR/bindings.yaml" >/dev/null 2>&1
  local back
  back=$(security find-generic-password -a MACTEST_TRICKY -s "$K_SERVICE" -w "$K_KEYCHAIN" 2>/dev/null)
  [ "$back" = "$tricky" ] && ok "shell-hostile value round-trips exactly" \
    || bad "quoting protocol mangled the value (${#back} bytes back, ${#tricky} written)"

  step "7. \`kow secret list\` enumerates without prompting"
  local listed
  listed=$("$venv/bin/kow" secret list --config "$KOW_CONFDIR/bindings.yaml" 2>/dev/null)
  printf '%s\n' "$listed" | grep -qx MACTEST_KEY && ok "MACTEST_KEY listed" || bad "MACTEST_KEY not listed"
  printf '%s\n' "$listed" | grep -qx MACTEST_TRICKY && ok "MACTEST_TRICKY listed" || bad "MACTEST_TRICKY not listed"

  step "8. no plaintext secret anywhere under the config dir"
  if grep -rq "$REAL_SECRET" "$KOW_CONFDIR" 2>/dev/null; then
    bad "SECRET FOUND IN A CONFIG FILE"
  else
    ok "no secret bytes on disk outside the keychain"
  fi

  step "9. run the proxy against the keychain backend"
  HOME="$base/state" "$venv/bin/python" -m kow \
      --listen-host 127.0.0.1 --listen-port "$port" \
      --set kow_config="$KOW_CONFDIR/bindings.yaml" >"$log" 2>&1 &
  K_PROXY_PID=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$port" http://healthz.kow.invalid/healthz && break
    sleep 1
  done
  kill -0 "$K_PROXY_PID" 2>/dev/null && ok "proxy running (pid $K_PROXY_PID)" \
    || { bad "proxy died on startup"; tail -12 "$log"; return; }

  start_echo_upstream
  assert_wire_chain "$port" "$audit" "$log" ""

  step "10. a LOCKED keychain fails closed, and does not hang"
  # The production failure mode: a lid-close locks the keychain under a
  # long-running LaunchAgent. `security` must return an ERROR rather than block
  # forever on an unlock prompt nobody is there to answer. Every assertion here
  # is timed, so a hang FAILS the leg instead of stalling it.
  security lock-keychain "$K_KEYCHAIN"

  # First, the property that surprises people: an already-running proxy keeps
  # serving, because the value is cached. A lid-close does not break in-flight
  # traffic, and that is correct.
  local locked_rc
  locked_rc=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
                -x "http://127.0.0.1:$port" -H "Authorization: Bearer ${PLACEHOLDER}" \
                "http://127.0.0.1:$ECHO_PORT/")
  if [ "$locked_rc" = "000" ]; then
    bad "locked keychain HUNG the running proxy (no response in 30s)"
  else
    ok "running proxy keeps serving from cache while locked (-> $locked_rc)"
  fi

  # Now the path that actually reaches the locked keychain: a FRESH process with
  # nothing cached. It must fail, fail quickly, and name the fix.
  local lockout rc9
  run_limited 60 "$venv/bin/kow" secret list --config "$KOW_CONFDIR/bindings.yaml"; rc9=$?
  lockout=$(cat "$RUNDIR/limited.out")
  if [ "$rc9" = "124" ]; then
    bad "a locked keychain HUNG a fresh kow process (blocked on an unlock prompt)"
  elif [ "$rc9" = "0" ]; then
    bad "a locked keychain was read anyway (rc 0) — the lock bought nothing"
  else
    ok "fresh process fails closed on a locked keychain (rc $rc9, no hang)"
  fi
  case "$lockout" in
    *unlock-keychain*) ok "the error names \`security unlock-keychain\` as the fix" ;;
    *)                 bad "locked-keychain error does not name the fix: ${lockout%%$'\n'*}" ;;
  esac

  security unlock-keychain -p "$kcpw" "$K_KEYCHAIN"
  run_limited 60 "$venv/bin/kow" secret list --config "$KOW_CONFDIR/bindings.yaml" \
    && ok "recovers after unlock" || bad "still failing after unlock-keychain"

  step "11. removal"
  "$venv/bin/kow" secret remove MACTEST_TRICKY --config "$KOW_CONFDIR/bindings.yaml" >/dev/null 2>&1
  security find-generic-password -a MACTEST_TRICKY -s "$K_SERVICE" "$K_KEYCHAIN" >/dev/null 2>&1 \
    && bad "item still present after kow secret remove" || ok "kow secret remove deleted the item"
}

# ============================================================== system leg

# Globals for the same reason as the user leg — the EXIT trap must still be able
# to see every path it is responsible for removing.
S_USR=_kow
S_CONF=""; S_STATE=""; S_LOGD=""; S_OPTDIR=""
S_PLIST=/Library/LaunchDaemons/io.inflightsec.kow.plist

teardown_system() {
  stop_echo_upstream
  [ -z "$S_CONF" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept installed (teardown skipped; logs: %s)\n' "$RUNDIR"; return; fi
  printf '\n== teardown\n'
  sudo launchctl bootout system/io.inflightsec.kow 2>/dev/null \
    || sudo launchctl unload -w "$S_PLIST" 2>/dev/null
  sudo rm -f "$S_PLIST"
  # sappnd blocks removal until it is cleared, so this must precede the rm.
  # It must be nosappnd, NOT noappnd: sappnd is the SYSTEM append-only flag and
  # noappnd only clears the USER one (uappnd), so the audit log stayed
  # undeletable and the whole log dir survived teardown. Caught on a real Mac.
  sudo chflags -R nosappnd,nouappnd "$S_LOGD" 2>/dev/null \
    || sudo chflags -R nosappnd "$S_LOGD" 2>/dev/null
  sudo rm -rf "$S_CONF" "$S_STATE" "$S_LOGD" "$S_OPTDIR"
  sudo dseditgroup -o delete "$S_USR" >/dev/null 2>&1
  sudo dscl . -delete "/Users/$S_USR" >/dev/null 2>&1
  sudo dscacheutil -flushcache 2>/dev/null
  local left=""
  for p in "$S_PLIST" "$S_CONF" "$S_STATE" "$S_LOGD" "$S_OPTDIR"; do [ -e "$p" ] && left="$left $p"; done
  dscl . -read "/Groups/$S_USR" >/dev/null 2>&1 && left="$left group:$S_USR"
  dscl . -read "/Users/$S_USR" >/dev/null 2>&1 && left="$left user:$S_USR"
  [ -z "$left" ] && printf '  clean: every artifact removed\n' || red "  RESIDUE LEFT:$left"
}

run_system_mode() {
  local usr="$S_USR"
  local conf="$PREFIX/etc/kow" state="$PREFIX/var/lib/kow" logd="$PREFIX/var/log/kow"
  local optdir="$PREFIX/opt/kow"
  local plist="$S_PLIST"
  local port=14322

  if [ "${KOW_E2E_CONSENT:-}" != "1" ]; then
    cat >&2 <<EOF

REFUSING TO RUN --system WITHOUT CONSENT.

This performs the real documented install on THIS machine:
  * creates the ${usr} service account and group (dscl)
  * installs and loads a LaunchDaemon at ${plist}
  * writes ${conf}, ${state}, ${logd}, ${optdir}
  * sets the append-only system flag (chflags sappnd) on the audit log

All of it is reversed when the script exits (use --keep to retain it), but a
hard kill can leave residue. Prefer the default unprivileged mode, or a
throwaway machine such as a CI runner.

  KOW_E2E_CONSENT=1 bash $0 --system

EOF
    exit 2
  fi

  sudo -n true 2>/dev/null || sudo -v || { red "--system needs sudo"; exit 2; }

  # With no brew, PREFIX is a guess and we would be creating service directories
  # under a tree Homebrew does not manage. That is still the documented layout,
  # but say so rather than let it look deliberate.
  command -v brew >/dev/null 2>&1 \
    || printf 'note: Homebrew not found; using %s as the install prefix (set KOW_PREFIX to override)\n' "$PREFIX"

  # Never touch a real deployment. The teardown removes six paths plus the group
  # and the user, so the refusal check must cover EVERY ONE of them — anything
  # checked here but not there is a gap that destroys somebody's data. Keep the
  # two lists in step.
  local found=""
  [ -e "$plist" ]  && found="$found $plist"
  [ -e "$conf" ]   && found="$found $conf"
  [ -e "$state" ]  && found="$found $state"
  [ -e "$logd" ]   && found="$found $logd"
  [ -e "$optdir" ] && found="$found $optdir"
  dscl . -read "/Groups/$usr" >/dev/null 2>&1 && found="$found group:$usr"
  dscl . -read "/Users/$usr"  >/dev/null 2>&1 && found="$found user:$usr"
  # A job can be loaded with its plist deleted; teardown would boot out something
  # it never started.
  sudo launchctl print system/io.inflightsec.kow >/dev/null 2>&1 && found="$found launchd:io.inflightsec.kow"
  if [ -n "$found" ]; then
    red "refusing: an existing kow install was found:$found"
    red "remove it first, or run the default unprivileged mode."
    exit 2
  fi

  require_free_port "$port" "kow proxy"
  require_free_port "$ECHO_PORT" "test upstream"

  # Arm the teardown only once the pre-existing-install check has passed, so a
  # refusal can never remove someone else's deployment.
  S_CONF="$conf"; S_STATE="$state"; S_LOGD="$logd"; S_OPTDIR="$optdir"

  step "1. service account + directories + append-only audit"
  # uid/gid 250 is the stock _analyticsusers group on every Mac — derive a free one.
  local nid
  nid=$(for i in $(seq 450 550); do
          dscl . -list /Groups PrimaryGroupID | awk -v G="$i" '$2==G' | grep -q . || { echo "$i"; break; }
        done)
  # An empty nid means the whole range was taken. Without set -e the dscl calls
  # below would each fail quietly and leave a half-built account behind.
  case "$nid" in
    ''|*[!0-9]*) red "could not find a free gid in 450-550 (got '${nid}')"; exit 2 ;;
  esac
  sudo dseditgroup -o create -i "$nid" $usr
  sudo dscl . -create /Users/$usr UniqueID "$nid"
  sudo dscl . -create /Users/$usr PrimaryGroupID "$nid"
  sudo dscl . -create /Users/$usr UserShell /usr/bin/false
  sudo dscl . -create /Users/$usr NFSHomeDirectory /var/empty
  sudo dscacheutil -flushcache 2>/dev/null
  dscl . -read /Groups/$usr PrimaryGroupID >/dev/null 2>&1 \
    && ok "service group $usr has a usable gid ($nid)" || bad "group $usr has no PrimaryGroupID"

  # Prove the group name is actually usable by chown — this is what caught the
  # uid-250 collision. Use a scratch dir; never the shared /tmp.
  local canary; canary=$(mktemp -d)
  sudo chown "root:$usr" "$canary" 2>/dev/null && ok "group usable as a chown target" || bad "illegal group name for chown"
  sudo rm -rf "$canary"

  sudo install -d -o root  -g $usr -m 0750 "$conf"
  sudo install -d -o $usr  -g $usr -m 0750 "$state"
  sudo install -d -o $usr  -g $usr -m 0750 "$logd"
  sudo touch "$logd/audit.jsonl"
  sudo chown $usr:$usr "$logd/audit.jsonl"
  sudo chmod 0640 "$logd/audit.jsonl"
  sudo chflags sappnd "$logd/audit.jsonl" && ok "audit log append-only (chflags sappnd)" || bad "chflags sappnd failed"
  [ -d "$conf" ] && ok "confdir $conf created" || bad "confdir missing"

  step "2. venv + install from this tree (under $PREFIX)"
  sudo "$PY" -m venv "$optdir/.venv" >/dev/null 2>&1
  if sudo "$optdir/.venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip.log" 2>&1; then
    ok "installed from source tree"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip.log"; return
  fi
  "$optdir/.venv/bin/kow" --version >/dev/null 2>&1 && ok "\`kow --version\` works" || bad "kow --version failed"

  step "3. static bindings"
  sudo install -d -o $usr -g $usr -m 0700 "$conf/static"
  printf 'secrets:\n  MACTEST_KEY: "%s"\n' "$REAL_SECRET" | sudo tee "$conf/static/secrets.yaml" >/dev/null
  sudo chown $usr:$usr "$conf/static/secrets.yaml"; sudo chmod 0600 "$conf/static/secrets.yaml"
  write_bindings "$conf" "$conf/static/secrets.yaml" "$logd/audit.jsonl" | sudo tee "$conf/bindings.yaml" >/dev/null
  sudo chown "root:$usr" "$conf/bindings.yaml"; sudo chmod 0640 "$conf/bindings.yaml"
  ok "bindings.yaml + static secrets written"

  step "4. launchd daemon"
  sudo "$optdir/.venv/bin/python" - "$plist" "$usr" "$optdir" "$conf" "$state" "$logd" <<'PY'
import plistlib, sys
plist, usr, optdir, conf, state, logd = sys.argv[1:7]
plistlib.dump({
    "Label": "io.inflightsec.kow",
    "UserName": usr, "GroupName": usr,
    "ProgramArguments": [f"{optdir}/.venv/bin/python", "-m", "kow",
                         "--set", f"kow_config={conf}/bindings.yaml"],
    "EnvironmentVariables": {"HOME": state},
    "RunAtLoad": True, "KeepAlive": True,
    "StandardErrorPath": f"{logd}/stderr.log",
}, open(plist, "wb"))
PY
  sudo chown root:wheel "$plist"; sudo chmod 0644 "$plist"
  sudo launchctl load -w "$plist" 2>/dev/null
  sleep 8
  sudo launchctl print system/io.inflightsec.kow >/dev/null 2>&1 \
    && ok "launchd daemon loaded (system/io.inflightsec.kow)" || bad "daemon not registered in the system domain"
  if netstat -an 2>/dev/null | grep -q "127.0.0.1.$port.*LISTEN"; then
    ok "listening on 127.0.0.1:$port"
  else
    bad "no listener on $port"; sudo tail -12 "$logd/stderr.log" 2>/dev/null
  fi

  start_echo_upstream
  assert_wire_chain "$port" "$logd/audit.jsonl" "$logd/stderr.log" sudo
}

# ===================================================== gcp service account leg
#
# ADR-0050 on macOS, with the signing key in a real Keychain and no network.
#
# Three things this leg proves that no Linux test can:
#   1. The Keychain backend REFUSES a multi-line value, cleanly and before it
#      spawns anything. `security -i` would truncate at the first newline, so
#      _reject_untransmittable stops it at the API boundary. That means the
#      key-bearing GCP modes (jwt_bearer_grant, impersonate --source seat_key)
#      CANNOT use the Keychain backend, and the refusal must stay loud: a
#      silently shortened signing key is the worst outcome available here.
#      The keyless default (impersonate --source adc) needs no key at all, which
#      is the macOS story this constraint leaves intact.
#   2. The credential endpoint serves on macOS loopback with the content types
#      Google's own client libraries require.
#   3. The full chain on the real `security(1)`: key in the Keychain -> kow
#      mints a self-signed assertion -> the upstream receives a JWT that
#      VERIFIES against the public key, while the caller held only a placeholder.
#
# `self_signed_jwt` is used deliberately: it is the one mode that mints without
# talking to Google, so this leg needs no network and no GCP project.

G_BASE=""; G_PROXY_PID=""; G_KEYCHAIN=""
G_SERVICE=kow-e2e-gcp
G_SA=e2e-runner@kow-e2e.iam.gserviceaccount.com
G_PLACEHOLDER="ya29.kow-PLACEHOLDER-macose2e0123456789"

cleanup_gcp() {
  if [ -n "$G_PROXY_PID" ]; then kill "$G_PROXY_PID" 2>/dev/null; wait "$G_PROXY_PID" 2>/dev/null; fi
  stop_echo_upstream
  if [ -n "$G_KEYCHAIN" ] && [ "$KEEP" != "1" ]; then
    security delete-keychain "$G_KEYCHAIN" 2>/dev/null
    if [ -e "$G_KEYCHAIN" ]; then red "  RESIDUE LEFT: $G_KEYCHAIN"
    else printf '  clean: throwaway keychain deleted\n'; fi
  fi
  [ -z "$G_BASE" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s (logs: %s)\n' "$G_BASE" "$RUNDIR"
  else rm -rf "$G_BASE"; fi
}

run_gcp_mode() {
  G_BASE="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e-gcp.XXXXXX")"
  local base="$G_BASE"
  local venv="$base/venv" audit="$base/audit.jsonl" log="$base/proxy.log"
  local port=14379 metaport=14381
  export KOW_CONFDIR="$base/config"

  [ "$(id -u)" -ne 0 ] || { red "the gcp leg must not run as root - a keychain belongs to a login session"; exit 2; }
  require_free_port "$port" "kow proxy"
  require_free_port "$metaport" "credential endpoint"
  require_free_port "$ECHO_PORT" "test upstream"

  mkdir -p "$KOW_CONFDIR" "$base/state"
  chmod 0700 "$base" "$base/state" "$KOW_CONFDIR"

  step "1. throwaway keychain (the login keychain is never touched)"
  G_KEYCHAIN="$base/kow-e2e-gcp.keychain-db"
  local kcpw; kcpw="e2e-$(head -c12 /dev/urandom | xxd -p)"
  security create-keychain -p "$kcpw" "$G_KEYCHAIN" && ok "created $G_KEYCHAIN" \
    || { bad "create-keychain failed"; return; }
  security set-keychain-settings "$G_KEYCHAIN"
  security unlock-keychain -p "$kcpw" "$G_KEYCHAIN" && ok "unlocked" \
    || { bad "unlock-keychain failed"; return; }

  step "2. user-local venv + install from this tree"
  "$PY" -m venv "$venv" >/dev/null 2>&1
  if "$venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip-gcp.log" 2>&1; then
    ok "installed into \$HOME without sudo"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip-gcp.log"; return
  fi

  step "3. generate an RSA signing key (it never touches the config)"
  "$venv/bin/python" - "$base" <<'PY'
import sys, pathlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
base = pathlib.Path(sys.argv[1])
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
base.joinpath("sa-signing.pem").write_bytes(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption()))
base.joinpath("sa-public.pem").write_bytes(key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
PY
  [ -s "$base/sa-signing.pem" ] && ok "2048-bit key generated" || { bad "key generation failed"; return; }
  chmod 0600 "$base/sa-signing.pem"

  step "4. the Keychain REFUSES a multi-line value (and says why)"
  # Pinned as a regression: this refusal is what stops `security -i` truncating
  # a signing key at its first newline. If it ever silently succeeds, a later
  # mint would sign with a prefix of the key and fail in a way that looks like
  # a Google problem.
  cat > "$base/kc-bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  GCP_SA_KEY:
    placeholder: "kow-PLACEHOLDER-keychain-refusal-check"
    inject:
      header: "Authorization"
      format: "Bearer {GCP_SA_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: keychain
  config:
    type: keychain
    service: ${G_SERVICE}
    keychain: ${G_KEYCHAIN}
    self_check: deny
audit:
  path: ${audit}
YAML
  chmod 0600 "$base/kc-bindings.yaml"
  local kcout
  kcout=$("$venv/bin/kow" secret add GCP_SA_KEY --stdin \
      --config "$base/kc-bindings.yaml" < "$base/sa-signing.pem" 2>&1)
  if [ $? -eq 0 ]; then
    bad "the keychain accepted a multi-line value - security -i would truncate it"
  elif printf '%s' "$kcout" | grep -qi "single-line"; then
    ok "refused, with the reason named (key-bearing modes need a networked backend)"
  else
    bad "refused, but not with the documented reason: $(printf '%s' "$kcout" | head -1)"
  fi

  local stray
  stray=$(security find-generic-password -a GCP_SA_KEY -s "$G_SERVICE" -w "$G_KEYCHAIN" 2>/dev/null)
  [ -z "$stray" ] && ok "nothing partial was written to the keychain" \
    || bad "a truncated value reached the keychain"

  step "5. bindings.yaml: static backend + gcp_service_account + credential endpoint"
  cat > "$KOW_CONFDIR/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  GCP:
    placeholder: "${G_PLACEHOLDER}"
    inject:
      type: gcp_service_account
      mode: self_signed_jwt
      service_account_email: ${G_SA}
      private_key_secret: GCP_SA_KEY
      audience: "http://127.0.0.1:${ECHO_PORT}/"
    bindings:
      - host: "127.0.0.1"
        methods: [GET]
credential_endpoint:
  enabled: true
  port: ${metaport}
  binding: GCP
  project_id: kow-e2e
backend:
  type: static
  config:
    path: ${base}/static-secrets.yaml
audit:
  path: ${audit}
YAML
  chmod 0600 "$KOW_CONFDIR/bindings.yaml"
  ok "bindings.yaml written (static backend: the Keychain cannot hold a PEM)"

  step "6. the signing key goes into the static backend, mode 0600"
  "$venv/bin/python" - "$base" <<'PY'
import pathlib, sys
base = pathlib.Path(sys.argv[1])
pem = base.joinpath("sa-signing.pem").read_text()
indented = "".join("    " + line for line in pem.splitlines(keepends=True))
base.joinpath("static-secrets.yaml").write_text("secrets:\n  GCP_SA_KEY: |\n" + indented)
PY
  chmod 0600 "$base/static-secrets.yaml"
  [ -s "$base/static-secrets.yaml" ] && ok "static secrets file written" \
    || { bad "could not write the static secrets file"; return; }

  step "7. start the daemon"
  start_echo_upstream
  "$venv/bin/kow" --set kow_config="$KOW_CONFDIR/bindings.yaml" --mode "regular@${port}" \
    >"$log" 2>&1 &
  G_PROXY_PID=$!
  sleep 8
  kill -0 "$G_PROXY_PID" 2>/dev/null && ok "daemon running (pid $G_PROXY_PID)" \
    || { bad "daemon exited"; tail -12 "$log"; return; }

  step "8. the credential endpoint answers ADC the way Google's libraries need"
  local tok ctype
  tok=$(curl -s -H "Metadata-Flavor: Google" \
    "http://127.0.0.1:${metaport}/computeMetadata/v1/instance/service-accounts/default/token")
  ctype=$(curl -s -o /dev/null -w '%{content_type}' -H "Metadata-Flavor: Google" \
    "http://127.0.0.1:${metaport}/computeMetadata/v1/instance/service-accounts/default/token")
  printf '%s' "$tok" | grep -q "$G_PLACEHOLDER" \
    && ok "token endpoint serves the PLACEHOLDER, not a credential" \
    || bad "token endpoint did not serve the placeholder"
  case "$ctype" in application/json*) ok "labelled application/json (google-auth requires it)" ;;
    *) bad "token response content-type was '$ctype', not application/json" ;; esac
  curl -s -H "Metadata-Flavor: Google" \
    "http://127.0.0.1:${metaport}/computeMetadata/v1/instance/service-accounts/default/?recursive=true" \
    | grep -q "$G_SA" && ok "recursive ADC document names the service account" \
    || bad "recursive ADC document missing or wrong"
  local nohdr
  nohdr=$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:${metaport}/computeMetadata/v1/instance/service-accounts/default/token")
  [ "$nohdr" = "403" ] && ok "refuses a request without Metadata-Flavor" \
    || bad "answered without the flavor header (got $nohdr)"

  step "9. the wire: the upstream receives a VERIFIABLE assertion, not the placeholder"
  local seen
  seen=$(curl -s --noproxy "" -x "http://127.0.0.1:$port" -H "Authorization: Bearer ${G_PLACEHOLDER}" \
      "http://127.0.0.1:$ECHO_PORT/" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
  case "$seen" in
    "Bearer ${G_PLACEHOLDER}") bad "no substitution: upstream saw the placeholder unchanged"; return ;;
    "") bad "upstream saw nothing (request did not complete)"; return ;;
    "Bearer eyJ"*) ok "upstream saw a minted JWT" ;;
    *) bad "upstream saw an unexpected value (${#seen} bytes, withheld)"; return ;;
  esac

  printf '%s' "${seen#Bearer }" > "$base/assertion.jwt"
  if "$venv/bin/python" - "$base/assertion.jwt" "$base/sa-public.pem" "$G_SA" "$ECHO_PORT" <<'PY'
import base64, json, sys, time, pathlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

jwt = pathlib.Path(sys.argv[1]).read_text().strip()
pub = serialization.load_pem_public_key(pathlib.Path(sys.argv[2]).read_bytes())
email, echo_port = sys.argv[3], sys.argv[4]

def b64(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

h, p, sig = jwt.split(".")
pub.verify(b64(sig), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
header, claims = json.loads(b64(h)), json.loads(b64(p))
assert header["alg"] == "RS256", header
assert claims["iss"] == email, claims
assert claims["sub"] == email, claims          # the self-signed form sets sub == iss
assert claims["aud"] == f"http://127.0.0.1:{echo_port}/", claims
assert claims["exp"] - claims["iat"] <= 3600, "assertion outlives Google's ceiling"
assert claims["exp"] > time.time(), "assertion already expired"
PY
  then
    ok "the assertion verifies against the public key, with the right claims"
  else
    bad "the minted assertion failed signature or claim verification"
  fi

  step "10. no key material anywhere it should not be"
  # Match on real key BYTES (a slice of the base64 body), not on the PEM header:
  # a header-only check would pass against a partially-written value.
  local needle leaked=0
  needle=$(sed -n '3p' "$base/sa-signing.pem" | cut -c1-40)
  [ -n "$needle" ] || { bad "could not sample the key for the leak check"; return; }
  grep -qF "$needle" "$audit" 2>/dev/null && { bad "key bytes found in the audit log"; leaked=1; }
  grep -qF "$needle" "$log" 2>/dev/null && { bad "key bytes found in the daemon log"; leaked=1; }
  grep -qF "$needle" "$KOW_CONFDIR/bindings.yaml" && { bad "key bytes found in bindings.yaml"; leaked=1; }
  [ "$leaked" = "0" ] && ok "no key bytes in the audit log, the daemon log, or the config"

  step "11. the audit recorded the injection"
  grep -q '"decision": *"allowed"' "$audit" 2>/dev/null \
    && ok "inject_decision: allowed recorded" || bad "no allowed decision in the audit log"
}

# ===================================================================== driver

case "$MODE" in
  user)     run_user_mode ;;
  keychain) run_keychain_mode ;;
  gcp)      run_gcp_mode ;;
  system)   run_system_mode ;;
esac

printf '\n===== kow macOS e2e (%s): %d passed, %d failed =====\n' "$MODE" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
