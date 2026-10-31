#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QSCTL="${QSCTL:-$ROOT/target/debug/qsctl}"

if [[ "$(id -u)" == "0" ]]; then
  echo "ERROR: run this test as the normal unprivileged user, not root." >&2
  exit 2
fi
command -v bwrap >/dev/null 2>&1 || {
  echo "ERROR: Bubblewrap is required. On Void/SpiderOS: sudo xbps-install -S bubblewrap" >&2
  exit 2
}
[[ -x "$QSCTL" ]] || { echo "ERROR: qsctl binary not found/executable: $QSCTL" >&2; exit 2; }
SH="$(type -P sh || true)"
[[ -n "$SH" && -x "$SH" ]] || { echo "ERROR: could not find an executable sh." >&2; exit 2; }

BASE="$HOME/SecurityReports/qs-sandbox-test-$$-$(date +%s)-$RANDOM"
APP="$BASE/app"
OUT="$BASE/output"
mkdir -p "$APP" "$OUT"
chmod 700 "$BASE" "$APP" "$OUT"
cleanup() {
  # Safety check: only remove under $HOME/SecurityReports
  case "$BASE" in
    "$HOME"/SecurityReports/qs-sandbox-test-*) rm -rf -- "$BASE" ;;
    *) echo "REFUSING cleanup of unexpected path: $BASE" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

cat > "$APP/probe.sh" <<'PROBE'
#!/bin/sh
if printf 'tamper' > "$0" 2>/dev/null; then
  echo 'QS_APPDIR_WRITABLE_UNEXPECTEDLY'
  exit 41
fi
printf 'QS_APPDIR_READONLY\n'
PROBE
chmod 700 "$APP/probe.sh"

echo "=== executable + read-only app directory ==="
APP_OUT="$("$QSCTL" sandbox-run "$APP/probe.sh" --app-dir "$APP")"
grep -Fxq 'QS_APPDIR_READONLY' <<<"$APP_OUT" || { printf '%s\n' "$APP_OUT" >&2; echo "FAIL: app directory was not read-only." >&2; exit 1; }
echo "PASS: app launched and could not modify its read-only app directory."

echo
echo "=== host home hidden ==="
HOME_OUT="$("$QSCTL" sandbox-run "$SH" -- -c 'test ! -e "$1" && printf QS_HOME_HIDDEN' qs-test "$HOME")"
grep -Fq 'QS_HOME_HIDDEN' <<<"$HOME_OUT" || { printf '%s\n' "$HOME_OUT" >&2; echo "FAIL: host home was visible in the sandbox." >&2; exit 1; }
echo "PASS: the host HOME path was not visible inside the sandbox."

echo
echo "=== sandbox root is read-only ==="
ROOT_OUT="$($QSCTL sandbox-run "$SH" -- -c 'if touch /qs-root-write-test 2>/dev/null; then echo QS_ROOT_WRITABLE_UNEXPECTEDLY; exit 42; else echo QS_ROOT_READONLY; fi' qs-test)"
grep -Fq 'QS_ROOT_READONLY' <<<"$ROOT_OUT" || { printf '%s\n' "$ROOT_OUT" >&2; echo "FAIL: sandbox root filesystem accepted a write." >&2; exit 1; }
echo "PASS: unbound root filesystem is read-only."

echo
echo "=== Mandatory PID namespace isolation ==="
HOST_PID_NS="$(readlink /proc/self/ns/pid)"
CHILD_PID_NS="$("$QSCTL" sandbox-run "$SH" -- -c 'readlink /proc/self/ns/pid' qs-test)"
[[ "$HOST_PID_NS" != "$CHILD_PID_NS" ]] || {
  echo "FAIL: PID namespace was not isolated." >&2
  exit 1
}
echo "PASS: PID namespace differs from the host."

echo
echo "=== Network namespace isolation (capability-dependent) ==="
HOST_NET_NS="$(readlink /proc/self/ns/net)"
if NET_OUT="$("$QSCTL" sandbox-run "$SH" -- -c 'readlink /proc/self/ns/net' qs-test 2>&1)"; then
  CHILD_NET_NS="$(printf '%s\n' "$NET_OUT" | grep -Eo 'net:\[[0-9]+\]' | tail -n 1)"
  [[ -n "$CHILD_NET_NS" ]] || {
    printf '%s\n' "$NET_OUT" >&2
    echo "FAIL: could not read child network namespace." >&2
    exit 1
  }
  [[ "$HOST_NET_NS" != "$CHILD_NET_NS" ]] || {
    echo "FAIL: network namespace was not isolated by default." >&2
    exit 1
  }
  echo "PASS: network namespace differs from the host."
else
  if grep -qiF 'no permissions to create a new namespace' <<<"$NET_OUT" &&
     grep -qiF 'non-privileged user namespaces' <<<"$NET_OUT"; then
    echo "SKIP: host lacks the recognized unprivileged network namespace capability."
  else
    printf '%s\n' "$NET_OUT" >&2
    echo "FAIL: network namespace probe failed for an unexpected reason." >&2
    exit 1
  fi
fi

# QS_EFFECTIVE_RLIMITS_CHECK
echo
echo "=== effective kernel resource limits ==="
LIMITS_OUT="$("$QSCTL" sandbox-run "$SH" -- -c 'cat /proc/self/limits' qs-test)"

check_limit() {
  label="$1"
  pattern="$2"
  if printf '%s\n' "$LIMITS_OUT" | grep -Eq "$pattern"; then
    echo "PASS: $label"
  else
    echo "FAIL: $label is not set to the expected kernel limit." >&2
    printf '%s\n' "$LIMITS_OUT" >&2
    exit 1
  fi
}

check_limit "CPU time: 60 seconds" \
  'Max cpu time[[:space:]]+60[[:space:]]+60[[:space:]]+seconds'
check_limit "Address space: 512 MiB" \
  'Max address space[[:space:]]+536870912[[:space:]]+536870912[[:space:]]+bytes'
check_limit "File size: 256 MiB" \
  'Max file size[[:space:]]+268435456[[:space:]]+268435456[[:space:]]+bytes'
check_limit "Open file descriptors: 1024" \
  'Max open files[[:space:]]+1024[[:space:]]+1024[[:space:]]+files'
check_limit "Process count: 256" \
  'Max processes[[:space:]]+256[[:space:]]+256[[:space:]]+processes'
check_limit "Core dumps disabled" \
  'Max core file size[[:space:]]+0[[:space:]]+0[[:space:]]+bytes'

echo "PASS: all six expected kernel resource limits are visible in the sandbox."


echo
echo "=== explicitly selected writable output directory ==="
"$QSCTL" sandbox-run "$SH" --writable-dir "$OUT" -- -c 'printf "QS_WRITABLE_OUTPUT_OK\\n" > "$QS_WRITABLE_DIR/marker"' qs-test
[[ "$(cat "$OUT/marker")" == 'QS_WRITABLE_OUTPUT_OK' ]] || { echo "FAIL: selected writable output directory did not work." >&2; exit 1; }
echo "PASS: selected output directory is writable from inside the sandbox."

echo
echo "PASS: Bubblewrap mount, namespace and resource-limit smoke tests passed."

echo
echo "=== seccomp filter installed and enforced ==="
bash "$ROOT/scripts/test-seccomp-sandbox.sh"
echo "PASS: Software Shield syscall-filter integration test passed."
