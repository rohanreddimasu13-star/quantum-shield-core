#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QSCTL="${QSCTL:-$ROOT/target/debug/qsctl}"
PROBE="$ROOT/target/debug/examples/seccomp_probe"

if [[ "$(id -u)" == "0" ]]; then
  echo "ERROR: run this test as the normal unprivileged user, not root." >&2
  exit 2
fi
command -v bwrap >/dev/null 2>&1 || {
  echo "ERROR: Bubblewrap is required." >&2
  exit 2
}
[[ -x "$QSCTL" ]] || { echo "ERROR: qsctl missing: $QSCTL" >&2; exit 2; }
if [[ ! -x "$PROBE" ]]; then
  echo "Building the seccomp probe..."
  cargo build --manifest-path "$ROOT/Cargo.toml" --bin qsctl --example seccomp_probe
fi
[[ -x "$PROBE" ]] || { echo "ERROR: seccomp probe was not built: $PROBE" >&2; exit 2; }

OUT="$(timeout --kill-after=3s 20s "$QSCTL" sandbox-run "$PROBE" 2>&1)" || {
  rc=$?
  printf '%s\n' "$OUT" >&2
  echo "FAIL: seccomp probe exited with status $rc" >&2
  exit "$rc"
}
printf '%s\n' "$OUT"
grep -Fq 'PASS: kernel reports Seccomp: 2' <<<"$OUT" || {
  echo "FAIL: the running sandbox process did not report seccomp filter mode." >&2
  exit 1
}
grep -Fq 'PASS: ptrace syscall denied with EPERM by seccomp policy.' <<<"$OUT" || {
  echo "FAIL: seccomp did not block PTRACE_TRACEME as expected." >&2
  exit 1
}
echo "PASS: Software Shield seccomp integration probe completed."
