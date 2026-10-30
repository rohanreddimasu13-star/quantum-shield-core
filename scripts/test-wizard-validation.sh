#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WIZARD="$ROOT/quantum-shield-first-run.sh"
FAIL=0

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; FAIL=$((FAIL + 1)); }
has() { grep -Fq -- "$2" "$1"; }

echo "========== QUANTUM SHIELD WIZARD VALIDATION =========="

if bash -n "$WIZARD"; then pass "Wizard shell syntax"; else fail "Wizard shell syntax"; fi

for fn in encryption_mode integration_mode integration_maintenance_mode website_mode repository_mode software_mode; do
  if grep -Eq "^${fn}\\(\\)[[:space:]]*\\{" "$WIZARD"; then
    pass "Workflow function: $fn"
  else
    fail "Missing workflow function: $fn"
  fi
done

for entry in \
  '1) integration_mode' \
  '2) encryption_mode' \
  '3) website_mode' \
  '4) repository_mode' \
  '5) software_mode' \
  '6) integration_maintenance_mode' \
  '7) exit 0'
do
  if has "$WIZARD" "$entry"; then
    pass "Menu route: $entry"
  else
    fail "Missing menu route: $entry"
  fi
done

for feature in \
  'encrypt-file' \
  'decrypt-file' \
  'key-list' \
  'website-audit' \
  'repo-scan' \
  'git-history-scan' \
  'app-audit' \
  'sandbox-run' \
  'integrate status' \
  'integrate remove'
do
  if has "$WIZARD" "$feature"; then
    pass "CLI workflow reference: $feature"
  else
    fail "Missing CLI workflow reference: $feature"
  fi
done

for safeguard in \
  'Too many ZIP entries' \
  'Duplicate path:' \
  'Encrypted ZIP entries are unsupported.' \
  'ZIP uncompressed size exceeds 512 MiB.' \
  'is_symlink' \
  'Refusing to overwrite existing output'
do
  if has "$WIZARD" "$safeguard"; then
    pass "Safety check: $safeguard"
  else
    fail "Missing safety check: $safeguard"
  fi
done

if has "$WIZARD" 'Share host networking? Type YES to opt in; otherwise isolate:' \
  && has "$WIZARD" '[[ "$share" == "YES" ]]' \
  && has "$WIZARD" '--share-network'; then
  pass "Network sharing requires explicit YES opt-in"
else
  fail "Network isolation/explicit opt-in control not verified"
fi

if has "$WIZARD" 'Project directory [$PWD]'; then
  pass "Integration directory default prompt"
else
  fail "Integration directory prompt missing"
fi

echo
if (( FAIL == 0 )); then
  echo "RESULT: ALL STATIC WIZARD CHECKS PASSED"
else
  echo "RESULT: $FAIL CHECK(S) FAILED"
  exit 1
fi
