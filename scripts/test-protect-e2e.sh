#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QS="$ROOT/target/debug/qsctl"
T="$(mktemp -d -t qs-protect-e2e.XXXXXX)"
trap 'rm -rf -- "$T"' EXIT

mkdir -m 700 "$T/home"
export HOME="$T/home"
KEY_ID="evidence-key-v1"

echo "=== Generate isolated test key ==="
"$QS" key-generate --id "$KEY_ID"
test -s "$HOME/.local/state/quantum-shield/keys/$KEY_ID.key"

echo "=== Create binary test fixture ==="
python3 - "$T/input.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"Quantum Shield proof\x00\xffbinary payload\n")
PY

echo "=== File encryption and decryption ==="
"$QS" encrypt-file --key-id "$KEY_ID" \
  --input "$T/input.bin" --output "$T/file.enc"
"$QS" decrypt-file --key-id "$KEY_ID" \
  --input "$T/file.enc" --output "$T/file.dec"
cmp "$T/input.bin" "$T/file.dec"
test "$(stat -c '%a' "$T/file.enc")" = 600
test "$(stat -c '%a' "$T/file.dec")" = 600
echo "PASS: binary file round trip and restrictive permissions."

echo "=== Context-bound payload round trip ==="
"$QS" encrypt-payload --key-id "$KEY_ID" \
  --input "$T/input.bin" --output "$T/payload.enc" \
  --context "hackathon-evidence:v1"
"$QS" decrypt-payload --key-id "$KEY_ID" \
  --input "$T/payload.enc" --output "$T/payload.dec" \
  --context "hackathon-evidence:v1"
cmp "$T/input.bin" "$T/payload.dec"
echo "PASS: payload round trip."

echo "=== Wrong-context rejection ==="
if "$QS" decrypt-payload --key-id "$KEY_ID" \
  --input "$T/payload.enc" --output "$T/wrong.dec" \
  --context "wrong-context" >"$T/wrong.log" 2>&1; then
    echo "FAIL: wrong context was accepted."
    exit 1
fi
test ! -e "$T/wrong.dec"
grep -qi "authentication failed" "$T/wrong.log"
echo "PASS: wrong context rejected; no plaintext output."

echo "=== Repository snapshot ==="
mkdir "$T/repo"
git -C "$T/repo" init -q
printf 'Quantum Shield repository fixture\n' > "$T/repo/README.md"

"$QS" protect --kind repository --path "$T/repo" \
  --key-id "$KEY_ID" --output "$T/repository.qse"
test -s "$T/repository.qse"

"$QS" decrypt-file --key-id "$KEY_ID" \
  --input "$T/repository.qse" --output "$T/repository.tar.gz"
tar -tzf "$T/repository.tar.gz" > "$T/repo-files.txt"
grep -q 'README.md' "$T/repo-files.txt"
echo "PASS: repository archive decrypts and lists README.md."

echo "=== Application snapshot ==="
mkdir -p "$T/app/src"
printf '[package]\nname = "qs-proof-app"\nversion = "0.1.0"\nedition = "2021"\n' > "$T/app/Cargo.toml"
printf 'fn main() {}\n' > "$T/app/src/main.rs"

"$QS" protect --kind application --path "$T/app" \
  --key-id "$KEY_ID" --output "$T/application.qse"
test -s "$T/application.qse"

"$QS" decrypt-file --key-id "$KEY_ID" \
  --input "$T/application.qse" --output "$T/application.tar.gz"
tar -tzf "$T/application.tar.gz" > "$T/app-files.txt"
grep -q 'Cargo.toml' "$T/app-files.txt"
grep -q 'src/main.rs' "$T/app-files.txt"
echo "PASS: application archive decrypts and lists its manifest and code."

echo "=== Revocation rejection ==="
"$QS" key-revoke --id "$KEY_ID"
if "$QS" encrypt-file --key-id "$KEY_ID" \
  --input "$T/input.bin" --output "$T/revoked.enc" \
  >"$T/revoked.log" 2>&1; then
    echo "FAIL: revoked key encrypted new data."
    exit 1
fi
grep -qi "revoked for new encryption" "$T/revoked.log"
test ! -e "$T/revoked.enc"
echo "PASS: revoked key rejected for the expected reason."

echo
echo "ALL ENCRYPTION AND BUNDLE CHECKS PASSED."
