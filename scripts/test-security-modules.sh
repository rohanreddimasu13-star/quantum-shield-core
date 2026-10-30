#!/usr/bin/env bash
# Local, non-network regression fixtures for repo-scan and app-audit.
set -Eeuo pipefail
fixture_aws_prefix='AKIA1234'
fixture_aws_suffix='567890ABCDEF'
fixture_aws_key="${fixture_aws_prefix}${fixture_aws_suffix}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QS="${QSCTL_BIN:-$ROOT/target/debug/qsctl}"
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for fixture JSON checks" >&2; exit 1; }
[ -x "$QS" ] || { echo "ERROR: build qsctl first: cargo build --bin qsctl" >&2; exit 1; }
TMP="$(mktemp -d /tmp/qs-security-test.XXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/repo" "$TMP/app"
# Build synthetic detections at runtime so the scanner does not report its own test fixture.
python3 - "$TMP/repo/leaked.txt" "$TMP/repo/client.py" <<'PYFIXTURE'
from pathlib import Path
import sys
Path(sys.argv[1]).write_text('AWS_ACCESS_KEY_ID = "' + "AKIA" + "1234567890ABCDEF" + '"\n')
Path(sys.argv[2]).write_text('requests.get(url, ' + 'verify=' + 'False' + ')\n')
PYFIXTURE
cat > "$TMP/app/Cargo.toml" <<'TOML'
[package]
name = "fixture-app"
version = "0.1.0"
edition = "2021"
TOML
cat > "$TMP/app/Dockerfile" <<'DOCKER'
FROM alpine:latest
CMD ["sh", "-c", "./server"]
DOCKER

"$QS" repo-scan "$TMP/repo" --json --output "$TMP/repository-report.json"
grep -q 'SECRET_AWS_ACCESS_KEY' "$TMP/repository-report.json"
grep -q 'TLS_VERIFICATION_DISABLED' "$TMP/repository-report.json"
if grep -q "${fixture_aws_key}" "$TMP/repository-report.json"; then
  echo "FAIL: report exposed the matched credential value" >&2
  exit 1
fi
echo "PASS: repository scanner detects fixture patterns without echoing the secret value."

"$QS" app-audit "$TMP/app" --json --output "$TMP/application-report.json"
grep -q 'APP_CARGO_LOCK_MISSING' "$TMP/application-report.json"
grep -q 'CONTAINER_FLOATING_IMAGE_TAG' "$TMP/application-report.json"
grep -q 'CONTAINER_NONROOT_USER_UNCONFIRMED' "$TMP/application-report.json"
echo "PASS: application audit detects a missing lockfile and insecure container defaults."

if "$QS" website-audit 'https://example.invalid/?token=must-not-be-accepted' >/dev/null 2>&1; then
  echo "FAIL: website audit unexpectedly accepted a query-string URL" >&2
  exit 1
fi
echo "PASS: website audit rejects query parameters before making a network request."
echo "PASS: security-module local regression fixtures completed."
