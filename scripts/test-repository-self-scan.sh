#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
QSCTL="${QSCTL:-$ROOT/target/debug/qsctl}"
[[ -x "$QSCTL" ]] || { echo "ERROR: qsctl binary missing: $QSCTL" >&2; exit 2; }

STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$ROOT/artifacts/repository-self-scan-$STAMP"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

REPO_JSON="$OUTDIR/repository.json"
HISTORY_JSON="$OUTDIR/git-history.json"

# Static scan only; this never builds or executes the target repository's own code.
echo "=== Scanning the actual Quantum Shield working tree ==="
"$QSCTL" repo-scan "$ROOT" \
  --max-files 100000 \
  --max-file-bytes 10485760 \
  --json --output "$REPO_JSON"

python3 - "$REPO_JSON" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(f"Working-tree files scanned: {report.get('files_scanned', 0)}")
print(f"Findings: {len(report.get('findings', []))}")
print(f"Scan truncated: {report.get('scan_truncated', 'unknown')}")
if report.get('scan_truncated') is not False:
    print("ERROR: scan was truncated or did not explicitly report complete coverage.", file=sys.stderr)
    raise SystemExit(3)
if report.get('files_scanned', 0) <= 0:
    print("ERROR: scanner reported no files scanned.", file=sys.stderr)
    raise SystemExit(4)
for finding in report.get('findings', []):
    # The scanner should redact values; print only rule/severity/location/title fields.
    print("FINDING | {} | {} | {} | {}".format(
        finding.get('severity', 'unknown'),
        finding.get('rule_id', 'unknown'),
        finding.get('location', '(no location)'),
        finding.get('title', '(no title)')))
PY

echo
echo "=== Scanning recent Git history ==="
"$QSCTL" git-history-scan "$ROOT" --json --output "$HISTORY_JSON"
python3 - "$HISTORY_JSON" <<'PY'
import json, sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
status = report.get('status', 'unknown')
findings = report.get('findings', [])
print(f"Git-history scan status: {status}")
print(f"Findings: {len(findings)}")
for finding in findings:
    print("FINDING | {} | {}".format(
        finding.get('severity', 'unknown'), finding.get('rule_id', 'unknown')))
if status not in ('clean', 'findings'):
    print("ERROR: Git-history scan is not verified; status is not clean/findings.", file=sys.stderr)
    raise SystemExit(5)
PY

echo
echo "Reports:"
echo "  $REPO_JSON"
echo "  $HISTORY_JSON"
echo "PASS: actual working-tree and recent Git-history scans completed; review reported findings before release."
