#!/usr/bin/env bash
# Reproducible local release evidence collector. No production deployment.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/quantum-shield-evidence-$STAMP"
mkdir -p "$OUT"
chmod 700 "$OUT"
FAILURES=0
TOTAL=0
SUMMARY="$OUT/checks.tsv"
printf 'CHECK\tSTATUS\tEXIT_CODE\n' > "$SUMMARY"

run() {
    name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    printf '\n=== %s ===\n' "$name"
    if "$@" > "$OUT/$name.log" 2>&1; then
        printf '%s\tPASS\t0\n' "$name" >> "$SUMMARY"
        echo "PASS: $name"
        tail -n 5 "$OUT/$name.log"
    else
        rc=$?
        printf '%s\tFAIL\t%s\n' "$name" "$rc" >> "$SUMMARY"
        FAILURES=$((FAILURES + 1))
        echo "FAIL: $name (exit $rc)"
        tail -n 70 "$OUT/$name.log"
    fi
}

# Environment and source identity. Never dump environment variables or tokens.
{
    date -u --iso-8601=seconds
    uname -a
    rustc --version
    cargo --version
    printf '\nGit commit: '
    git rev-parse HEAD 2>/dev/null || printf 'NO_COMMIT\n'
    printf '\nGit status:\n'
    git status --short
    printf '\nDocker:\n'
    docker --version 2>&1 || true
    printf '\nBubblewrap:\n'
    bwrap --version 2>&1 || true
    printf '\nLicense marker:\n'
    grep -E 'PolyForm Noncommercial|MIT License|Apache License|Mozilla Public License' LICENSE 2>/dev/null | head -n 3 || true
    printf '\nSource checksums:\n'
    sha256sum Cargo.toml Cargo.lock src/main.rs src/protect.rs src/crypto.rs 2>&1 || true
} > "$OUT/environment.txt" 2>&1

run "git-diff-check-unstaged" git diff --check
run "git-diff-check-staged" git diff --cached --check
run "cargo-metadata-locked" cargo metadata --locked --no-deps --format-version 1
run "format-check" cargo fmt --all -- --check
run "all-tests-all-features" cargo test --all-targets --all-features
run "clippy-all-features" cargo clippy --all-targets --all-features -- -D warnings
run "build-cli-all-features" cargo build --all-features --bin qsctl
run "build-desktop" cargo build --features desktop --bin qs-desktop

# Check all shell scripts, including newly added local regressions.
run "bash-syntax-all-scripts" bash -c '
    set -e
    while IFS= read -r -d "" file; do
        echo "Checking $file"
        bash -n "$file"
    done < <(find scripts -type f -name "*.sh" -print0)
'

# Install the audit tool if absent; record the install separately.
if ! cargo audit --version >/dev/null 2>&1; then
    run "install-cargo-audit" cargo install cargo-audit --locked
fi
run "cargo-dependency-audit" cargo audit

# Existing regression suites.
for test_script in \
    scripts/test-security-modules.sh \
    scripts/test-sandbox-run.sh \
    scripts/test-early-response.sh \
    scripts/test-local-tls.sh \
    scripts/test-cert-hot-reload.sh \
    scripts/test-compose-local-apply.sh
do
    if [ -f "$test_script" ]; then
        run "$(basename "$test_script" .sh)" bash "$test_script"
    else
        TOTAL=$((TOTAL + 1))
        FAILURES=$((FAILURES + 1))
        printf '%s\tFAIL\t127\n' "$test_script" >> "$SUMMARY"
        echo "FAIL: missing required test script: $test_script"
    fi
done

# Real local encryption round trips and fail-closed tests in a disposable HOME.
encryption_e2e() (
    set -euo pipefail
    QS="$ROOT/target/debug/qsctl"
    T="$(mktemp -d -t qs-hackathon-crypto.XXXXXX)"
    trap 'rm -rf -- "$T"' EXIT
    mkdir -m 700 "$T/home"
    export HOME="$T/home"

    "$QS" key-generate evidence-key-v1
    python3 - "$T/input.bin" <<'PY'
from pathlib import Path
import sys
Path(sys.argv[1]).write_bytes(b"Quantum Shield proof\x00\xffbinary payload\n")
PY

    "$QS" encrypt-file --id evidence-key-v1 \
        --input "$T/input.bin" --output "$T/file.enc"
    "$QS" decrypt-file --id evidence-key-v1 \
        --input "$T/file.enc" --output "$T/file.dec"
    cmp "$T/input.bin" "$T/file.dec"
    test "$(stat -c '%a' "$T/file.enc")" = 600
    test "$(stat -c '%a' "$T/file.dec")" = 600
    echo "PASS: binary file round trip; output permissions are 600."

    "$QS" encrypt-payload --id evidence-key-v1 \
        --input "$T/input.bin" --output "$T/payload.enc" \
        --context "hackathon-evidence:v1"
    "$QS" decrypt-payload --id evidence-key-v1 \
        --input "$T/payload.enc" --output "$T/payload.dec" \
        --context "hackathon-evidence:v1"
    cmp "$T/input.bin" "$T/payload.dec"
    echo "PASS: context-bound payload round trip."

    if "$QS" decrypt-payload --id evidence-key-v1 \
        --input "$T/payload.enc" --output "$T/wrong-context.dec" \
        --context "wrong-context" > "$T/wrong-context.log" 2>&1; then
        echo "FAIL: wrong context was accepted."
        exit 1
    fi
    test ! -e "$T/wrong-context.dec"
    echo "PASS: wrong context rejected without producing plaintext."

    mkdir "$T/repo"
    git -C "$T/repo" init -q
    printf 'Quantum Shield repository fixture\n' > "$T/repo/README.md"
    "$QS" protect --kind repository --path "$T/repo" \
        --key-id evidence-key-v1 --output "$T/repository.qse"
    "$QS" decrypt-file --id evidence-key-v1 \
        --input "$T/repository.qse" --output "$T/repository.tar.gz"
    tar -tzf "$T/repository.tar.gz" | grep -q 'README.md'
    echo "PASS: repository snapshot encrypted and decrypted archive inspected."

    mkdir -p "$T/app/src"
    printf '[package]\nname = "qs-proof-app"\nversion = "0.1.0"\nedition = "2021"\n' > "$T/app/Cargo.toml"
    printf 'fn main() {}\n' > "$T/app/src/main.rs"
    "$QS" protect --kind application --path "$T/app" \
        --key-id evidence-key-v1 --output "$T/application.qse"
    "$QS" decrypt-file --id evidence-key-v1 \
        --input "$T/application.qse" --output "$T/application.tar.gz"
    tar -tzf "$T/application.tar.gz" | grep -q 'Cargo.toml'
    echo "PASS: application snapshot encrypted and decrypted archive inspected."

    "$QS" key-revoke --id evidence-key-v1
    if "$QS" encrypt-file --id evidence-key-v1 \
        --input "$T/input.bin" --output "$T/revoked.enc" > "$T/revoked.log" 2>&1; then
        echo "FAIL: revoked key encrypted new data."
        exit 1
    fi
    test ! -e "$T/revoked.enc"
    echo "PASS: revoked key cannot encrypt new data."
    "$QS" key-audit
)

run "encryption-and-protection-cli-e2e" encryption_e2e

# Simulations must run offline and report scope accurately.
run "os-protection-simulation" "$ROOT/target/debug/qsctl" protect --kind os --simulate
run "all-cloud-protection-simulation" "$ROOT/target/debug/qsctl" protect --kind cloud-server --simulate

# Check the provider-specific simulation actually filters output.
cloud_provider_e2e() {
    output="$("$ROOT/target/debug/qsctl" protect --kind cloud-server --provider aws --simulate)" || return 1
    printf '%s\n' "$output"
    printf '%s\n' "$output" | grep -q '\[AWS\]' || return 1
    if printf '%s\n' "$output" | grep -Eq '\[GCP\]|\[AZURE\]'; then
        echo "FAIL: AWS-only simulation included other providers."
        return 1
    fi
    echo "PASS: AWS-only simulation does not list other providers."
}
run "aws-only-simulation" cloud_provider_e2e
run "doctor-output" "$ROOT/target/debug/qsctl" doctor

{
    echo "# Quantum Shield validation evidence"
    echo
    echo "- Evidence timestamp: $STAMP (UTC)"
    echo "- Total checks: $TOTAL"
    echo "- Failed checks: $FAILURES"
    echo "- Result: $([ "$FAILURES" -eq 0 ] && echo PASS || echo FAIL)"
    echo
    echo "This evidence covers only commands listed in checks.tsv."
    echo "It is not an independent security audit and does not prove universal protection."
    echo "OS-disk and cloud operations shown in simulation mode are plans, not encryption."
    if grep -qi 'PolyForm Noncommercial' "$ROOT/LICENSE" 2>/dev/null; then
        echo
        echo "## Submission blocker to resolve"
        echo "The detected LICENSE contains PolyForm Noncommercial. Confirm the hackathon's open-source requirement and choose a compatible license only if you intend to grant those rights."
    fi
    echo
    echo "## Manual evidence still required"
    echo "- A real successful Nebius Token Factory runtime call using an NVIDIA open-source model, if not already implemented."
    echo "- Public repository URL, correct license, demo URL, public YouTube video under 3 minutes."
    echo "- Cloud tests require authorized accounts and are not performed here."
} > "$OUT/REPORT.md"

printf '\n=== FINAL SUMMARY ===\n'
cat "$SUMMARY"
echo
echo "Evidence directory: $OUT"
echo "Report: $OUT/REPORT.md"

ARCHIVE="$OUT.tar.gz"
if tar -czf "$ARCHIVE" -C "$(dirname "$OUT")" "$(basename "$OUT")"; then
    echo "Evidence archive: $ARCHIVE"
else
    echo "WARNING: failed to archive evidence directory."
    FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -eq 0 ]; then
    echo "ALL RECORDED ENGINEERING CHECKS PASSED."
else
    echo "$FAILURES CHECK(S) FAILED. Use the individual log files to fix the first concrete error, then rerun."
fi

# This exits only this script, not the user's interactive terminal.
[ "$FAILURES" -eq 0 ]
