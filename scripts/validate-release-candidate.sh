#!/usr/bin/env bash
# Full release-candidate gate; public ACME staging on a controlled domain is a separate manual gate.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo fmt --all
cargo fmt --all -- --check
for script in scripts/test-early-response.sh scripts/test-local-tls.sh scripts/test-cert-hot-reload.sh scripts/test-compose-local-apply.sh scripts/test-security-modules.sh scripts/test-sandbox-run.sh; do
  bash -n "$script"
done
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --bin qsctl
cargo build --features desktop --bin qs-desktop
./scripts/test-security-modules.sh
if command -v bwrap >/dev/null 2>&1 && [[ "$(id -u)" != "0" ]]; then
  ./scripts/test-sandbox-run.sh
else
  echo "SKIP: live Bubblewrap sandbox test requires bwrap installed and the release gate running as an unprivileged user. Run scripts/test-sandbox-run.sh before treating the software sandbox as validated."
fi
./scripts/test-early-response.sh
./scripts/test-local-tls.sh
./scripts/test-cert-hot-reload.sh
./scripts/test-compose-local-apply.sh
if command -v cargo-audit >/dev/null 2>&1 || cargo audit --version >/dev/null 2>&1; then
  cargo audit
else
  echo "ERROR: cargo-audit is required for this release gate; install it with: cargo install cargo-audit --locked" >&2
  exit 2
fi

echo
echo "PASS: local release-candidate checks passed. Public ACME staging, restart/cache/renewal recovery, rollback failure injection, SBOM/signature and independent review are still required before general production use."
