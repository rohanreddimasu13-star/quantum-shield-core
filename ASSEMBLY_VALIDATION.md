# Assembly validation — Quantum Shield v1.0.0-rc.2

This note records checks actually run while assembling this archive. RC2 adds a Bubblewrap-based CLI sandbox profile and has not been Rust-compiled in the packaging environment.

## Passed in the packaging environment

- `Cargo.toml` parses as TOML; package version is `1.0.0-rc.2`.
- All shipped shell scripts pass `bash -n` syntax validation.
- The security-module regression script is present and references the generated `qsctl` binary under `target/debug`.
- The repository contains no `target/` build directory or developer-local backup directory.
- ZIP archives are checked after creation for CRC integrity and expected files.

## Not executed in the packaging environment

This environment has no `cargo`, `rustc`, or `rustfmt` executable. Therefore **the integrated v1.0.0-rc.2 Rust source, including the new sandbox, has not been compiled or tested here**. The user's prior v1.0.0-rc.1 checkout passed its local unit-test, Clippy/build, scanner-fixture, early-response, TLS, hot-reload and Compose tests; those results do not validate this newly integrated sandbox source.

The exact integrated source still needs, at minimum, the checks in `scripts/validate-release-candidate.sh` on the target host. Install Bubblewrap and run `scripts/test-sandbox-run.sh` as a normal, unprivileged user. Generate and review a `Cargo.lock` from the target toolchain and include it in the final release source before calling the build reproducible.

## Mandatory external release gates

- ACME staging issuance for a disposable domain the operator controls.
- Cache persistence after container restart; redirect, renewal, and recovery tests for bad DNS/upstream/cert conditions.
- Rollback failure-injection tests, including port conflicts and failed health checks.
- Fresh dependency audit, secret scan, SBOM, artifact checksum/signing and independent security review.
- Representative false-positive/false-negative evaluation for the static scanners.

This archive is a release candidate for review, **not a declaration of production readiness**.


## RC2 sandbox integration checks required on SpiderOS

- Install Bubblewrap and run `scripts/test-sandbox-run.sh` as the normal, unprivileged user.
- Confirm root invocation is refused and network isolation is active by default.
- Confirm host home is hidden, a mounted app directory cannot be modified, the unbound root is read-only, capabilities are dropped, and only the selected writable output directory is host-writable.
- Test app-directory secret-name and symlink-escape rejection.
- Evaluate representative CLI apps and verify incompatible apps fail clearly. GUI applications are not yet supported by this profile.
