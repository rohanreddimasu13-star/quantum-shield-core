# Install Quantum Shield v1.0.0-rc.2 on SpiderOS side-by-side

This archive is a side-by-side release candidate. It does not modify or remove `~/Projects/quantum-shield-rust`.

## 1. Extract to a separate directory

```sh
mkdir -p ~/Projects/quantum-shield-rc2
unzip ~/Downloads/Quantum_Shield_Three_Module_Integrated_RC2.zip -d ~/Projects/quantum-shield-rc2
cd ~/Projects/quantum-shield-rc2/quantum-shield-rust-v1.0.0-rc2
```

If you extracted the archive somewhere else, adjust the `cd` path. Do not run this over the existing project directory.

## 2. Check the toolchain and compile

```sh
rustc --version
cargo --version
cargo fmt --all
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo build --bin qsctl
cargo build --features desktop --bin qs-desktop
```

The manifest requires Rust 1.92 or newer. This archive intentionally does not invent a `Cargo.lock`; the first Cargo command will resolve and create it. Review it, run the dependency audit, and commit it with the release source before treating the build as reproducible.

## 3. Run the local, read-only scanner fixtures

```sh
./scripts/test-security-modules.sh
```

Run the full local regression gate with Docker running:

```sh
./scripts/validate-release-candidate.sh
```

The full gate includes existing proxy/Compose tests and needs Docker Compose, curl, OpenSSL and `cargo-audit`. If a test fails, stop at the first failure and inspect it rather than proceeding to a public deployment.

## 4. Try the three modules

```sh
cargo run --bin qsctl -- website-audit https://your-domain.example
cargo run --bin qsctl -- app-audit /path/to/application --json --output app-report.json
cargo run --bin qsctl -- repo-scan /path/to/repository --json --output repository-report.json
```

The website command issues a passive HEAD request; it is not authenticated DAST. The application and repository commands are bounded read-only static scans; they do not execute targets or automatically apply fixes.

## 5. Do not use production ACME until staging passes

Use a disposable domain you control. First verify DNS A/AAAA, firewall/NAT and reachable TCP/80 and TCP/443; then apply ACME staging. Confirm challenge handling, redirect behavior, persistent cache across container restart, renewal and failure recovery. Only then consider production issuance, which creates real public certificate orders.


## Software Shield CLI sandbox (RC2)

Install Bubblewrap 0.8.0 or newer before using `sandbox-run`: `sudo xbps-install -S bubblewrap`, then check `bwrap --version`. Run Quantum Shield as your normal unprivileged user, not under `sudo`. Then run `./scripts/test-sandbox-run.sh`. For a minimal check, run `./target/debug/qsctl sandbox-run /usr/bin/printf -- 'sandbox check passed\n'`. Network is disabled by default; only pass `--share-network` when the program explicitly requires network and you accept that data may leave the sandbox.
