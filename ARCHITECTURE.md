# Quantum Shield architecture and release history

## Product boundary

Quantum Shield is a Rust-first local installer and HTTP/1 TLS edge. The UX may describe desired protection for a website or software/API, but the code marks a layer active only after a platform adapter actually implements and verifies it. The first apply adapter is Docker Compose; the system is not universal across all providers.

## Runtime components

- `qsctl`: strict CLI for config validation, HTTP/HTTPS proxy serving, ACME modes, planning and Compose deployment.
- `qs-desktop`: native eframe/egui wizard. It supports the Docker Compose TLS edge with either a supplied certificate/key or ACME HTTP-01. Staging is the default ACME choice; production requires a separate acknowledgement.
- `proxy.rs`: Hyper HTTP/1 proxy, body-pump limit/back-pressure, Rustls/Tokio-Rustls serving, ACME HTTP-01 challenge/redirect listener, certificate diagnostics and renewal event loop.
- `deploy.rs`: parses Docker Compose's normalized JSON model (not arbitrary YAML by hand), constrains topology, writes a separate overlay and private build context, copies an already-built `qsctl` binary into a minimal runtime image, applies only after explicit approval, performs HTTPS health checks, and attempts proxy-only rollback.
- `tls-hot-reload` 0.4.0: watched certificate/key resolver for direct supplied-cert HTTPS. Valid replacement key/cert pairs are swapped for new handshakes; active connections are not forcibly restarted. The watcher is filesystem-dependent; the Compose single-file bind-mount caveat remains documented.
- `rustls-acme` 0.15.4: HTTP-01 challenge response and certificate/account cache/renewal. The renewal state is progressed by continuously polling the incoming TLS stream.

## Certificate lifecycle

### Supplied certificate

Direct `serve-https` validates certificate/key material before listening and establishes the watched resolver. The Compose adapter mounts the certificate/key read-only. Because Docker single-file bind mounts may not follow a host atomic rename, a mounted-file replacement may require container recreation; verify the served certificate after any update.

### ACME HTTP-01

- Uses Let's Encrypt staging by default. Production is only selected by the explicit `--production --acknowledge-production-issuance` pair.
- Requires a real owned DNS name, valid contact email, public A/AAAA records and external HTTP/TLS reachability.
- HTTP port 80 serves `/.well-known/acme-challenge/*` from the ACME state and responds with a 308 HTTPS redirect for other requests matching a configured host.
- HTTPS uses the same ACME resolver for regular traffic. The incoming stream must continue to be polled; it drives first issuance and renewals.
- Account/certificate cache persists under a mode-0700 directory on Unix. Staging and production use separate default directories to avoid mixing CA state.
- Docker Compose maps host 80 to container 8080 and host 443 to container 18443; no host 80/443 binding is done unless `--apply --acknowledge-public-listener` is supplied.

## Docker Compose overlay

The base Compose file is never edited. The adapter supports exactly one site and one upstream service attached to one project-managed Compose network. It refuses upstream host port publishing, `network_mode`, external networks or multiple networks. It also requires the generated edge's port(s) to be free. The runtime image copies the already-built CLI (no Cargo dependency resolution inside Docker), pins Debian Trixie slim to the reviewed multi-platform OCI digest `sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` (2026-10-24 snapshot), runs with the invoking unprivileged UID/GID, uses a read-only root filesystem, drops capabilities, enables `no-new-privileges`, and mounts provided cert/key read-only. ACME cache is the only intentionally writable persistent data mount.

All generated proxy services use Docker `json-file` logging with `max-size: "10m"` and `max-file: "3"` to cap rotated container logs.

## Failure/rollback contract

1. Validate config/domain, cert/key or ACME settings, Compose topology and port conflicts.
2. Create a private build context and overlay. Validate the merged Compose model before applying.
3. Only start the proxy after explicit apply/public opt-in (or loopback-only `--local-test` for supplied certs).
4. Poll HTTPS health. For ACME staging, the local certificate trust is bypassed solely for this staging check; production health checks use normal certificate validation.
5. If creation or health check fails, remove only the generated proxy service. If rollback fails, print an actionable unresolved error; never claim success.
6. After success, print the exact rollback command and leave generated artifacts for inspection.

## Release gates

- `cargo fmt --all -- --check`
- `cargo test --all-targets --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --bin qsctl` and desktop build
- `scripts/test-early-response.sh`
- `scripts/test-cert-hot-reload.sh`
- `scripts/test-compose-local-apply.sh`
- ACME staging test with a real disposable domain, including cache persistence/restart and renewal verification
- Fault-injected rollback, invalid cert/key, upstream outage, port conflict, dependency audit, SBOM and independent security review

## External sources reviewed

- `https://github.com/FlorianUekermann/rustls-acme` (0.15.4): ACME stream polling, HTTP-01 challenge service, persistent account/cert cache.
- `https://github.com/sebadob/tls-hot-reload` (0.4.0): watched Rustls certificate resolver and atomic certificate/key reload for new TLS connections.
- `https://docs.docker.com/engine/logging/drivers/json-file/`: `max-size` plus `max-file` log rotation behavior.

The upstream projects are dependencies, not an audit of this application.


## v1.0.0-rc.1 three-module layer

The CLI adds three independent report-producing paths in `src/security.rs`: `website-audit` (passive HTTPS and response-header checks via curl), `app-audit` (bounded read-only manifest/configuration posture checks plus the shared source scan), and `repo-scan` (bounded read-only secret-pattern and unsafe-configuration checks). Reports are serializable JSON and human-readable; `--fail-on-findings` enables a strict CI exit code. Scanning does not execute target code or auto-remediate findings.

Website/TLS remains backed by the existing `proxy.rs` + `deploy.rs` implementation. Handshake logs now report the negotiated TLS cipher suite alongside key-exchange group. TLS cipher suite selection and key exchange are separate protocol dimensions; transport cipher suites do not imply storage or app-payload encryption.


## v1.0.0-rc.2 — Software Shield baseline CLI sandbox

The new Linux `sandbox-run` command is separate from static `app-audit`: it runs an operator-selected CLI executable via Bubblewrap, with user/PID/IPC/UTS namespaces, network namespace isolation by default, all capabilities dropped, read-only system runtime mounts and sandbox root, host home/runtime paths hidden, a cleared environment, bounded temporary mounts, a read-only executable/app directory, and an explicit non-overlapping writable output directory. Optional network sharing is deliberately conspicuous and refuses a resolver path below `/run` rather than expose host runtime sockets. The desktop UI surfaces the same non-interactive CLI workflow.

This policy is intentionally conservative and remains a baseline. It does not provide GUI session/device passthrough, syscall allowlisting, CPU/memory/process quotas, language-specific launch profiles or universal compatibility. Bubblewrap is a policy toolkit rather than a complete ready-made security policy; the exact runtime should be tested on every supported host.
