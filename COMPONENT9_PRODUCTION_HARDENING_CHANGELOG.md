# Component 9 — Production-hardening candidate (v0.9.0)

- Added `serve-acme-http01`: HTTP-01 validation, challenge serving, HTTP-to-HTTPS 308 redirect, persistent `rustls-acme` account/certificate cache, and renewal through the continuously polled incoming TLS stream. Staging is default; production requires `--production` plus `--acknowledge-production-issuance`, plus explicit public-listener acknowledgement.
- Extended `deploy-compose` with `--acme-email`, `--acme-cache`, staging-by-default behavior, explicit production acknowledgement, persistent cache mount, host 80/443 bindings only after `--apply --acknowledge-public-listener`, and up to 120 seconds for initial certificate health polling.
- Added `tls-hot-reload` 0.4.0 for direct supplied-certificate `serve-https`. The watched resolver swaps valid pairs for new handshakes without terminating existing connections. Invalid key/cert replacement is not intended to replace the last valid cert.
- Added Docker `json-file` log rotation (`max-size: "10m"`, `max-file: "3"`) to both supplied-certificate and ACME Compose overlays.
- Replaced Docker-internal Cargo builds with a copy of the already-built `qsctl` into a small runtime image, addressing the prior observed crates.io DNS failure inside the Docker builder.
- Extended desktop wizard with an ACME option, contact email, staging default, explicit public TCP/80+443 acknowledgement, and a separate production-issuance acknowledgement.
- Added `scripts/test-cert-hot-reload.sh` for a loopback-only atomic certificate replacement test.
- Retained the restriction that stored-data and application-payload encryption are not implemented by the generic proxy. Unsupported platforms/protocols remain explicitly listed.

## Verification status

This packaging environment has no Rust toolchain, so v0.9.0 was not compiled here. The target SpiderOS machine must run the full format/test/Clippy/build gate, local certificate-reload test, and Docker Compose apply test. ACME production mode must not be used until staging issuance, cache persistence, renewal and failure recovery have been verified on a disposable domain. This component must not be described as independently audited or universally production ready until the release gates pass.
