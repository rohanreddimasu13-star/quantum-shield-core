# Dependency review snapshot — 2026-10-24

| Dependency | Pin / range in Cargo.toml | Why used | Upstream source reviewed |
|---|---|---|---|
| `rustls` | 0.23.46-compatible with `prefer-post-quantum`, `aws_lc_rs` | TLS provider and handshake | https://github.com/rustls/rustls |
| `tokio-rustls` | 0.26.6 | Tokio TLS transport | https://github.com/rustls/tokio-rustls |
| `rustls-acme` | exact 0.15.4, `tokio`, `aws-lc-rs`, `tower` | ACME HTTP-01, account/cert cache and renewal state | https://github.com/FlorianUekermann/rustls-acme |
| `tls-hot-reload` | exact 0.4.0, `aws_lc_rs` | Filesystem watch + reloadable Rustls certificate resolver | https://github.com/sebadob/tls-hot-reload |
| Hyper / hyper-util | 1.x / 0.1.x semver ranges | HTTP/1 server and proxy client | https://github.com/hyperium/hyper |
| eframe / egui | exact 0.34.3 | Native desktop wizard; uses skrifa/vello_cpu font stack instead of ab_glyph/ttf-parser | https://github.com/emilk/egui |

## Findings and constraints

- Upstream `rustls-acme` documents that account and certificate caching are important for production rate limits, and its incoming ACME stream must be polled continuously to drive certificate issuance/renewal. ACME staging is used for tests because its certificates are not browser-trusted.
- Upstream `tls-hot-reload` provides `CertifiedKeyWatched`, which watches files and their parent directories and swaps the resolver for subsequent handshakes when a matching key/certificate pair can be loaded. This is not a guarantee that every filesystem supplies reliable native watch events; validate the actual deployment filesystem.
- Docker's `json-file` driver supports rotation with `max-size` and `max-file`; both are set in generated Compose overlays. Rotation does not manage direct host stdout/stderr logs outside Docker.
- The user-reported 2026-10-24 GUI dependency migration run found `ttf-parser` absent and showed `cargo audit` scanning 443 dependency packages without advisory output. This bundled source archive omits Cargo.lock, so the exact release-candidate dependency graph must be regenerated and re-audited on the target host. No independent source security audit, SBOM, or signed release is claimed by this document.

The runtime base image is pinned to the official Debian Trixie slim multi-platform OCI index digest recorded below. Re-validate the digest and scan the image during each release cycle. Before an actual v1.0 release: review and commit `Cargo.lock`, run `cargo audit`, generate an SBOM, scan for secrets, sign release artifacts, and complete an independent security review. None of those gates should be marked complete until CI/release evidence exists.
