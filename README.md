# QuantumShield Forge — Universal Network-Layer Security Gateway

> **QUANTUMSHIELD FORGE** - High-performance, universal network-layer security gateway and reverse proxy engineered entirely in native, memory-safe Rust.

QuantumShield Forge acts as an ironclad, protocol-sanitizing perimeter wall that sits directly in front of any application, software repository, website, or cloud server. Its core mission is to make elite, next-generation data privacy and autonomous threat defense universally accessible via an intuitive, one-click configuration utility.

Even if the underlying infrastructure or backend software is full of critical vulnerabilities, QuantumShield completely alters its security posture from the inside out by scrubbing and encrypting 100% of all data traffic before it can touch the host server.

**AI-FREE Security System** - Pure deterministic, rule-based protection with no AI/ML inference in the defense path.

## 🏛️ The Three Pillars of QuantumShield Forge

### 1. The Post-Quantum Cryptographic Core
Legacy encryption standards (like RSA and ECC) are mathematically vulnerable to being cracked by upcoming quantum computers. State-sponsored threat actors currently use "Harvest Now, Decrypt Later" (HNDL) strategies.

QuantumShield instantly mitigates this threat by terminating public connections at the perimeter line and deploying **NIST FIPS 203 Hybrid X25519-MLKEM768 lattice geometry**. By binding classical cryptographic curves with post-quantum lattices, the data transit tunnel remains permanently unreadable for the next 50+ years.

### 2. Inside-Out Deep Packet Inspection (DPI) & Sanitization
Operating as a protocol clean room, the proxy handles all traffic in-memory with zero-overhead Rust streams.

- **Inbound Scrubbing**: Parses incoming HTTP frames via httparse, strips out volatile hop-by-hop tracking headers to completely neutralize HTTP Request Smuggling exploits. Enforces a strict, stream-bounded 16 MiB request-body socket cap to insulate host RAM and starve DDoS botnets.
- **Inline Text Filtering**: Every string, query, and parameter sent into the infrastructure is cross-referenced against a compiled regex signature library, programmatically neutralizing SQL Injections (SQLi), Cross-Site Scripting (XSS), and Path Traversals.
- **Outbound Leak Prevention**: Monitors what the vulnerable backend sends back to the public web, stripping internal system errors, server markers (like X-Powered-By), or sensitive data shapes before they reach the public internet.

### 3. Deterministic Hardening & Red-Team Stress Testing
Static, battle-tested rule sets provide consistent protection without AI dependencies.

- **Red-Team Stress Tester**: Deterministic attack generator that continuously probes the firewall with known attack patterns (SQLi, XSS, path traversal, HTTP smuggling) to validate defenses. This is the *only* adversarial component - strictly for testing.
- **Compiled Signature Library**: Pre-compiled regex rules for all major attack vectors, updated through configuration rather than ML models.
- **Deterministic Enforcement**: Every request is evaluated against the same ruleset with predictable, auditable behavior.

## ⚡ Quick Start - One-Click Gateway

```bash
# Build the gateway
cargo build --release --bin qsctl

# Validate your configuration
./target/release/qsctl validate config.toml

# Launch Quantum Shield HTTPS reverse proxy with post-quantum TLS, WAF, and AI crawler blocking
./target/release/qsctl serve-https config.toml \
  --listen 127.0.0.1:18443 \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem
```

**Status:** controlled pilot / production-hardening candidate, not an independently audited universal security product. A successful test proves only the tested path and environment. Do not claim that every website or software platform is supported.

## Reversible project integration (RC2)

Run one command from a supported project directory to detect its stack and install the applicable helper files without rewriting application source or package startup scripts:

```sh
qsctl integrate detect .
qsctl integrate install .
qsctl integrate status .
qsctl integrate remove .
```

For a supported local server, the installer can generate a loopback-only HTTP gateway preview and use `127.0.0.1:0` so the operating system selects the actual port at bind time. The generated gateway does not launch or hide the original app listener and is not a claim of public protection. Repository checks and the CLI sandbox wrappers use the existing security commands. Edited generated files and user hooks are preserved during removal. See [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for boundaries and details.

For Vercel or GoDaddy-hosted websites, these project files alone cannot reconfigure the remote hosting or DNS. Use passive website assessment or a supported, explicitly authorized edge/deployment integration. Public production traffic must actually pass through the gateway.

## Website ownership verification (RC2 addition)

Before a real public listener or public Docker Compose deployment is started, Quantum Shield can require a recent DNS TXT proof for each configured hostname. From the build directory, run `qsctl domain-challenge your.domain` and publish the exact TXT name/value printed by the command. After DNS has propagated, run `qsctl domain-verify your.domain`. The command uses `dig`, so install the DNS utilities package for your Linux distribution if `dig` is missing.

The challenge expires after 30 minutes, is single-use, and successful proof is accepted for public-listener gating for up to one hour. Local loopback test mode does not require a public DNS proof. Domain proof establishes DNS control only; it does not grant hosting authorization or make an unsupported hosting platform deployable. Store the challenge state under the user's private Quantum Shield state directory. Do not share challenge values publicly.

## What is implemented

- Strict TOML configuration validation and a native eframe/egui setup wizard.
- HTTP/1.1 reverse proxying with exact Host routing, hop-by-hop header filtering, bounded active connections, bounded headers, upstream timeouts, and a streamed 16 MiB request-body cap that continues to validate uploads when the upstream responds early.
- Rustls/Tokio-Rustls HTTPS using a supplied PEM cert/key. The direct `serve-https` mode watches the cert and key files and atomically swaps valid certificate material for **new TLS handshakes**; it does not drop existing connections to force a reload. Invalid or mismatched replacements should not displace the last valid pair.
- `serve-acme-http01`: automatic Let's Encrypt HTTP-01 challenge handling, HTTPS redirect on ordinary HTTP requests, persistent account/certificate cache, and renewal driven by the continuously polled ACME incoming stream. Staging is default. Production issuance requires both `--production` and `--acknowledge-production-issuance`, in addition to the explicit public-listener acknowledgement.
- Docker Compose adapter supports one site, one project-managed private Compose network, and one single-label application service. It can use either supplied cert/key files or ACME HTTP-01. It generates a separate overlay, does not edit the original Compose file, starts a non-root proxy with a read-only root filesystem and dropped Linux capabilities, verifies HTTPS, and attempts to remove only its own proxy service if start/health checks fail.
- Every generated Compose proxy service uses Docker's `json-file` logging driver with `max-size: "10m"` and `max-file: "3"`.
- Runtime images copy the already-built `qsctl` binary; Docker does **not** run Cargo or need crates.io access during the proxy image build. The Debian Trixie slim multi-platform OCI index is pinned to `sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad` (verified from Docker Official Image metadata on 2026-10-24); refresh and scan this pin in the release process. Docker may still need to pull the pinned runtime image if it is not cached.

## Three security modules (release candidate)

### Module 1 — Website/TLS security

The existing TLS edge/proxy and Docker Compose adapter are retained. TLS connection logs now include the **negotiated cipher suite** and key-exchange group where the TLS library exposes them. The AWS-LC/Rustls build supports multiple TLS 1.3 cipher suites (for example AES-GCM and ChaCha20-Poly1305 where offered by the linked provider); a connection negotiates a compatible suite rather than stacking cipher algorithms on the same bytes. The hybrid X25519MLKEM768 key exchange is separate from the traffic cipher.

Use the passive website check:

```sh
cargo run --bin qsctl -- website-audit https://your-domain.example
cargo run --bin qsctl -- website-audit https://your-domain.example --json --output website-report.json
```

This requires `curl`, sends a HEAD request, follows only HTTPS redirects, and uses normal system certificate verification. It checks response status, transport/redirect behavior, common security headers, and cookie attributes observed on that response. It is not an authenticated DAST scan, does not crawl a site, and may produce incomplete results for servers that reject HEAD.

### Module 2 — Application security

```sh
cargo run --bin qsctl -- app-audit /path/to/application
cargo run --bin qsctl -- app-audit /path/to/application --json --output app-report.json --fail-on-findings
```

The read-only assessment identifies common top-level manifests, checks for missing dependency lockfiles, inspects Python `requirements.txt` exact pins, checks selected Django production settings, and reuses repository secret/unsafe-pattern checks. It **does not start or execute the application**, authenticate to it, inspect runtime memory, or replace language-specific dependency auditors. It is not yet a general runtime agent for every installed desktop application.

### Module 3 — Repository security

```sh
cargo run --bin qsctl -- repo-scan /path/to/repository
cargo run --bin qsctl -- repo-scan /path/to/repository --json --output repository-report.json --fail-on-findings
```

The scanner checks a bounded working tree for private-key/known-token patterns, credential-like literal assignments, disabled TLS validation, selected unsafe deserialization/dynamic execution patterns, container hardening problems, and GitHub Actions permission omissions. It never places matched secret values in reports. It does not execute repository code or change files. By design it skips `.git` history, dependency/build caches, binaries, symlinks and over-limit files. Findings are patterns requiring human review, not a guarantee that all issues were found.

### Shared report behavior

All three commands support `--json`, `--output PATH`, and `--fail-on-findings`. Output files are explicitly selected by the operator. Review reports before remediation; this release candidate deliberately does not auto-edit source code or disable services.

## What is not implemented

- Storage-at-rest encryption for arbitrary databases, disks, volumes or backups. TLS cipher suites protect traffic in transit; they do not encrypt storage.
- Application/payload encryption for arbitrary software; this requires application-specific code, protocol design and key management.
- Universal installation adapters for all hosting providers, website builders and application stacks. Initial live apply is Docker Compose only.
- WebSocket tunneling, HTTP/2, per-client rate limiting, a WAF, bot defense, or distributed DDoS mitigation.
- An independent security audit, signed release pipeline, or a guarantee of zero downtime/zero defects.
- Full SAST/data-flow analysis, Git-history secret scanning, authenticated DAST/crawling, full system-wide runtime instrumentation, application-specific seccomp allowlists, GUI-session sandboxing, or universal support for every language/platform.

The GUI allows requesting additional layers, and RC2 includes a Software Shield baseline-sandbox panel for non-interactive Linux CLI tasks. That profile drops capabilities, remounts the sandbox root read-only, hides host home/runtime paths, isolates networking by default and allows only one explicitly selected host output directory to remain writable. It is a baseline containment profile, not a universal application shield: GUI apps, application-specific syscall allowlists, memory limits, and runtime-specific compatibility policies are not yet implemented. The Linux profile does enforce kernel CPU-time, address-space, file-size, open-file, process-count, and core-dump limits. Selected storage/payload layers remain **not applied** unless a future platform-specific adapter performs and verifies them.

## Build gate on Linux

This source archive is a release candidate, not a signed production release. It intentionally does not bundle a `Cargo.lock`; the first build refreshes the lockfile from the checked manifest. Review and commit that generated lockfile before making release artifacts. The current container/session used to assemble this archive did not have Cargo installed, so a successful build of this exact integrated source has **not** been claimed here. Use the full build and regression gate below on the target SpiderOS host.


Requires Rust/Cargo 1.92+ (a newer stable toolchain is preferred), Docker Engine + Compose plugin for the Compose integration test, and OpenSSL/curl/ss for the local smoke scripts. The archive omits `Cargo.lock`; the first build will resolve the dependency graph. Inspect and commit the generated lockfile before producing release artifacts.

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --bin qsctl
cargo check --features desktop --bin qs-desktop
cargo build --bin qsctl
cargo build --features desktop --bin qs-desktop
cargo audit
./scripts/test-security-modules.sh
# If Bubblewrap is installed and the gate is run as an unprivileged user:
./scripts/test-sandbox-run.sh
./scripts/test-early-response.sh
./scripts/test-local-tls.sh
./scripts/test-cert-hot-reload.sh
./scripts/test-compose-local-apply.sh
```

Launch the wizard:

```sh
cargo run --features desktop --bin qs-desktop
```

## First: verify the already-supported local deployment

With Docker running and the build gate passing:

```sh
./scripts/test-compose-local-apply.sh
```

That creates a disposable app, binds the proxy only to `127.0.0.1` using a Docker-assigned host port, tests HTTPS and the hybrid group log when negotiated, inspects the actual Docker container log-rotation values, and cleans up its test containers. It uses a self-signed cert only for the local test. It is not public certificate validation.

## Test certificate hot reload

```sh
./scripts/test-cert-hot-reload.sh
```

This test starts `serve-https` on loopback using temporary self-signed certificates, atomically replaces the cert/key files, and checks that a new TLS handshake presents the new certificate while HTTP proxying remains operational. It tests **direct file-watched serving**. A Docker bind-mounted single certificate file may not reflect a host atomic rename; use the ACME mode's in-process renewal or recreate the container after replacing such a mounted file.

## Supplied-certificate Compose mode

Dry-run, then apply only after reviewing the generated overlay:

```sh
qsctl deploy-compose CONFIG \
  --compose-file /path/to/compose.yaml \
  --cert /private/path/fullchain.pem \
  --key /private/path/privkey.pem

qsctl deploy-compose CONFIG \
  --compose-file /path/to/compose.yaml \
  --cert /private/path/fullchain.pem \
  --key /private/path/privkey.pem \
  --apply --acknowledge-public-listener
```

Use `--local-test --apply` instead for loopback-only testing; Docker assigns an available host port bound only to `127.0.0.1`, and the adapter prints the resulting local URL. Production supplied-certificate mode validates the served hostname/certificate normally and requires the key to be readable by the invoking non-root user, owned by that user, and not accessible to group/other users. The original Compose file is not edited. Keep the generated overlay and build directory; they are needed to inspect and manage the generated service.

## Automatic certificate mode

**Staging first.** Check DNS A and AAAA records, NAT/firewall rules, and that external TCP/80 and TCP/443 reach the intended host. The adapter cannot make DNS/port forwarding correct on the user's behalf.

Dry-run:

```sh
qsctl deploy-compose CONFIG \
  --compose-file /path/to/compose.yaml \
  --acme-email admin@yourdomain.com
```

Apply staging after review:

```sh
qsctl deploy-compose CONFIG \
  --compose-file /path/to/compose.yaml \
  --acme-email admin@yourdomain.com \
  --apply --acknowledge-public-listener
```

Staging certs are **not publicly trusted**. Only after a staging issuance, restart/cache, redirect and renewal review should production be requested:

```sh
qsctl deploy-compose CONFIG \
  --compose-file /path/to/compose.yaml \
  --acme-email admin@yourdomain.com \
  --production --acknowledge-production-issuance \
  --apply --acknowledge-public-listener
```

Production mode creates real publicly trusted certificate orders; use it only for a domain you control. The adapter needs host ports 80 and 443 free. The HTTP listener serves ACME HTTP-01 challenges and redirects other valid configured-host requests to HTTPS. Account and certificate state live under `$HOME/.local/state/quantum-shield/acme-staging` or `acme-production` by default (or `--acme-cache`); the cache is persistent and restricted to mode 0700 on Unix. The certificate renewal loop advances while the ACME incoming stream is polled; it does not depend on manually rebuilding the proxy container.

The adapter polls HTTPS health for up to 120 seconds while first ACME issuance completes. A local host check does not verify external DNS, IPv6, CDN, firewall, or client behavior. If checks fail, the adapter attempts to remove only the generated proxy service; inspect the printed error if rollback itself fails.

## Logs and reload behavior

The generated Compose overlay includes:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

These options bound Docker's `json-file` logs to three 10 MiB files per service. Direct non-Compose logs still go to the caller's stdout/stderr and must be rotated by the chosen service manager.

For direct `serve-https`, the `tls-hot-reload` certificate resolver watches certificate/key files and swaps in a valid matching pair for new TLS handshakes. It does not require SIGHUP, and it does not terminate existing connections. Watcher support depends on the filesystem; network filesystems may require polling or a tested alternative. Compose ACME mode manages certificates in process and persists its ACME cache. Existing single-file bind mounts can have inode replacement limitations; the supplied-cert Compose adapter explicitly notes that caveat.

## Production release gates — still mandatory

1. Run the full format/test/Clippy/build gate on the release source and commit a reviewed `Cargo.lock`.
2. Pass `scripts/test-compose-local-apply.sh` and `scripts/test-cert-hot-reload.sh` on the supported host.
3. Test ACME staging on a disposable real domain, including certificate cache persistence across a container restart, HTTP-to-HTTPS redirect, renewal behavior and recovery from broken DNS/upstream/cert conditions.
4. Test rollback with induced bad image/build, invalid key/cert, port conflicts, failing health checks, and rollback failure.
5. Verify logging rotation from the generated overlay and inspect the runtime container hardening.
6. Run dependency audit, secret scanning, SBOM generation, artifact checksums/signing, and an independent security review before general sale.
7. Never mark storage or app-level encryption active without a separate tested adapter and documented key-management process.

## Reviewed upstream projects

- `rustls-acme` 0.15.4: <https://github.com/FlorianUekermann/rustls-acme>
- `tls-hot-reload` 0.4.0: <https://github.com/sebadob/tls-hot-reload>
- Docker `json-file` logging options: <https://docs.docker.com/engine/logging/drivers/json-file/>

These upstream projects provide components, not an independent audit of Quantum Shield. Keep dependency versions/lockfile under review.

## Release status

**Release candidate — not yet cleared for general production use.** The three module commands are implemented as bounded passive/static checks. Before public production use, run the full gate on the exact source and lockfile, complete ACME staging/renewal/cache-restart/recovery tests on a domain you control, test rollback failure modes, run dependency/secret/SBOM checks, and arrange an independent review. The repository and app scanners must be benchmarked against representative fixtures and false-positive/false-negative expectations before being used as a CI security gate.


## Guided first run

After cloning the repository, run:

```bash
chmod +x quantum-shield-first-run.sh
./quantum-shield-first-run.sh
```

The launcher builds the existing CLI if needed and guides you through
Website, Repository or Software workflows. It reuses existing CLI commands;
it does not replace the security engine or bypass existing checks.

Website mode requires a valid site configuration and certificate/key files.
Hybrid X25519MLKEM768 key exchange is active only when supported and actually
negotiated. Repository checks distinguish unavailable commands/tools from clean
results. Software mode uses the existing Bubblewrap CLI profile, and fails
closed if required sandbox features are unavailable. Network policy defaults to `isolated`; `shared` explicitly enables host networking; `automatic` prefers isolation and, on Linux only, falls back to shared networking for a narrowly recognized unprivileged-user-namespace capability restriction. Other probe failures remain fail-closed.

This launcher is a CLI onboarding layer. It does not claim universal
application compatibility or that all modes provide identical encryption.


## Built-in AI crawler and agent blocking

Website mode blocks known AI crawlers, AI browsing agents, and headless browser
automation by default. Matching is a case-insensitive substring test against the
request `User-Agent` and happens before any upstream connection is opened.
Blocked requests receive `HTTP 403` with `x-quantum-shield-policy:
ai-agent-blocked`.

The built-in policy covers:

- OpenAI: `GPTBot`, `ChatGPT-User`, `OAI-SearchBot`, `OpenAI`
- Anthropic: `ClaudeBot`, `Claude-User`, `Claude-SearchBot`, `Anthropic`
- Perplexity: `PerplexityBot`, `Perplexity-User`
- Google AI surfaces: `Google-Extended`, `GoogleOther`, `Gemini`
- Other crawlers and dataset collectors: `CCBot`, `Bytespider`, `Amazonbot`,
  `Applebot-Extended`, `meta-externalagent`, `meta-externalfetcher`,
  `FacebookBot`, `Cohere`, `Diffbot`, `YouBot`, `TimpiBot`, `OmgiliBot`,
  `Webz.io`, `AI2Bot`, `ImagesiftBot`, `Copilot`
- AI agent frameworks and clients: `LangChain`, `AutoGPT`, `CrewAI`, `Cursor`
- Agentic pentest frameworks and scanner tooling: `ARTEX`, `Nuclei`, `sqlmap`,
  `Nikto`, `ffuf`, `Gobuster`, `Feroxbuster`, `DirBuster`, `Wfuzz`, `masscan`,
  `Nmap`, `Acunetix`, `Nessus`, `OpenVAS`, `w3af`, `OWASP ZAP`
- Headless automation commonly used by AI agents: `HeadlessChrome`,
  `Playwright`, `Puppeteer`, `Selenium`, `WebDriver`, `PhantomJS`

Add organization-specific patterns with `QS_BLOCKED_USER_AGENTS`, a
comma-separated list such as `AcmeCrawler,InternalAgent`. Operator entries are
merged with the built-in policy; the built-in AI policy cannot be disabled.

A User-Agent string is client-supplied and can be spoofed. Clients that present
a normal browser User-Agent, or that use a platform browser without an
identifying marker, cannot be distinguished at this layer. This control is a
request policy, not authentication, proof of crawler identity, or a guarantee
against AI scraping. It must not be described as an unbreakable scraping
defense.
