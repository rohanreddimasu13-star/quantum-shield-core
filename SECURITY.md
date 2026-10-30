# Quantum Shield security policy and deployment boundaries (v1.0.0-rc.2)

## Release status

This is a **production-hardening candidate**, not an independently audited enterprise release. Verified local tests are evidence for those specific paths only. The first live deployment adapter supports exactly one configured site through Docker Compose on one project-managed private network. It does not support arbitrary website builders or all software stacks.

## Implemented protections

- Strict route config parsing, loopback/public-listener safeguards, and explicit acknowledgements for public ACME and production issuance.
- HTTP/1 reverse proxy with host routing, hop-by-hop header filtering, bounded connections/headers/body, idle/total request body deadlines, upstream timeouts, and a regression test for an upstream that replies early to an oversized chunked upload.
- Rustls TLS using an explicitly selected AWS-LC provider with post-quantum key-exchange preference, and server logging of the negotiated protocol/key exchange where available.
- Direct supplied-certificate mode validates the initial key/cert pairing and uses file watching to reload valid pairs for new TLS handshakes without forcibly restarting existing connections.
- ACME HTTP-01 mode defaults to Let's Encrypt staging; caches account/cert state persistently, handles HTTP-01 challenge requests, redirects other allowed HTTP requests to HTTPS, and drives renewal through the polled ACME incoming stream. Production issuance requires `--production`, `--acknowledge-production-issuance`, and the explicit public listener acknowledgement.
- Docker Compose overlays enforce `json-file` log rotation (`max-size: 10m`, `max-file: 3`), a non-root runtime UID/GID, read-only root filesystem, dropped capabilities, `no-new-privileges`, and read-only mounts for supplied cert/key files. ACME cache is a separate writable, persistent private mount.
- The Compose adapter does not modify the user's base Compose file. On start or health-check failure it attempts to remove only the generated proxy service; rollback failures must be treated as unresolved incidents.

## Not implemented or not guaranteed

- No storage-at-rest encryption of arbitrary databases, volumes, object storage or backups.
- No application payload encryption for arbitrary applications; this requires protocol/app changes and key management.
- No universal integration for every site builder/managed provider; no Caddy, NGINX, Apache or Kubernetes adapter yet.
- No WebSocket upgrade tunneling, HTTP/2, per-client rate limiting, WAF, bot protection, or distributed DDoS mitigation.
- No independent security audit, signed distributable pipeline or guarantee of no defects/zero downtime.
- Docker single-file certificate bind mounts may not see an atomic host-file replacement. The direct `serve-https` watcher and ACME in-process renewal modes have different lifecycle behavior; use the appropriate tested mode.

## Required safety rules

- Treat all configuration, request headers/bodies, paths, Compose models and environment values as untrusted.
- Never call a layer active merely because the user selected it in the GUI.
- Never advertise complete post-quantum security; hybrid TLS key exchange is not a guarantee that every client connection negotiated the hybrid group or that stored data/application logic is quantum-safe.
- Never expose a listener without an explicit operator acknowledgement; never run a supplied-cert or ACME mode with a placeholder domain.
- Keep the ACME cache persistent and access-restricted. Keep production and staging cache paths separate.
- Keep private keys out of source repositories, Docker build contexts, logs and generated public artifacts. Mount supplied keys read-only and require owner-only permissions on Unix.
- Keep the generated Compose overlay for later service operations; do not assume a successful `docker compose up` means health verification passed.
- Do not edit the base Compose file automatically. If an app service has published ports or uses host/shared/external/multiple networks, stop and explain the incompatibility rather than guessing.
- Retain and run the early-response upload regression script. Normal bodyless GET and oversized chunked upload cases must both pass.
- Keep `Cargo.lock` reviewed and committed in an actual release repository. Audit dependencies and generate an SBOM before release.

## Incident reporting

No public security contact is published yet. For a production release, add a private vulnerability-reporting channel, response expectations, supported-version policy and disclosure process before inviting public deployment.


## Three-module scanner boundaries (v1.0.0-rc.2)

- `website-audit` performs a single passive HEAD request with curl and standard TLS certificate verification. It does not exploit endpoints or enumerate every cipher. It refuses query strings and fragments to reduce secret leakage in process arguments and reports.
- `app-audit` reads source/manifests/config files only. It does not start applications, authenticate to endpoints, or run package manager install scripts.
- `repo-scan` works on bounded text files in the current working tree, skips known build/dependency directories and symlinks, and does not scan Git history. Matching tokens are never printed into reports.
- Static pattern scanners have false positives and false negatives; do not treat an empty report as a security guarantee.
- These modules do not implement arbitrary storage-at-rest encryption or application-payload encryption. TLS cipher suites secure transport only; they are not additional universal encryption layers for stored data.


## RC2 Software Shield sandbox scope

The Linux `sandbox-run` mode is a Bubblewrap-based baseline for non-interactive CLI applications. It defaults to a new network namespace, drops all capabilities, remounts the sandbox root read-only, keeps runtime mounts read-only, hides host home/runtime paths, clears the environment, and permits only an optional explicitly selected non-overlapping writable output directory. The mode refuses to run as root. `--share-network` weakens isolation and should be treated as an explicit trust decision; it refuses a host resolver path below `/run` because that profile deliberately hides `/run`.

This mode is not yet a complete security boundary for every threat: it lacks a tailored seccomp policy, CPU/memory/process quotas, GUI/session/device integration, and validated application-specific profiles. Bubblewrap is a sandbox-construction toolkit, and the command-line policy is Quantum Shield's responsibility. Do not use it as the sole control for highly hostile code until the exact build, host-kernel behavior, adversarial cases and independent review are complete.
