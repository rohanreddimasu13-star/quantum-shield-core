# Component 8 — Docker Compose TLS apply adapter (v0.8.0)

## Adds

- `qsctl deploy-compose` command with dry-run default and explicit `--apply --acknowledge-public-listener` required to publish host TCP/443.
- Docker Compose normalized-JSON inspection and refusal of ambiguous targets, upstream public port mappings, network mode, external networks and multiple networks.
- Existing PEM certificate/private key prevalidation, private-key permission and owner checks, and readable-file checks before creating the deployment context.
- Dedicated generated build context and Compose overlay; no edits to the original Compose file.
- Embedded project source/lockfile build into a Debian Bookworm runtime image using `cargo build --release --locked`.
- Container runs as the same unprivileged UID/GID as the operator; capabilities are dropped, root filesystem is read-only, key mount is read-only, and no-new-privileges is set.
- HTTPS health check validates certificate and hostname, accepts an application HTTP response in the 2xx–4xx range, and attempts proxy-only rollback on apply or health failure.
- Desktop wizard adds the Compose file, certificate/key and public-listener acknowledgement fields and runs deployment in a background thread. It reports that storage/payload encryption remain unapplied.
- New tests for overlay permissions and refusal of external/multi-network configurations.

## Explicit non-goals in this component

- This component does not provide universal one-click encryption for any website host.
- It does not apply storage/database/backup encryption or app-level payload encryption.
- It does not manage ACME production issuance, certificate renewal, HTTP-to-HTTPS redirect, WebSockets, HTTP/2, WAF, distributed DDoS protection or per-client rate limiting.
- It has not been compiled by the authoring environment because Rust/Cargo are unavailable there. The target machine must run all build gates and the adapter needs live Docker Compose integration testing before use on a real website.

## Rollback behavior

The base Compose file is not edited. The adapter removes only its unique generated proxy service when a health test fails. Generated overlay/build files are retained for inspection and future Compose operations. If rollback itself fails, the CLI surfaces the error and names the generated service for manual review.
