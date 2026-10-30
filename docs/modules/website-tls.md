# Module 1 — Website and TLS

## Included capabilities

- Existing Rustls HTTPS/reverse-proxy code and Docker Compose TLS-edge adapter.
- Supplied certificate/key mode with private-key permission checks and direct-serving certificate hot reload.
- ACME HTTP-01 staging by default, persistent cache and renewal path; production issuance requires separate explicit acknowledgements.
- Passive `website-audit` using curl HEAD, normal TLS verification and HTTPS-only redirects; reports selected response headers, cookie flags, redirect status and HTTP status.
- Local regression scripts for supplied-cert TLS, certificate reload and loopback Compose apply.

## Operator commands

```sh
cargo run --bin qsctl -- website-audit https://your-domain.example
cargo run --bin qsctl -- website-audit https://your-domain.example --json --output website-report.json
./scripts/test-local-tls.sh
./scripts/test-cert-hot-reload.sh
./scripts/test-compose-local-apply.sh
```

## Deliberate boundaries

- Website audit is a single HEAD request, not authenticated DAST, crawl, WAF, exploit test, load test, or complete TLS cipher enumeration.
- Live deployment support remains limited to the documented Docker Compose shape and direct Rustls serving; it is not an adapter for every hosting provider or website builder.
- ACME staging on a real controlled domain, restart/cache/renewal and recovery tests remain mandatory.
