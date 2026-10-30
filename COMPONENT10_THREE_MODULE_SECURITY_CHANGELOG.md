# Component 10 — Three-module security candidate

## Added

- `website-audit`: passive HTTP/HTTPS response/header check via curl; follows HTTPS redirects only; relies on standard certificate verification; checks HSTS, CSP, clickjacking policy, nosniff, referrer/permissions headers, selected cookie attributes, response status and transport failure.
- `app-audit`: bounded read-only application source/config scan, top-level stack detection, dependency-lock presence checks, Python requirements pin checks, selected Django DEBUG/ALLOWED_HOSTS checks, and inherited repository rules.
- `repo-scan`: bounded read-only working-tree scan for private-key/known-token/credential-like patterns, disabled TLS validation, unsafe deserialization/evaluation patterns, selected container hardening issues, and GitHub Actions permission omissions.
- Human and JSON reports, caller-selected output path, optional CI exit failure on any finding, bounded file sizes/count/total bytes/depth, no symlink traversal, and tests asserting secret values aren't copied to reports.
- Desktop controls to launch all three module commands and view/save their reports.
- TLS handshake logs now include the negotiated TLS cipher suite and key-exchange group when available.
- `scripts/test-security-modules.sh` local regression fixtures and `scripts/validate-release-candidate.sh` consolidated release-candidate gate.

## Explicitly not claimed

This is not an independently audited production release. Website checking is passive HEAD-only, not authenticated DAST. Application/repository checks are pattern-based and incomplete, do not scan Git history or run code, and can produce false positives/negatives. There is no universal desktop-app runtime agent, general WAF, WebSocket/HTTP2 proxy, arbitrary storage-at-rest encryption adapter, or universal app-payload encryption adapter.

The integrated archive does not include a `Cargo.lock`; on the target host, run the gate to refresh it, inspect it, commit it, and only then freeze/sign release artifacts. The bundle was assembled in an environment without Cargo, so its integrated Rust build has not been executed here.
