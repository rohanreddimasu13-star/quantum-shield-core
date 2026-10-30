# Reversible project integration (RC2)

The integration manager is intentionally non-invasive. It detects a project and creates Quantum Shield-owned helpers under `.quantum-shield/`. It does not edit application source files, package manifests, startup commands, the original Docker Compose file, DNS, or hosting-provider settings.

## Commands

```sh
qsctl integrate detect .
qsctl integrate install .
qsctl integrate status .
qsctl integrate remove .
```

To override an inferred local HTTP upstream for a supported server project:

```sh
qsctl integrate install . --upstream http://127.0.0.1:3000
```

The manager refuses remote upstreams for the host-run preview. The existing deployment adapter separately supports a single-label Docker service name on the same private Compose network. It refuses to overwrite an existing unmanaged `.quantum-shield/` directory and does not overwrite an existing user Git pre-commit hook.

## What is installed

- `website-audit.sh URL` runs the existing passive website audit without changing remote hosting or routing.
- `repository-check.sh` runs the existing bounded repository scanner. If a repository has no pre-commit hook, install can add a report-first hook. Findings are report-only by default; set `QS_BLOCK_COMMIT_ON_FINDINGS=1` when invoking the check to request a failing exit status on findings.
- `software-shield.sh audit PATH` runs the existing application audit. `software-shield.sh run EXECUTABLE [ARGS...]` launches an explicitly selected Linux CLI executable using the existing `sandbox-run` command (an executable path without `run` is accepted for backwards compatibility). Bubblewrap and host kernel namespace support are required. This is not a universal GUI sandbox.
- `website.toml` and `website-shield.sh` are generated only when a local upstream can be reasonably inferred or explicitly supplied and the detected platform is not identified as managed/static. The gateway binds to `127.0.0.1:0`, letting the OS select the listening port at bind time. Read the `Listening on` line for the assigned URL.

## Important limits

The local gateway binds only to loopback and uses a generated `localhost` Host route. Its console reports the actual OS-assigned port; browse using `http://localhost:PORT/` to match the Host rule. It does not launch the original application, alter its original listener, or prevent clients from connecting directly to that original listener. It is a local reverse-proxy preview, not proof that a site is protected or an always-on service. Production enforcement requires traffic to be routed through Quantum Shield. The existing supported public deployment adapter is Docker Compose, subject to its explicit DNS, certificate and public-listener gates.

A Vercel-managed deployment cannot be changed by editing its local source tree. For externally hosted Vercel or GoDaddy sites, run `qsctl website-audit https://your-domain.example` for a passive assessment or use a platform-specific edge integration that is separately implemented and tested. GoDaddy may be only the registrar/DNS provider; this detector cannot infer where a remote site is hosted.

## Removal and drift

`qsctl integrate remove .` deletes only files it previously recorded and whose contents still match the generated version. It preserves edited helper files and edited Git hooks and retains the manifest when user-edited files remain. The manifest uses a stable non-cryptographic content hash for ordinary edit detection; it is not a tamper-proof attestation. Review `qsctl integrate status .` before removal.
