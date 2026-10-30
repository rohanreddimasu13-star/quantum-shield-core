# Quantum Shield module map

All module ZIPs are full source trees with the same integrated CLI, GUI, shared reporting logic, build scripts, and tests. Each archive adds a `MODULE_SCOPE.md` that documents the selected module. They are not independently installed binaries and should be built/tested against one reviewed Cargo.lock before release.

- `website-tls.md`: TLS edge, Compose adapter, ACME lifecycle and passive website assessment.
- `application-security.md`: static application/deployment checks.
- `repository-security.md`: bounded working-tree secret/configuration pattern scanning.
