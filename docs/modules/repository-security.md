# Module 3 — Repository security

## Included capabilities

`repo-scan` statically scans a repository's current working tree using bounded file, byte, and directory-depth limits. It flags selected private-key/token/credential patterns, disabled TLS verification, common unsafe YAML/dynamic-evaluation patterns, selected container hardening issues, and GitHub Actions workflow permission omissions. It produces human-readable or JSON reports and supports a nonzero CI exit status on findings.

## Operator commands

```sh
cargo run --bin qsctl -- repo-scan /path/to/repository
cargo run --bin qsctl -- repo-scan /path/to/repository --json --output repository-report.json --fail-on-findings
```

## Deliberate boundaries

- Scans the current working tree only; it does not inspect Git history, remote secrets, compiled binaries, skipped dependency/build trees, or runtime behavior.
- Never executes code from the target repository and never changes target files.
- Secret values are not copied into reports; finding patterns can still produce false positives and miss obfuscated secrets.
- It is not a complete SAST/data-flow engine or independent security audit.
