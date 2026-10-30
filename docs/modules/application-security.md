# Module 2 — Application security

## Included capabilities

`app-audit` performs bounded, read-only checks on a local application source/deployment directory. It identifies common top-level Rust, Node.js, Go, Python and Java manifests; checks for selected missing dependency lockfiles; checks exact pins in Python `requirements.txt`; flags selected Django `DEBUG` and wildcard `ALLOWED_HOSTS` settings; and reuses repository security patterns.

## Operator commands

```sh
cargo run --bin qsctl -- app-audit /path/to/application
cargo run --bin qsctl -- app-audit /path/to/application --json --output app-report.json --fail-on-findings
```

## Deliberate boundaries

- Never starts or executes the target application; no runtime monitoring, authenticated testing, memory inspection, or arbitrary desktop-app agent is included.
- It does not replace language-specific dependency auditors or comprehensive SAST.
- Findings require review. Missing-file checks are stack heuristics and can produce false positives when a project intentionally uses another package manager/release policy.
- No automatic repair or file modification is performed.


## Runtime Software Shield (RC2 Linux CLI baseline)

`sandbox-run` is a separate enforcement path; `app-audit` still never executes target code.

```sh
cargo run --bin qsctl -- sandbox-run /usr/bin/printf -- 'sandbox check passed\n'
cargo run --bin qsctl -- sandbox-run /home/you/clean-app/tool \
  --app-dir /home/you/clean-app --writable-dir /home/you/SecurityReports/output -- --help
```

It requires Bubblewrap (`bwrap`) and unprivileged Linux user namespaces, refuses to run as UID 0, isolates the network by default, hides host home/runtime paths, mounts common system runtime paths read-only, clears inherited environment variables, mounts the executable/app directory read-only, and allows a separate writable directory only after explicit selection. Arguments are forwarded directly without a shell. `--share-network` opts into host networking.

Before mounting an app directory, it performs a bounded filename/symlink inspection and refuses common secret-bearing names or symlinks that escape that directory. This is defense in depth, not secret discovery: use a clean copy and do not mount a directory containing data the program must not read.

The current profile is for non-interactive CLI software, not GUI applications. It has no application-specific seccomp allowlist, resource quota, device/session pass-through, universal compatibility, or protection guarantee against kernel vulnerabilities or resource exhaustion. A successful launch proves the selected sandbox path ran, not that every malicious behavior is prevented. The target-host Bubblewrap smoke test is `scripts/test-sandbox-run.sh`.
