# Component 11 — Linux Software Shield baseline sandbox (RC2)

## Added

- Linux-only `qsctl sandbox-run` command backed by Bubblewrap.
- Separate user/PID/IPC/UTS namespaces and a network namespace by default.
- Explicitly drop all capabilities and remount the sandbox root read-only while preserving only the explicitly mounted writable output and bounded tmpfs mounts.
- Bind selected application/output paths before hiding host parent paths so app directories beneath `$HOME` are not broken by mount order.
- Read-only FHS system runtime and read-only sandbox root; host `/home`, `/root`, `/run`, `/sys`, `/var`, and `/tmp` hidden behind sandbox mounts.
- Minimal environment, temporary HOME/TMPDIR, and direct argv forwarding without shell interpretation.
- Executable-only mount by default; optional app directory is read-only and screened for common secret filenames, repository metadata, and escaping symlinks. Common credential files are masked with read-only `/dev/null` mounts rather than directory tmpfs mounts.
- Optional non-overlapping writable output directory, explicit network-sharing opt-in, refusal to run as root.
- Desktop panel for non-interactive CLI jobs, regression tests for builder and policy behavior, and a target-host integration smoke test.

## Boundaries

This is a baseline Bubblewrap policy, not a complete or universal application sandbox. GUI session/device integration, seccomp syscall allowlisting, CPU/memory/process quotas, extensive adversarial bypass testing, and app-specific profiles are not implemented. Bubblewrap maintainers emphasize that Bubblewrap is a toolkit rather than a ready-made security policy; Quantum Shield owns the correctness of the mount/namespace policy. See https://github.com/containers/bubblewrap/blob/main/README.md.

## Validation status

The packaging environment lacks Cargo/Rust, so this new source has not been compiled here. Run the full release gate on SpiderOS and `scripts/test-sandbox-run.sh` with Bubblewrap installed. Do not mark this feature production-ready until it passes tests on supported kernels and receives security review.
