//! Linux command-line software sandbox backed by Bubblewrap.
//!
//! This is a conservative baseline, not a universal application sandbox: GUI session
//! passthrough, strict per-application syscall allowlists and language/runtime-specific profiles
//! remain separate work. A conservative seccomp denylist is applied; network access is denied by default.

use crate::sandbox_policy::{SandboxNetworkMode, SandboxNetworkReport};
use anyhow::{bail, Context, Result};
use std::env;
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const SANDBOX_ROOT: &str = "/qs";
const SANDBOX_APP: &str = "/qs/app";
const SANDBOX_WRITABLE: &str = "/qs/writable";
const SANDBOX_HOME: &str = "/qs/home";
const SANDBOX_PRLIMIT: &str = "/usr/sbin/prlimit";
const MAX_APP_DIR_ENTRIES: usize = 20_000;
const MAX_APP_DIR_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SandboxLimits {
    cpu_seconds: u64,
    memory_mb: u64,
    file_mb: u64,
    nofile: u64,
    nproc: u64,
}

fn limits_for_profile(profile: &str) -> Result<SandboxLimits> {
    match profile {
        "strict" => Ok(SandboxLimits {
            cpu_seconds: 30,
            memory_mb: 256,
            file_mb: 128,
            nofile: 512,
            nproc: 64,
        }),
        "balanced" => Ok(SandboxLimits {
            cpu_seconds: 60,
            memory_mb: 512,
            file_mb: 256,
            nofile: 1024,
            nproc: 256,
        }),
        "developer" => Ok(SandboxLimits {
            cpu_seconds: 300,
            memory_mb: 2048,
            file_mb: 1024,
            nofile: 2048,
            nproc: 512,
        }),
        other => bail!("unknown sandbox profile '{other}'; choose strict, balanced, or developer"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkNamespaceProbe {
    Supported,
    CapabilityUnavailable(String),
    Failed(String),
}

/// Only this specific Bubblewrap diagnostic is treated as a capability limitation.
/// A generic EPERM / "Operation not permitted" is deliberately NOT sufficient.
fn classify_network_namespace_probe(success: bool, stderr: &str) -> NetworkNamespaceProbe {
    if success {
        return NetworkNamespaceProbe::Supported;
    }

    let diagnostic = stderr.trim();
    let lower = diagnostic.to_ascii_lowercase();

    if lower.contains("no permissions to create a new namespace")
        && lower.contains("non-privileged user namespaces")
    {
        return NetworkNamespaceProbe::CapabilityUnavailable(diagnostic.to_owned());
    }

    NetworkNamespaceProbe::Failed(if diagnostic.is_empty() {
        "Bubblewrap network namespace probe failed without a diagnostic".to_owned()
    } else {
        diagnostic.to_owned()
    })
}

fn probe_network_namespace() -> Result<NetworkNamespaceProbe> {
    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

    let mut child = Command::new("bwrap")
        .args(["--unshare-net", "--new-session"])
        .args(
            ["/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64"]
                .iter()
                .filter(|root| Path::new(root).exists())
                .flat_map(|root| ["--ro-bind", *root, *root]),
        )
        .args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            "/",
            "--",
            "/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not execute Bubblewrap network namespace capability probe")?;

    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .context("failed waiting for Bubblewrap capability probe")?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .context("failed collecting Bubblewrap capability probe output")?;
            return Ok(classify_network_namespace_probe(
                output.status.success(),
                &String::from_utf8_lossy(&output.stderr),
            ));
        }

        if started.elapsed() >= PROBE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(NetworkNamespaceProbe::Failed(
                "Bubblewrap network namespace capability probe timed out after 5 seconds"
                    .to_owned(),
            ));
        }

        thread::sleep(Duration::from_millis(25));
    }
}

/// Resolve the requested mode into an explicit requested/effective policy report.
fn resolve_linux_network_policy(mode: SandboxNetworkMode) -> Result<SandboxNetworkReport> {
    match mode {
        SandboxNetworkMode::Shared => {
            eprintln!("Quantum Shield: network mode explicitly set to shared.");
            Ok(SandboxNetworkReport::new(
                mode,
                SandboxNetworkMode::Shared,
                None,
            ))
        }
        SandboxNetworkMode::Isolated => match probe_network_namespace()? {
            NetworkNamespaceProbe::Supported => Ok(SandboxNetworkReport::new(
                mode,
                SandboxNetworkMode::Isolated,
                None,
            )),
            NetworkNamespaceProbe::CapabilityUnavailable(reason)
            | NetworkNamespaceProbe::Failed(reason) => {
                bail!(
                    "network isolation is required, but Bubblewrap could not establish a network namespace: {reason}"
                )
            }
        },
        SandboxNetworkMode::Automatic => match probe_network_namespace()? {
            NetworkNamespaceProbe::Supported => Ok(SandboxNetworkReport::new(
                mode,
                SandboxNetworkMode::Isolated,
                None,
            )),
            NetworkNamespaceProbe::CapabilityUnavailable(reason) => {
                eprintln!(
                    "WARNING: Quantum Shield automatic network mode is falling back to shared host networking because this host reports that unprivileged user namespaces are unavailable: {reason}"
                );
                Ok(SandboxNetworkReport::new(
                    mode,
                    SandboxNetworkMode::Shared,
                    Some(reason),
                ))
            }
            NetworkNamespaceProbe::Failed(reason) => {
                bail!(
                    "automatic network mode refused fallback because the Bubblewrap probe failed for an unrecognized reason: {reason}"
                )
            }
        },
    }
}

/// Replace this process with Bubblewrap running a target executable in a restricted namespace.
///
/// Host HOME, /root, /run, /sys, /var and /tmp are hidden behind fresh sandbox mounts. Common
/// system runtime directories are read-only. The executable itself is mounted read-only unless
/// an explicit app directory is supplied, in which case that directory is mounted read-only.
/// Only an explicitly chosen, non-overlapping writable directory is mounted writable.
pub fn exec_sandboxed(
    executable: &Path,
    app_dir: Option<&Path>,
    writable_dir: Option<&Path>,
    network_mode: SandboxNetworkMode,
    application_args: &[OsString],
    profile: &str,
) -> Result<()> {
    let limits = limits_for_profile(profile)?;

    if effective_uid()? == 0 {
        bail!("refusing to sandbox-run as root; run Quantum Shield as an unprivileged user");
    }

    let executable = executable
        .canonicalize()
        .with_context(|| format!("could not resolve executable {}", executable.display()))?;
    let metadata = fs::metadata(&executable)
        .with_context(|| format!("could not inspect executable {}", executable.display()))?;
    if !metadata.is_file() {
        bail!(
            "sandbox executable must be a regular file: {}",
            executable.display()
        );
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!(
            "sandbox executable has no execute bit: {}",
            executable.display()
        );
    }

    let app_dir = app_dir
        .map(|path| canonical_dir(path, "application directory"))
        .transpose()?;
    if let Some(directory) = app_dir.as_deref() {
        validate_app_dir(directory)?;
        if !executable.starts_with(directory) {
            bail!(
                "executable {} is not inside --app-dir {}; use a directory containing that executable",
                executable.display(),
                directory.display()
            );
        }
    }

    let writable_dir = writable_dir
        .map(|path| canonical_dir(path, "writable directory"))
        .transpose()?;
    if let Some(directory) = writable_dir.as_deref() {
        validate_writable_dir(directory)?;
        let app_boundary = app_dir
            .as_deref()
            .or_else(|| executable.parent())
            .context("executable has no parent directory")?;
        if paths_overlap(directory, app_boundary) {
            bail!(
                "--writable-dir must not overlap the executable or read-only --app-dir; choose a separate output directory"
            );
        }
    }

    let network_report = resolve_linux_network_policy(network_mode)?;
    let network_shared = network_report.effective_mode == SandboxNetworkMode::Shared;

    if network_shared {
        let resolver_target = Path::new("/etc/resolv.conf").canonicalize().context(
            "could not resolve /etc/resolv.conf; refusing shared networking until the resolver is fixed",
        )?;
        validate_shared_network_resolver(&resolver_target)?;
    }

    // Bubblewrap loads a compiled cBPF program from this inherited file descriptor and
    // installs it in the sandbox's init process before the target process starts.
    // The descriptor is deliberately non-CLOEXEC and stays alive until exec(2).
    let seccomp_profile = create_seccomp_profile()
        .context("could not prepare the mandatory Software Shield seccomp profile")?;
    let mut bwrap_args = build_bwrap_args_with_nproc(
        &executable,
        app_dir.as_deref(),
        writable_dir.as_deref(),
        network_report.effective_mode,
        application_args,
        limits.nproc,
    )?;
    prepend_seccomp_option(&mut bwrap_args, seccomp_profile.as_raw_fd());

    eprintln!("Quantum Shield Software Shield (Linux baseline sandbox)");
    eprintln!("  Executable     : {}", executable.display());
    let app_label = app_dir
        .as_deref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "executable file only".to_owned());
    eprintln!("  App directory  : {app_label}");
    eprintln!(
        "  Network        : requested={}, effective={}",
        network_report.requested_mode.as_str(),
        network_report.effective_mode.as_str()
    );
    if let Some(reason) = &network_report.fallback_reason {
        eprintln!("  Fallback reason: {reason}");
    }
    eprintln!("  Host filesystem: read-only system runtime; host home/runtime sockets hidden");
    let writable_label = writable_dir
        .as_deref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "none (sandbox temporary storage only)".to_owned());
    eprintln!("  Writable host  : {writable_label}");
    eprintln!("  Profile        : {profile}");
    eprintln!(
        "  Resource limits: CPU {}s, AS {}MB, fsize {}MB, nofile {}, nproc {}, core 0",
        limits.cpu_seconds, limits.memory_mb, limits.file_mb, limits.nofile, limits.nproc
    );
    eprintln!("  Syscall policy : Bubblewrap cBPF denylist active (fail-closed if unavailable)");
    eprintln!("  Limitations    : no GUI session integration; syscall policy is a denylist, not a per-application allowlist");

    // Apply profile-specific limits before exec; Bubblewrap inherits these limits.
    #[cfg(unix)]
    {
        let memory_bytes = limits.memory_mb * 1024 * 1024;
        let file_bytes = limits.file_mb * 1024 * 1024;
        apply_resource_limit(libc::RLIMIT_CPU, limits.cpu_seconds, "RLIMIT_CPU")?;
        apply_resource_limit(libc::RLIMIT_AS, memory_bytes, "RLIMIT_AS")?;
        apply_resource_limit(libc::RLIMIT_FSIZE, file_bytes, "RLIMIT_FSIZE")?;
        apply_resource_limit(libc::RLIMIT_NOFILE, limits.nofile, "RLIMIT_NOFILE")?;
        apply_resource_limit(libc::RLIMIT_CORE, 0, "RLIMIT_CORE")?;
    }

    // exec() preserves the target process's exit status and avoids wrapping user arguments in a shell.
    let error = Command::new("bwrap").args(&bwrap_args).exec();
    Err(error).context("could not execute Bubblewrap; install bubblewrap and verify that unprivileged user namespaces are enabled")
}

#[cfg(unix)]
fn apply_resource_limit(
    resource: libc::__rlimit_resource_t,
    requested: u64,
    label: &str,
) -> Result<()> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        bail!("failed to read {label}");
    }

    let requested = requested as libc::rlim_t;
    if current.rlim_max != libc::RLIM_INFINITY && current.rlim_max < requested {
        bail!(
            "{label} hard limit {} is below requested limit {}",
            current.rlim_max,
            requested
        );
    }

    let limit = libc::rlimit {
        rlim_cur: requested,
        rlim_max: requested,
    };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        bail!("failed to set {label}");
    }
    Ok(())
}

fn effective_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status")
        .context("cannot read /proc/self/status to verify the effective UID")?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .context("Uid field is absent from /proc/self/status")?;
    let fields = uid_line.split_whitespace().skip(1).collect::<Vec<_>>();
    fields
        .get(1)
        .context("effective UID field is missing")?
        .parse::<u32>()
        .context("effective UID is not numeric")
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("could not resolve {label} {}", path.display()))?;
    if !canonical.is_dir() {
        bail!(
            "{label} must be an existing directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn validate_app_dir(directory: &Path) -> Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|p| p.canonicalize().ok());
    if is_broad_sensitive_directory(directory)
        || home
            .as_deref()
            .is_some_and(|home| home.starts_with(directory))
    {
        bail!(
            "--app-dir {} is too broad or includes the user home; choose a dedicated, minimal application directory",
            directory.display()
        );
    }
    scan_app_directory_for_sensitive_inputs(directory)
}

fn scan_app_directory_for_sensitive_inputs(root: &Path) -> Result<()> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_APP_DIR_DEPTH {
            continue;
        }
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "could not inspect application directory {}",
                directory.display()
            )
        })? {
            let entry = entry?;
            visited += 1;
            if visited > MAX_APP_DIR_ENTRIES {
                bail!("--app-dir exceeds the {}-entry safety inspection limit; prepare a smaller clean application directory", MAX_APP_DIR_ENTRIES);
            }
            let name = entry.file_name();
            if is_sensitive_filename(&name.to_string_lossy()) {
                let entry_path = entry.path();
                let relative = entry_path
                    .strip_prefix(root)
                    .unwrap_or(entry_path.as_path())
                    .to_path_buf();
                bail!(
                    "--app-dir contains a potentially sensitive file/directory ({}) at {}; remove secrets and use a clean copy before sandboxing",
                    name.to_string_lossy(),
                    relative.display()
                );
            }

            let kind = entry.file_type()?;
            if kind.is_symlink() {
                let entry_path = entry.path();
                let target = entry_path.canonicalize().with_context(|| {
                    format!("broken symlink in --app-dir: {}", entry_path.display())
                })?;
                if !target.starts_with(root) {
                    bail!(
                        "--app-dir contains a symlink that escapes the application directory: {}",
                        entry_path.display()
                    );
                }
                if target.is_dir() && depth < MAX_APP_DIR_DEPTH {
                    pending.push((target, depth + 1));
                }
            } else if kind.is_dir() && depth < MAX_APP_DIR_DEPTH {
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(())
}

fn is_sensitive_filename(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        ".env.example" | ".env.sample" | ".env.template"
    ) {
        return false;
    }
    matches!(lower.as_str(), ".git" | ".svn" | ".hg")
        || lower == ".env"
        || lower.starts_with(".env.")
        || matches!(
            lower.as_str(),
            ".aws"
                | ".ssh"
                | ".kube"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | ".git-credentials"
                | "credentials"
                | "credentials.json"
                | "secrets.json"
                | "id_rsa"
                | "id_ed25519"
                | "id_ecdsa"
                | "id_dsa"
        )
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
}

fn validate_writable_dir(directory: &Path) -> Result<()> {
    if is_unsafe_writable_directory(directory) {
        bail!("--writable-dir cannot be a system/root directory ({}); choose a dedicated output directory inside your user workspace", directory.display());
    }
    if let Some(home) = env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|p| p.canonicalize().ok())
    {
        if home == directory || home.starts_with(directory) {
            bail!("--writable-dir cannot be the home directory or one of its parents; choose a dedicated child directory");
        }
    }
    Ok(())
}

fn is_broad_sensitive_directory(path: &Path) -> bool {
    const BLOCKED_EXACT: &[&str] = &[
        "/", "/etc", "/home", "/root", "/run", "/var", "/proc", "/sys", "/dev", "/usr", "/bin",
        "/sbin", "/lib", "/lib64", "/boot", "/opt", "/mnt", "/media", "/tmp",
    ];
    if BLOCKED_EXACT
        .iter()
        .any(|blocked| path == Path::new(blocked))
    {
        return true;
    }
    // These trees can contain credentials, host runtime state, devices, or externally mounted data.
    const BLOCKED_TREES: &[&str] = &[
        "/etc", "/root", "/run", "/var", "/proc", "/sys", "/dev", "/boot", "/mnt", "/media",
    ];
    BLOCKED_TREES
        .iter()
        .any(|blocked| path.starts_with(Path::new(blocked)))
}

fn is_unsafe_writable_directory(path: &Path) -> bool {
    if is_broad_sensitive_directory(path) {
        return true;
    }
    const BLOCKED_PREFIXES: &[&str] = &[
        "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev",
        "/run", "/var", "/opt", "/mnt", "/media", "/tmp", "/root",
    ];
    BLOCKED_PREFIXES.iter().any(|blocked| {
        let blocked = Path::new(blocked);
        path.starts_with(blocked) || blocked.starts_with(path)
    })
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

/// Insert Bubblewrap's seccomp option before all setup operations. The open file must remain
/// alive and non-CLOEXEC until `CommandExt::exec` replaces this process with Bubblewrap.
fn prepend_seccomp_option(args: &mut Vec<OsString>, fd: i32) {
    args.insert(0, OsString::from(fd.to_string()));
    args.insert(0, OsString::from("--seccomp"));
}

/// Create a Linux cBPF seccomp denylist and expose its bytecode through an inherited memfd.
///
/// This is intentionally a conservative denylist rather than a strict allowlist: general CLI
/// applications need different syscall sets. Network isolation, namespace isolation, read-only
/// mounts and resource limits remain independent controls. Unsupported architectures fail closed.
#[cfg(target_os = "linux")]
fn create_seccomp_profile() -> Result<File> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ENOSYS: u32 = 0x0005_0000 | libc::ENOSYS as u32;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

    let (audit_arch, denied_syscalls): (u32, &[u32]) = if cfg!(target_arch = "x86_64") {
        // Linux audit arch x86_64. Syscall numbers are from the x86_64 Linux ABI.
        (
            0xc000_003e,
            &[
                101, // ptrace
                154, // modify_ldt
                155, // pivot_root
                161, // chroot
                163, // acct
                165, // mount
                166, // umount2
                167, // swapon
                168, // swapoff
                169, // reboot
                172, // iopl
                173, // ioperm
                175, // init_module
                176, // delete_module
                246, // kexec_load
                248, // add_key
                249, // request_key
                250, // keyctl
                272, // unshare
                298, // perf_event_open
                303, // name_to_handle_at
                304, // open_by_handle_at
                308, // setns
                310, // process_vm_readv
                311, // process_vm_writev
                312, // kcmp
                313, // finit_module
                321, // bpf
                323, // userfaultfd
                425, // io_uring_setup
                426, // io_uring_enter
                427, // io_uring_register
                428, // open_tree
                429, // move_mount
                430, // fsopen
                431, // fsconfig
                432, // fsmount
                433, // fspick
                442, // mount_setattr
            ],
        )
    } else if cfg!(target_arch = "aarch64") {
        // Linux audit arch AArch64. These are the corresponding generic syscall numbers.
        (
            0xc000_00b7,
            &[
                39,  // umount2
                40,  // mount
                41,  // pivot_root
                51,  // chroot
                89,  // acct
                97,  // unshare
                104, // kexec_load
                105, // init_module
                106, // delete_module
                117, // ptrace
                142, // reboot
                217, // add_key
                218, // request_key
                219, // keyctl
                224, // swapon
                225, // swapoff
                241, // perf_event_open
                264, // name_to_handle_at
                265, // open_by_handle_at
                268, // setns
                270, // process_vm_readv
                271, // process_vm_writev
                272, // kcmp
                273, // finit_module
                280, // bpf
                282, // userfaultfd
                425, // io_uring_setup
                426, // io_uring_enter
                427, // io_uring_register
                428, // open_tree
                429, // move_mount
                430, // fsopen
                431, // fsconfig
                432, // fsmount
                433, // fspick
                442, // mount_setattr
            ],
        )
    } else {
        bail!("Software Shield seccomp policy is not defined for target architecture {}; refusing to run without syscall filtering", std::env::consts::ARCH);
    };

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    let mut filters = Vec::<libc::sock_filter>::with_capacity(4 + denied_syscalls.len() * 2);
    // Kill rather than accidentally interpret a syscall from an unexpected ABI.
    filters.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET));
    filters.push(jump(BPF_JMP_JEQ_K, audit_arch, 1, 0));
    filters.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    filters.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    if cfg!(target_arch = "x86_64") {
        // The x32 ABI shares AUDIT_ARCH_X86_64 but sets __X32_SYSCALL_BIT. Kill it rather
        // than let ABI-tagged syscall numbers bypass the native syscall denylist.
        filters.push(jump(0x45, 0x4000_0000, 0, 1)); // BPF_JMP | BPF_JSET | BPF_K
        filters.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    }

    // Namespace creation through clone(2) uses flags in args[0]. Deny namespace flags while
    // retaining ordinary fork/thread creation. clone3(2) points to a struct that classic BPF
    // cannot safely dereference, so report ENOSYS to trigger libc's clone(2) fallback; the
    // fallback is checked against the namespace-flag mask below.
    let clone_number = if cfg!(target_arch = "x86_64") {
        56
    } else {
        220
    };
    filters.push(jump(BPF_JMP_JEQ_K, clone_number, 0, 3));
    filters.push(stmt(BPF_LD_W_ABS, 16)); // seccomp_data.args[0], low 32-bit flags
    filters.push(jump(0x45, 0x7e02_0080, 0, 1)); // any CLONE_NEW* bit set
    filters.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filters.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    filters.push(jump(BPF_JMP_JEQ_K, 435, 0, 1)); // clone3: force safe libc fallback
    filters.push(stmt(BPF_RET_K, SECCOMP_RET_ENOSYS));
    filters.push(stmt(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));

    for syscall_number in denied_syscalls {
        // Match: return EPERM. Non-match skips the return and tests the next syscall.
        filters.push(jump(BPF_JMP_JEQ_K, *syscall_number, 0, 1));
        filters.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filters.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));

    // Bubblewrap's --seccomp FD input is a flat array of 8-byte `sock_filter` records,
    // not a `sock_fprog` wrapper. This is documented by Bubblewrap's own CLI reference.
    if std::mem::size_of::<libc::sock_filter>() != 8 {
        bail!("unexpected libc sock_filter layout; refusing to install seccomp profile");
    }
    let data = unsafe {
        std::slice::from_raw_parts(
            filters.as_ptr().cast::<u8>(),
            filters.len() * std::mem::size_of::<libc::sock_filter>(),
        )
    };

    let name = CString::new("quantum-shield-seccomp").expect("static memfd name has no NUL");
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("memfd_create failed for seccomp policy; refusing unfiltered launch");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(data)
        .context("could not write seccomp bytecode")?;
    file.flush().context("could not flush seccomp bytecode")?;
    file.seek(SeekFrom::Start(0))
        .context("could not rewind seccomp bytecode")?;

    let fd_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0
        || unsafe {
            libc::fcntl(
                file.as_raw_fd(),
                libc::F_SETFD,
                fd_flags & !libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(std::io::Error::last_os_error())
            .context("could not preserve the seccomp descriptor across Bubblewrap exec");
    }

    Ok(file)
}

#[cfg(not(target_os = "linux"))]
fn create_seccomp_profile() -> Result<File> {
    bail!("Software Shield seccomp filtering is Linux-only; refusing to launch without it")
}

fn build_bwrap_args_with_nproc(
    executable: &Path,
    app_dir: Option<&Path>,
    writable_dir: Option<&Path>,
    network_mode: SandboxNetworkMode,
    application_args: &[OsString],
    nproc: u64,
) -> Result<Vec<OsString>> {
    let mut args = Vec::<OsString>::new();
    push_flag(&mut args, "--die-with-parent");
    push_flag(&mut args, "--new-session");
    push_flag(&mut args, "--unshare-user");
    push_flag(&mut args, "--disable-userns");
    push_flag(&mut args, "--unshare-pid");
    push_flag(&mut args, "--unshare-ipc");
    push_flag(&mut args, "--unshare-uts");
    push_flag(&mut args, "--cap-drop");
    push_flag(&mut args, "ALL");
    if network_mode != SandboxNetworkMode::Shared {
        push_flag(&mut args, "--unshare-net");
    }

    // Build a minimal FHS-oriented runtime. Host system roots remain read-only.
    for root in ["/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64"] {
        let source = Path::new(root);
        if source.exists() {
            push_flag(&mut args, "--ro-bind");
            args.push(source.as_os_str().to_owned());
            args.push(source.as_os_str().to_owned());
        }
    }
    push_flag(&mut args, "--proc");
    push_path(&mut args, "/proc");
    push_flag(&mut args, "--dev");
    push_path(&mut args, "/dev");

    // Create private destinations and bind user-selected inputs before masking their host
    // ancestors (for example, an app located under $HOME). This avoids order-dependent mounts.
    push_flag(&mut args, "--dir");
    push_path(&mut args, SANDBOX_ROOT);
    push_flag(&mut args, "--dir");
    push_path(&mut args, SANDBOX_APP);
    push_flag(&mut args, "--size");
    push_flag(&mut args, "33554432");
    push_flag(&mut args, "--tmpfs");
    push_path(&mut args, SANDBOX_HOME);

    let executable_in_sandbox = if let Some(directory) = app_dir {
        let relative = executable
            .strip_prefix(directory)
            .context("executable is not below --app-dir")?;
        push_flag(&mut args, "--ro-bind");
        args.push(directory.as_os_str().to_owned());
        push_path(&mut args, SANDBOX_APP);
        Path::new(SANDBOX_APP).join(relative)
    } else {
        let name = executable
            .file_name()
            .context("executable has no filename")?;
        let destination = Path::new(SANDBOX_APP).join(name);
        push_flag(&mut args, "--ro-bind");
        args.push(executable.as_os_str().to_owned());
        args.push(destination.as_os_str().to_owned());
        destination
    };

    let working_directory = if let Some(directory) = writable_dir {
        push_flag(&mut args, "--dir");
        push_path(&mut args, SANDBOX_WRITABLE);
        push_flag(&mut args, "--bind");
        args.push(directory.as_os_str().to_owned());
        push_path(&mut args, SANDBOX_WRITABLE);
        PathBuf::from(SANDBOX_WRITABLE)
    } else if app_dir.is_some() {
        PathBuf::from(SANDBOX_APP)
    } else {
        PathBuf::from("/tmp")
    };

    // Mask common host secret directories even though /etc itself is read-only.
    // Use /dev/null bind mounts for credential *files*; a tmpfs-on-file mount is not portable.
    for secret_path in [
        "/etc/ssh",
        "/etc/letsencrypt",
        "/etc/ssl/private",
        "/etc/pki/private",
        "/etc/pki/tls/private",
        "/etc/NetworkManager/system-connections",
        "/etc/credstore",
        "/etc/credstore.encrypted",
    ] {
        if Path::new(secret_path).is_dir() {
            push_flag(&mut args, "--tmpfs");
            push_path(&mut args, secret_path);
        }
    }
    for secret_file in [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/shadow-",
        "/etc/gshadow-",
    ] {
        if Path::new(secret_file).is_file() {
            push_flag(&mut args, "--ro-bind");
            push_path(&mut args, "/dev/null");
            push_path(&mut args, secret_file);
        }
    }
    for (mount, size_bytes) in [
        ("/tmp", "268435456"), // 256 MiB
        ("/var", "67108864"),  // 64 MiB
        ("/home", "33554432"), // 32 MiB
        ("/root", "16777216"), // 16 MiB
        ("/run", "16777216"),  // 16 MiB
        ("/sys", "16777216"),  // 16 MiB
    ] {
        push_flag(&mut args, "--size");
        push_flag(&mut args, size_bytes);
        push_flag(&mut args, "--tmpfs");
        push_path(&mut args, mount);
    }

    // A root mount made read-only prevents writes to otherwise-unbound paths in the sandbox.
    // Nested tmpfs mounts and the one explicitly selected writable bind remain independently writable.
    push_flag(&mut args, "--remount-ro");
    push_path(&mut args, "/");

    push_flag(&mut args, "--clearenv");
    set_env(&mut args, "HOME", SANDBOX_HOME);
    set_env(&mut args, "TMPDIR", "/tmp");
    set_env(
        &mut args,
        "PATH",
        "/qs/app:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    set_env(&mut args, "LANG", "C.UTF-8");
    set_env(&mut args, "QS_SANDBOXED", "1");
    if writable_dir.is_some() {
        set_env(&mut args, "QS_WRITABLE_DIR", SANDBOX_WRITABLE);
    }
    push_flag(&mut args, "--chdir");
    args.push(working_directory.as_os_str().to_owned());
    push_flag(&mut args, "--");
    args.push(Path::new(SANDBOX_PRLIMIT).as_os_str().to_owned());
    args.push(OsString::from(format!("--nproc={nproc}")));
    push_flag(&mut args, "--");
    args.push(executable_in_sandbox.as_os_str().to_owned());
    args.extend(application_args.iter().cloned());
    Ok(args)
}

fn validate_shared_network_resolver(resolver_target: &Path) -> Result<()> {
    if resolver_target.starts_with("/run") {
        bail!(
            "--share-network is not supported with this host resolver: /etc/resolv.conf resolves below /run, which Software Shield deliberately hides. Keep network isolation enabled or configure a stable system resolver."
        );
    }
    Ok(())
}

fn push_flag(args: &mut Vec<OsString>, value: &str) {
    args.push(OsString::from(value));
}

fn push_path(args: &mut Vec<OsString>, value: &str) {
    args.push(OsString::from(value));
}

fn set_env(args: &mut Vec<OsString>, name: &str, value: &str) {
    push_flag(args, "--setenv");
    push_flag(args, name);
    push_flag(args, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_policy::SandboxNetworkMode;
    use std::io::Read;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("qs-sandbox-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("create test directory");
        path
    }

    fn executable(root: &Path) -> PathBuf {
        let path = root.join("test-app");
        fs::write(&path, b"not executed in builder tests\n").expect("write test executable");
        let mut permissions = fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("set executable permission");
        path.canonicalize().expect("canonical executable")
    }

    fn as_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn seccomp_option_is_passed_to_bubblewrap() {
        let mut args = vec![OsString::from("--die-with-parent"), OsString::from("--")];
        prepend_seccomp_option(&mut args, 37);
        let values = as_strings(&args);
        assert_eq!(values[0], "--seccomp");
        assert_eq!(values[1], "37");
        assert_eq!(values[2], "--die-with-parent");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_profile_is_nonempty_bpf_bytecode_and_fd_is_inheritable() {
        let mut profile = create_seccomp_profile().expect("create seccomp profile");
        let metadata = profile.metadata().expect("profile metadata");
        assert!(metadata.len() >= 5 * 8);
        assert_eq!(metadata.len() % 8, 0);
        let flags = unsafe { libc::fcntl(profile.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            0,
            "Bubblewrap must inherit the seccomp fd"
        );
        let mut bytes = Vec::new();
        profile.read_to_end(&mut bytes).expect("read bytecode");
        assert_eq!(bytes.len() as u64, metadata.len());
    }

    #[test]
    fn named_profiles_have_expected_resource_limits() {
        assert_eq!(
            limits_for_profile("strict").unwrap(),
            SandboxLimits {
                cpu_seconds: 30,
                memory_mb: 256,
                file_mb: 128,
                nofile: 512,
                nproc: 64,
            }
        );
        assert_eq!(
            limits_for_profile("balanced").unwrap(),
            SandboxLimits {
                cpu_seconds: 60,
                memory_mb: 512,
                file_mb: 256,
                nofile: 1024,
                nproc: 256,
            }
        );
        assert_eq!(
            limits_for_profile("developer").unwrap(),
            SandboxLimits {
                cpu_seconds: 300,
                memory_mb: 2048,
                file_mb: 1024,
                nofile: 2048,
                nproc: 512,
            }
        );
    }

    #[test]
    fn unknown_sandbox_profile_is_rejected() {
        assert!(limits_for_profile("unrestricted")
            .unwrap_err()
            .to_string()
            .contains("unknown sandbox profile"));
    }

    #[test]
    fn profile_process_limits_reach_bubblewrap_arguments() {
        let root = temp_dir("profile-nproc");
        let exe = executable(&root);

        for (name, expected) in [
            ("strict", "--nproc=64"),
            ("balanced", "--nproc=256"),
            ("developer", "--nproc=512"),
        ] {
            let limits = limits_for_profile(name).unwrap();
            let args = build_bwrap_args_with_nproc(
                &exe,
                None,
                None,
                SandboxNetworkMode::Isolated,
                &[],
                limits.nproc,
            )
            .expect("build sandbox args");
            assert!(
                as_strings(&args).contains(&expected.to_owned()),
                "{name} profile did not set {expected}"
            );
        }

        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn default_profile_is_network_isolated_and_uses_read_only_mounts() {
        let root = temp_dir("default");
        let exe = executable(&root);
        let args =
            build_bwrap_args_with_nproc(&exe, None, None, SandboxNetworkMode::Isolated, &[], 256)
                .expect("build args");
        let values = as_strings(&args);
        assert!(values.contains(&"--unshare-net".to_owned()));
        assert!(values.contains(&"--unshare-user".to_owned()));
        assert!(values.contains(&"--disable-userns".to_owned()));
        assert!(values.contains(&"--ro-bind".to_owned()));
        assert!(values.contains(&"--clearenv".to_owned()));
        assert!(values.contains(&"/home".to_owned()));
        assert!(values
            .windows(2)
            .any(|pair| pair[0] == "--cap-drop" && pair[1] == "ALL"));
        assert!(values
            .windows(2)
            .any(|pair| pair[0] == "--remount-ro" && pair[1] == "/"));
        let remount_ro_index = values
            .windows(2)
            .position(|pair| pair[0] == "--remount-ro" && pair[1] == "/")
            .expect("root remount");
        let tmp_mount_index = values
            .windows(2)
            .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/tmp")
            .expect("tmpfs mount");
        assert!(
            tmp_mount_index < remount_ro_index,
            "temporary writable mounts must exist before the root is remounted read-only"
        );
        assert!(!values.contains(&"--share-net".to_owned()));
        assert!(values
            .windows(2)
            .any(|pair| pair[0] == "QS_SANDBOXED" && pair[1] == "1"));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn shared_network_rejects_resolver_that_depends_on_hidden_run() {
        assert!(validate_shared_network_resolver(Path::new(
            "/run/systemd/resolve/stub-resolv.conf"
        ))
        .is_err());
        assert!(validate_shared_network_resolver(Path::new("/etc/resolv.conf")).is_ok());
    }

    #[test]
    fn network_is_only_shared_when_explicitly_requested() {
        let root = temp_dir("network");
        let exe = executable(&root);
        let args =
            build_bwrap_args_with_nproc(&exe, None, None, SandboxNetworkMode::Shared, &[], 256)
                .expect("build args");
        assert!(!as_strings(&args).contains(&"--unshare-net".to_owned()));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn app_directory_is_mounted_read_only_at_private_sandbox_path() {
        let root = temp_dir("app-dir");
        let exe = executable(&root);
        let args = build_bwrap_args_with_nproc(
            &exe,
            Some(&root),
            None,
            SandboxNetworkMode::Isolated,
            &[],
            256,
        )
        .expect("build args");
        let values = as_strings(&args);
        let root_text = root.to_string_lossy().into_owned();
        assert!(values.windows(3).any(|triple| {
            triple[0] == "--ro-bind" && triple[1] == root_text && triple[2] == SANDBOX_APP
        }));
        let app_bind_index = values
            .windows(3)
            .position(|triple| {
                triple[0] == "--ro-bind" && triple[1] == root_text && triple[2] == SANDBOX_APP
            })
            .expect("app directory bind");
        let home_mask_index = values
            .windows(2)
            .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/home")
            .expect("host home mask");
        let tmp_mask_index = values
            .windows(2)
            .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/tmp")
            .expect("host tmp mask");
        assert!(
            app_bind_index < home_mask_index,
            "bind selected app before hiding its host parent"
        );
        assert!(
            app_bind_index < tmp_mask_index,
            "bind selected app before hiding its possible temporary parent"
        );
        assert!(values.contains(&format!("{SANDBOX_APP}/test-app")));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn broad_or_secret_bearing_app_directories_are_rejected() {
        assert!(validate_app_dir(Path::new("/etc")).is_err());
        let root = temp_dir("secret-dir");
        fs::write(root.join(".env"), b"TEST=fixture\n").expect("write fixture");
        assert!(scan_app_directory_for_sensitive_inputs(&root).is_err());
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn repository_metadata_is_rejected_in_runnable_app_directory() {
        assert!(is_sensitive_filename(".git"));
        assert!(is_sensitive_filename(".svn"));
        assert!(is_sensitive_filename(".hg"));
        assert!(!is_sensitive_filename("index.html"));
    }

    #[test]
    fn app_directory_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let root = temp_dir("symlink-root");
        let outside = temp_dir("symlink-outside");
        symlink(&outside, root.join("external")).expect("create outside symlink");
        assert!(scan_app_directory_for_sensitive_inputs(&root).is_err());
        fs::remove_dir_all(root).expect("clean root fixture");
        fs::remove_dir_all(outside).expect("clean outside fixture");
    }

    #[test]
    fn writable_mount_cannot_be_a_system_directory() {
        assert!(validate_writable_dir(Path::new("/etc")).is_err());
        assert!(validate_writable_dir(Path::new("/usr")).is_err());
    }

    #[test]
    fn app_and_writable_mounts_cannot_overlap() {
        let root = temp_dir("overlap");
        let child = root.join("output");
        fs::create_dir_all(&child).expect("create output");
        assert!(paths_overlap(&root, &child));
        assert!(paths_overlap(&child, &root));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn arguments_are_forwarded_without_a_shell() {
        let root = temp_dir("argv");
        let exe = executable(&root);
        let user_args = vec![OsString::from("semi;colon"), OsString::from("space arg")];
        let args = build_bwrap_args_with_nproc(
            &exe,
            None,
            None,
            SandboxNetworkMode::Isolated,
            &user_args,
            256,
        )
        .expect("build args");
        let values = as_strings(&args);
        assert!(values.ends_with(&[
            format!("{SANDBOX_APP}/test-app"),
            "semi;colon".to_owned(),
            "space arg".to_owned()
        ]));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_denylist_blocks_privileged_syscalls_but_allows_normal_io() {
        let mut profile = create_seccomp_profile().expect("create seccomp profile");
        let mut bytes = Vec::new();
        profile.read_to_end(&mut bytes).expect("read bytecode");
        assert_eq!(
            bytes.len() % 8,
            0,
            "bytecode must be whole sock_filter records"
        );
        let filters: Vec<(u16, u8, u8, u32)> = bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| {
                (
                    u16::from_le_bytes([chunk[0], chunk[1]]),
                    chunk[2],
                    chunk[3],
                    u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
                )
            })
            .collect();

        // Arch guard: unexpected ABIs are killed, not filtered through the native table.
        assert_eq!(filters[0].0, 0x20, "first filter must load the audit arch");
        assert_eq!(
            filters[1].0, 0x15,
            "second filter must compare the audit arch"
        );
        assert_eq!(filters[1].2, 0, "arch mismatch falls through to the kill");
        assert_eq!(filters[2].0, 0x06);
        assert_eq!(
            filters[2].3, 0x8000_0000,
            "unexpected ABI must kill the process"
        );

        let mut denied = std::collections::BTreeSet::new();
        for window in filters.windows(2) {
            let (code, jt, jf, syscall) = window[0];
            let (ret_code, _, _, ret_value) = window[1];
            if code == 0x15 && jt == 0 && jf == 1 && ret_code == 0x06 && ret_value == 0x0005_0001 {
                denied.insert(syscall);
            }
        }

        for syscall in [101u32, 165, 166, 175, 176, 272, 308, 310, 321, 323, 442] {
            assert!(
                denied.contains(&syscall),
                "seccomp denylist is missing privileged syscall {syscall}"
            );
        }
        for allowed in [0u32, 1, 59, 257] {
            assert!(
                !denied.contains(&allowed),
                "seccomp denylist must not block ordinary syscall {allowed}"
            );
        }
        let last = filters.last().expect("nonempty filter");
        assert_eq!(last.0, 0x06);
        assert_eq!(last.3, 0x7fff_0000, "default action must be ALLOW");

        #[cfg(target_arch = "x86_64")]
        {
            let x32_check = filters
                .iter()
                .find(|filter| filter.0 == 0x45 && filter.3 == 0x4000_0000)
                .expect("x32 ABI guard must be present");
            assert_eq!(x32_check.1, 0, "x32 syscall must fall through");
            assert_eq!(x32_check.2, 1, "native syscalls must skip the kill");
        }
    }
}

#[cfg(test)]
mod network_namespace_probe_tests {
    use super::*;

    #[test]
    fn successful_probe_is_supported() {
        assert_eq!(
            classify_network_namespace_probe(true, ""),
            NetworkNamespaceProbe::Supported
        );
    }

    #[test]
    fn recognized_unprivileged_namespace_diagnostic_is_capability_unavailable() {
        let diagnostic = "bwrap: No permissions to create a new namespace, likely because the kernel does not allow non-privileged user namespaces.";
        assert_eq!(
            classify_network_namespace_probe(false, diagnostic),
            NetworkNamespaceProbe::CapabilityUnavailable(diagnostic.to_owned())
        );
    }

    #[test]
    fn generic_operation_not_permitted_is_not_a_capability_fallback() {
        assert_eq!(
            classify_network_namespace_probe(false, "Operation not permitted"),
            NetworkNamespaceProbe::Failed("Operation not permitted".to_owned())
        );
    }

    #[test]
    fn unrelated_probe_error_fails_closed() {
        assert_eq!(
            classify_network_namespace_probe(false, "bwrap: executable not found"),
            NetworkNamespaceProbe::Failed("bwrap: executable not found".to_owned())
        );
    }

    #[test]
    fn empty_probe_error_fails_closed_with_diagnostic() {
        assert!(matches!(
            classify_network_namespace_probe(false, ""),
            NetworkNamespaceProbe::Failed(message) if message.contains("without a diagnostic")
        ));
    }
}
