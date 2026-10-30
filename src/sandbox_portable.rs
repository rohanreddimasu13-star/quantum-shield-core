//! Native sandbox launchers for macOS and Windows.
//! These backends have OS-specific prerequisites and require native testing.

use anyhow::{bail, Result};
use std::ffi::OsString;
use std::path::Path;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use anyhow::Context;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label}: {}", path.display()))?;
    if !path.is_dir() {
        bail!("{label} is not a directory: {}", path.display());
    }
    Ok(path)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn canonical_executable(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve executable: {}", path.display()))?;
    if !path.is_file() {
        bail!("sandbox target is not a regular file: {}", path.display());
    }
    Ok(path)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn validate_writable(app: &Path, writable: Option<&Path>) -> Result<Option<PathBuf>> {
    let Some(path) = writable else {
        return Ok(None);
    };
    let path = canonical_dir(path, "writable directory")?;
    if path.starts_with(app) || app.starts_with(&path) {
        bail!("writable directory must not overlap the read-only application directory");
    }
    Ok(Some(path))
}

#[cfg(target_os = "macos")]
pub fn exec_sandboxed(
    executable: &Path,
    app_dir: Option<&Path>,
    writable_dir: Option<&Path>,
    share_network: bool,
    application_args: &[OsString],
    profile: &str,
) -> Result<()> {
    if profile != "balanced" {
        bail!(
            "named resource profiles are currently supported only by the Linux Bubblewrap backend"
        );
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let executable = canonical_executable(executable)?;
    let app = match app_dir {
        Some(path) => canonical_dir(path, "application directory")?,
        None => executable
            .parent()
            .context("executable has no parent")?
            .to_path_buf(),
    };
    if !executable.starts_with(&app) {
        bail!("executable must be inside the read-only application directory");
    }
    let writable = validate_writable(&app, writable_dir)?;
    let temp = fs::canonicalize(std::env::temp_dir())?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let profile_path = temp.join(format!("qs-{}-{stamp}.sb", std::process::id()));

    let seatbelt = |p: &Path| {
        p.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let temp_s = seatbelt(&temp);
    let app_s = seatbelt(&app);
    let exe_s = seatbelt(&executable);
    let writable_rule = writable
        .as_deref()
        .map(|p| format!(" (subpath \"{}\")", seatbelt(p)))
        .unwrap_or_default();
    let network_rule = if share_network {
        "(allow network-outbound)"
    } else {
        ""
    };
    let profile = format!(
        r#"(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/bin") (subpath "/sbin") (subpath "/Library") (subpath "/Applications") (subpath "/private/etc") (subpath "/dev") (subpath "{app_s}") (subpath "{temp_s}") (literal "{exe_s}"))
(allow file-map-executable (subpath "/System") (subpath "/usr") (subpath "{app_s}"))
(allow file-write* (subpath "{temp_s}"){writable_rule})
{network_rule}
"#
    );

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&profile_path)?;
    file.write_all(profile.as_bytes())?;
    drop(file);

    eprintln!("Quantum Shield: macOS Seatbelt sandbox; filesystem writes restricted.");
    eprintln!(
        "Network: {}",
        if share_network {
            "outbound allowed by opt-in"
        } else {
            "denied by default"
        }
    );
    eprintln!("Note: sandbox-exec is deprecated on macOS and may not be available.");

    let result = Command::new("/usr/bin/sandbox-exec")
        .arg("-f")
        .arg(&profile_path)
        .arg(&executable)
        .args(application_args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin")
        .env("HOME", &temp)
        .env("TMPDIR", &temp)
        .status()
        .context("macOS sandbox-exec unavailable; refusing to launch unsandboxed");
    let _ = fs::remove_file(&profile_path);
    let status = result?;
    if !status.success() {
        bail!("sandboxed application exited with status {status}");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn exec_sandboxed(
    executable: &Path,
    app_dir: Option<&Path>,
    writable_dir: Option<&Path>,
    share_network: bool,
    application_args: &[OsString],
    profile: &str,
) -> Result<()> {
    if profile != "balanced" {
        bail!(
            "named resource profiles are currently supported only by the Linux Bubblewrap backend"
        );
    }
    use std::time::{SystemTime, UNIX_EPOCH};

    fn xml(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }
    fn ps(s: &str) -> String {
        format!("'{}'", s.replace('\'', "''"))
    }
    fn win_arg(s: &str) -> String {
        let mut out = String::from("\"");
        let mut slashes = 0usize;
        for c in s.chars() {
            if c == '\\' {
                slashes += 1;
                continue;
            }
            if c == '"' {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
            } else {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
            }
            slashes = 0;
        }
        out.push_str(&"\\".repeat(slashes * 2));
        out.push('"');
        out
    }

    let executable = canonical_executable(executable)?;
    let app = match app_dir {
        Some(path) => canonical_dir(path, "application directory")?,
        None => executable
            .parent()
            .context("executable has no parent")?
            .to_path_buf(),
    };
    let relative = executable
        .strip_prefix(&app)
        .context("executable must be inside the read-only application directory")?;
    let writable = validate_writable(&app, writable_dir)?;

    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let workdir =
        std::env::temp_dir().join(format!("quantum-shield-{}-{stamp}", std::process::id()));
    fs::create_dir(&workdir).context("cannot create temporary Windows Sandbox files")?;

    let guest_exe = format!(
        r"C:\QSApp\{}",
        relative.to_string_lossy().replace('/', "\\")
    );
    let guest_work = relative
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| format!(r"C:\QSApp\{}", p.to_string_lossy().replace('/', "\\")))
        .unwrap_or_else(|| r"C:\QSApp".to_owned());
    let args = application_args
        .iter()
        .map(|a| win_arg(&a.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ");
    let launch = if args.is_empty() {
        "$p = Start-Process -FilePath $exe -WorkingDirectory $work -Wait -PassThru".to_owned()
    } else {
        "$p = Start-Process -FilePath $exe -WorkingDirectory $work -ArgumentList $argsText -Wait -PassThru".to_owned()
    };
    let script = format!(
        "$exe = {}\n$work = {}\n$argsText = {}\n{}\nexit $p.ExitCode\n",
        ps(&guest_exe),
        ps(&guest_work),
        ps(&args),
        launch
    );
    fs::write(workdir.join("launch.ps1"), script)?;

    let output_mapping = writable.as_deref().map(|p| format!(
        "<MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\\QSWritable</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>",
        xml(&p.to_string_lossy())
    )).unwrap_or_default();
    let networking = if share_network { "Enable" } else { "Disable" };
    let config = format!(
        r#"<Configuration>
<Networking>{networking}</Networking>
<vGPU>Disable</vGPU>
<MemoryInMB>2048</MemoryInMB>
<ProtectedClient>Enable</ProtectedClient>
<ClipboardRedirection>Disable</ClipboardRedirection>
<PrinterRedirection>Disable</PrinterRedirection>
<AudioInput>Disable</AudioInput>
<VideoInput>Disable</VideoInput>
<MappedFolders>
<MappedFolder><HostFolder>{tools}</HostFolder><SandboxFolder>C:\QSTools</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
<MappedFolder><HostFolder>{app}</HostFolder><SandboxFolder>C:\QSApp</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
{output_mapping}
</MappedFolders>
<LogonCommand><Command>powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\QSTools\launch.ps1</Command></LogonCommand>
</Configuration>"#,
        networking = networking,
        tools = xml(&workdir.to_string_lossy()),
        app = xml(&app.to_string_lossy()),
        output_mapping = output_mapping
    );
    let config_path = workdir.join("QuantumShield.wsb");
    fs::write(&config_path, config)?;

    eprintln!("Quantum Shield: launching Windows Sandbox (2 GB memory cap).");
    eprintln!(
        "App folder is read-only; host output is shared only when --writable-dir is specified."
    );
    eprintln!(
        "Network: {}",
        if share_network {
            "enabled by explicit opt-in"
        } else {
            "disabled"
        }
    );
    eprintln!(
        "Temporary config retained at {} (remove its folder after closing the sandbox).",
        workdir.display()
    );

    Command::new("WindowsSandbox.exe").arg(&config_path).spawn()
        .context("Windows Sandbox is unavailable. It requires a supported Windows Pro/Enterprise/Education setup; refusing to launch unsandboxed")?;
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn exec_sandboxed(
    _executable: &Path,
    _app_dir: Option<&Path>,
    _writable_dir: Option<&Path>,
    _share_network: bool,
    _application_args: &[OsString],
    _profile: &str,
) -> Result<()> {
    bail!("no supported native Software Shield sandbox backend for this operating system")
}
