//! Reversible, non-invasive project integrations for Website, Repository and Software Shield.
//!
//! Integration files live under `.quantum-shield/`; the application source, package manifests,
//! start scripts, and deployment files are not rewritten. A generated local website gateway is
//! deliberately loopback-only. Public traffic still requires an explicitly configured deployment
//! adapter such as the existing Docker Compose path.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const MANAGED_DIR: &str = ".quantum-shield";
const MARKER: &str = "QUANTUM_SHIELD_MANAGED_INTEGRATION_V1";
const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug, Subcommand)]
pub enum IntegrationCommand {
    /// Detect the project type and show which integration paths are supported.
    Detect {
        /// Project/repository directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Add reversible Quantum Shield helpers without rewriting application source files.
    Install {
        /// Project/repository directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Explicit loopback HTTP upstream, e.g. http://127.0.0.1:3000. Docker service names are not valid for this host-run preview.
        #[arg(long)]
        upstream: Option<String>,
    },
    /// Show installed integration files and any local Git hook state.
    Status {
        /// Project/repository directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Remove only unmodified files created by Quantum Shield; preserve edited files and user hooks.
    Remove {
        /// Project/repository directory (defaults to the current directory).
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    marker: String,
    schema_version: u32,
    project_root: String,
    detected_platform: String,
    files: Vec<ManagedFile>,
    git_hook: Option<ManagedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedFile {
    relative_path: String,
    drift_hash_fnv1a64: String,
}

#[derive(Debug, Clone)]
struct Detection {
    platform: String,
    explanation: String,
    default_upstream: Option<String>,
    website_mode: &'static str,
}

pub fn run(command: IntegrationCommand) -> Result<()> {
    match command {
        IntegrationCommand::Detect { path } => detect_command(&path),
        IntegrationCommand::Install { path, upstream } => {
            install_command(&path, upstream.as_deref())
        }
        IntegrationCommand::Status { path } => status_command(&path),
        IntegrationCommand::Remove { path } => remove_command(&path),
    }
}

fn canonical_project_root(path: &Path) -> Result<PathBuf> {
    let root = path
        .canonicalize()
        .with_context(|| format!("could not resolve project directory {}", path.display()))?;
    if !root.is_dir() {
        bail!("integration target must be a directory: {}", root.display());
    }
    if root.parent().is_none() {
        bail!("refusing to integrate a filesystem root");
    }
    if !has_project_marker(&root) {
        bail!("{} does not look like a project root (no recognized manifest, Git metadata, Compose file, or website entry point); no files changed", root.display());
    }
    Ok(root)
}

fn has_project_marker(root: &Path) -> bool {
    [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "requirements.txt",
        "manage.py",
        "go.mod",
        "composer.json",
        "Gemfile",
        "pom.xml",
        "build.gradle",
        "index.html",
        "vercel.json",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        ".git",
    ]
    .iter()
    .any(|entry| root.join(entry).exists())
        || root.join("src").is_dir()
            && (root.join("README.md").exists() || root.join("README").exists())
}

fn detect(root: &Path) -> Detection {
    let vercel = root.join("vercel.json").exists() || root.join(".vercel").exists();
    let compose = ["compose.yaml", "compose.yml", "docker-compose.yml"]
        .iter()
        .any(|name| root.join(name).is_file());

    if vercel {
        return Detection {
            platform: "managed-vercel".to_owned(),
            explanation: "Vercel-managed deployment detected. A local Rust proxy cannot be inserted into the remote deployment by editing this directory; use a platform-compatible routing design or passive assessment.".to_owned(),
            default_upstream: None,
            website_mode: "managed-hosting / assessment-only from this directory",
        };
    }

    if compose {
        return Detection {
            platform: "docker-compose".to_owned(),
            explanation: "Docker Compose project detected. The existing deploy-compose adapter is the supported public gateway path; service name, domain, TLS and approval must be validated before apply. This installer will not rewrite the base Compose file.".to_owned(),
            default_upstream: None,
            website_mode: "existing Compose deployment adapter",
        };
    }

    if root.join("package.json").is_file() {
        if let Ok(text) = fs::read_to_string(root.join("package.json")) {
            if let Ok(package) = serde_json::from_str::<Value>(&text) {
                let has_dep = |name: &str| {
                    ["dependencies", "devDependencies", "peerDependencies"]
                        .iter()
                        .filter_map(|key| package.get(*key).and_then(Value::as_object))
                        .any(|deps| deps.contains_key(name))
                };
                let scripts = package.get("scripts").and_then(Value::as_object);
                let scripts_text = scripts
                    .map(|scripts| {
                        scripts
                            .values()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                if has_dep("next") {
                    let port = explicit_port(&scripts_text).unwrap_or(3000);
                    return node_detection(
                        "Next.js",
                        port,
                        "Next.js",
                        "local reverse-proxy preview; public deployment remains separate",
                    );
                }
                if has_dep("express") || has_dep("fastify") || has_dep("koa") || has_dep("hono") {
                    let port = explicit_port(&scripts_text).unwrap_or(3000);
                    let kind = if has_dep("express") {
                        "Express"
                    } else if has_dep("fastify") {
                        "Fastify"
                    } else if has_dep("koa") {
                        "Koa"
                    } else {
                        "Hono"
                    };
                    return node_detection(
                        kind,
                        port,
                        kind,
                        "local reverse-proxy preview; public deployment remains separate",
                    );
                }
                if has_dep("vite") {
                    let port = explicit_port(&scripts_text).unwrap_or(5173);
                    return node_detection("Vite frontend/dev server", port, "Vite", "local preview only; a static frontend has no server-side enforcement by itself");
                }
                if has_dep("react")
                    || has_dep("vue")
                    || has_dep("svelte")
                    || has_dep("@angular/core")
                {
                    return Detection {
                        platform: "javascript-static-or-client-rendered".to_owned(),
                        explanation: "A client-rendered frontend was detected, but no server-side request boundary was identified. The repository and software helpers can be installed; public enforcement requires a supported server/edge gateway.".to_owned(),
                        default_upstream: None,
                        website_mode: "assessment / separate gateway only",
                    };
                }
            }
        }
    }

    if root.join("manage.py").is_file() {
        return Detection {
            platform: "django".to_owned(),
            explanation: "Django project detected. A loopback preview can target the conventional development port, but it does not replace a production WSGI/ASGI server or alter deployment routing.".to_owned(),
            default_upstream: Some("http://127.0.0.1:8000".to_owned()),
            website_mode: "local reverse-proxy preview; public deployment remains separate",
        };
    }

    if root.join("go.mod").is_file() {
        if let Some(port) = find_port_in_source_tree(root, &["ListenAndServe(", "Listen("]) {
            return Detection {
                platform: "go-web-server".to_owned(),
                explanation: format!("Go project with a likely server port ({port}) detected. Verify the server is actually listening before starting the local gateway."),
                default_upstream: Some(format!("http://127.0.0.1:{port}")),
                website_mode: "local reverse-proxy preview; public deployment remains separate",
            };
        }
        return Detection {
            platform: "go-project".to_owned(),
            explanation: "Go project detected, but no server port could be inferred safely."
                .to_owned(),
            default_upstream: None,
            website_mode: "upstream required for local proxy preview",
        };
    }

    if root.join("requirements.txt").is_file() || root.join("pyproject.toml").is_file() {
        let mut corpus = String::new();
        for name in [
            "requirements.txt",
            "pyproject.toml",
            "app.py",
            "main.py",
            "server.py",
        ] {
            if let Ok(value) = fs::read_to_string(root.join(name)) {
                corpus.push_str(&value.to_ascii_lowercase());
                corpus.push('\n');
            }
        }
        if corpus.contains("django") {
            return simple_python_detection("django", 8000);
        }
        if corpus.contains("fastapi") || corpus.contains("uvicorn") {
            return simple_python_detection("FastAPI/Uvicorn", 8000);
        }
        if corpus.contains("flask") {
            return simple_python_detection("Flask", 5000);
        }
        return Detection {
            platform: "python-project".to_owned(),
            explanation: "Python project detected; no supported web framework/port combination could be inferred confidently.".to_owned(),
            default_upstream: None,
            website_mode: "upstream required for local proxy preview",
        };
    }

    if root.join("index.html").is_file() {
        return Detection {
            platform: "static-site".to_owned(),
            explanation: "Static site detected. There is no server-side code here to enforce request filtering; use a supported edge/reverse-proxy host or passive assessment.".to_owned(),
            default_upstream: None,
            website_mode: "assessment / separate gateway only",
        };
    }

    Detection {
        platform: "unknown-project".to_owned(),
        explanation: "A project marker was found, but no supported web runtime was identified. Repository and Software Shield helpers can still be installed.".to_owned(),
        default_upstream: None,
        website_mode: "no automatic website adapter",
    }
}

fn node_detection(kind: &str, port: u16, platform: &str, website_mode: &'static str) -> Detection {
    Detection {
        platform: format!("{platform}-node"),
        explanation: format!("{kind} was detected. A loopback-only HTTP gateway config will be generated for 127.0.0.1:{port}; this does not change the application's startup command or hide its original port."),
        default_upstream: Some(format!("http://127.0.0.1:{port}")),
        website_mode,
    }
}

fn simple_python_detection(platform: &str, port: u16) -> Detection {
    Detection {
        platform: platform.to_ascii_lowercase().replace('/', "-"),
        explanation: format!("{platform} detected. A local gateway config will target conventional development port {port}; verify the upstream server is running."),
        default_upstream: Some(format!("http://127.0.0.1:{port}")),
        website_mode: "local reverse-proxy preview; public deployment remains separate",
    }
}

fn explicit_port(scripts: &str) -> Option<u16> {
    // Accept common `--port N`, `-p N`, `PORT=N` and `--port=N` shapes only.
    let words: Vec<&str> = scripts
        .split(|c: char| c.is_whitespace() || c == ';' || c == '&')
        .collect();
    for (index, word) in words.iter().enumerate() {
        let candidate = if let Some(value) = word.strip_prefix("--port=") {
            Some(value)
        } else if let Some(value) = word.strip_prefix("PORT=") {
            Some(value)
        } else if *word == "--port" || *word == "-p" {
            words.get(index + 1).copied()
        } else {
            None
        };
        if let Some(value) = candidate.and_then(|v| {
            v.trim_matches(|c| c == '"' || c == '\'' || c == ',')
                .parse::<u16>()
                .ok()
        }) {
            if value > 0 {
                return Some(value);
            }
        }
    }
    None
}

fn find_port_in_source_tree(root: &Path, needles: &[&str]) -> Option<u16> {
    fn walk(dir: &Path, depth: usize, needles: &[&str]) -> Option<u16> {
        if depth > 5 {
            return None;
        }
        let entries = fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy();
            if name.starts_with('.')
                || matches!(name.as_ref(), "vendor" | "node_modules" | "target" | "dist")
            {
                continue;
            }
            if path.is_dir() {
                if let Some(port) = walk(&path, depth + 1, needles) {
                    return Some(port);
                }
            } else if path.extension().is_some_and(|ext| ext == "go") {
                if let Ok(content) = fs::read_to_string(path) {
                    for needle in needles {
                        let mut remainder = content.as_str();
                        while let Some(index) = remainder.find(needle) {
                            let after = &remainder[index + needle.len()..];
                            if let Some(start) = after.find(':') {
                                let digits: String = after[start + 1..]
                                    .chars()
                                    .take_while(|c| c.is_ascii_digit())
                                    .collect();
                                if let Ok(port) = digits.parse::<u16>() {
                                    if port > 0 {
                                        return Some(port);
                                    }
                                }
                            }
                            remainder = after.get(1..).unwrap_or("");
                            if remainder.is_empty() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        None
    }
    walk(root, 0, needles)
}

fn detect_command(path: &Path) -> Result<()> {
    let root = canonical_project_root(path)?;
    let detection = detect(&root);
    println!("QUANTUM SHIELD — PROJECT DETECTION");
    println!("Project       : {}", root.display());
    println!("Platform      : {}", detection.platform);
    println!("Website mode  : {}", detection.website_mode);
    println!("Assessment    : {}", detection.explanation);
    println!();
    println!("Repository    : bounded repo-scan helper; Git hook is installed only if no user pre-commit hook exists.");
    println!("Software      : explicit CLI-only sandbox launcher; Bubblewrap must be available at run time.");
    println!("Website       : no application source/start scripts are rewritten; public routing is never assumed.");
    if let Some(upstream) = detection.default_upstream {
        println!("Suggested upstream: {upstream}");
    }
    println!();
    println!("Run `qsctl integrate install {}` to install reversible helpers; add `--upstream http://127.0.0.1:PORT` to override the detected local upstream.", root.display());
    Ok(())
}

fn install_command(path: &Path, upstream_override: Option<&str>) -> Result<()> {
    let root = canonical_project_root(path)?;
    let detection = detect(&root);
    let managed_dir = root.join(MANAGED_DIR);

    if fs::symlink_metadata(&managed_dir).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!(
            "{} is a symlink; refusing to install through it",
            managed_dir.display()
        );
    }
    if managed_dir.exists() {
        let existing = managed_dir.join(MANIFEST_NAME);
        if existing.is_file() {
            let manifest: Manifest = serde_json::from_slice(&fs::read(&existing)?)
                .context("existing Quantum Shield manifest is invalid; preserving files")?;
            if manifest.marker == MARKER
                && manifest.schema_version == 1
                && manifest.project_root == root.to_string_lossy().into_owned()
            {
                println!("Quantum Shield integrations are already installed. Run `qsctl integrate status {}`; no files overwritten.", root.display());
                return Ok(());
            }
        }
        bail!("{} already exists but is not a recognized Quantum Shield integration directory; no files changed", managed_dir.display());
    }

    let chosen_upstream = upstream_override
        .map(str::to_owned)
        .or(detection.default_upstream.clone());
    let website_upstream = if matches!(
        detection.platform.as_str(),
        "managed-vercel"
            | "docker-compose"
            | "static-site"
            | "javascript-static-or-client-rendered"
    ) {
        None
    } else {
        chosen_upstream.clone()
    };
    let mut files: Vec<(String, Vec<u8>, u32)> = Vec::new();
    let root_display = root.to_string_lossy().to_string();
    let qsctl = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("qsctl"));
    let qsctl_display = qsctl.to_string_lossy().to_string();
    let qsctl_shell = shell_single_quote(&qsctl_display);

    let readme = format!(
        "<!-- {MARKER} -->\n# Quantum Shield project integration\n\nProject: `{root_display}`\nDetected platform: `{platform}`\n\n## Installed helpers\n\n- `website-audit.sh URL`: run the existing passive HTTPS assessment without changing the deployment.\n- `repository-check.sh`: bounded repository scan; optional Git pre-commit hook runs report-first. Set `QS_BLOCK_COMMIT_ON_FINDINGS=1` to make findings fail the commit.\n- `software-shield.sh audit PATH`: audit an application directory; `software-shield.sh run EXECUTABLE [ARGS...]` runs a selected Linux CLI executable via the existing `sandbox-run` profile. It does not sandbox arbitrary GUI applications.\n{website_detail}\n## Important boundaries\n\nThese helpers do not rewrite application source, package manifests, or the original Compose file. A local gateway is not public protection by itself. To protect a public website, real requests must be routed through Quantum Shield using the supported deployment adapter and a domain/certificate setup you control. For Vercel/GoDaddy-hosted sites where the runtime cannot be changed, use passive `qsctl website-audit URL` or a separately supported edge integration.\n\nRemove generated integration files with `qsctl integrate remove .` from this project. Files edited since installation are preserved.\n",
        platform = detection.platform.clone(),
        website_detail = if website_upstream.is_some() {
            "- `website-shield.sh`: loopback-only local reverse-proxy preview. It chooses an OS-assigned port at bind time; it does not change the app's original port, startup command, DNS, or public traffic route."
        } else {
            "- Website gateway was not generated because a safe local upstream could not be inferred. Re-run install with `--upstream http://127.0.0.1:PORT` only for a loopback/private service you control, or use the existing Compose adapter for an eligible self-hosted deployment."
        }
    );
    files.push(("README.md".to_owned(), readme.into_bytes(), 0o600));

    let repo_script = format!(
        "#!/usr/bin/env bash\n# {MARKER}\nset -Eeuo pipefail\nROOT=\"$(cd -- \"$(dirname -- \"${{BASH_SOURCE[0]}}\")/..\" && pwd -P)\"\nQSCTL=\"${{QSCTL_BIN:-}}\"\nif [[ -z \"$QSCTL\" ]]; then QSCTL={qsctl_shell}; fi\nif [[ ! -x \"$QSCTL\" ]]; then QSCTL=\"$(command -v qsctl || true)\"; fi\nif [[ -z \"$QSCTL\" || ! -x \"$QSCTL\" ]]; then echo \"ERROR: qsctl not found. Build/install Quantum Shield or set QSCTL_BIN.\" >&2; exit 127; fi\necho \"Quantum Shield repository check: $ROOT\"\nif [[ \"${{QS_BLOCK_COMMIT_ON_FINDINGS:-0}}\" == \"1\" ]]; then exec \"$QSCTL\" repo-scan \"$ROOT\" --fail-on-findings; else exec \"$QSCTL\" repo-scan \"$ROOT\"; fi\n"
    );
    files.push((
        "repository-check.sh".to_owned(),
        repo_script.into_bytes(),
        0o700,
    ));

    let website_audit_script = format!(
        "#!/usr/bin/env bash\n# {MARKER}\nset -Eeuo pipefail\nif (($# < 1)); then echo \"Usage: $0 https://website.example [website-audit-options...]\" >&2; exit 2; fi\nQSCTL=\"${{QSCTL_BIN:-}}\"\nif [[ -z \"$QSCTL\" ]]; then QSCTL={qsctl_shell}; fi\nif [[ ! -x \"$QSCTL\" ]]; then QSCTL=\"$(command -v qsctl || true)\"; fi\nif [[ -z \"$QSCTL\" || ! -x \"$QSCTL\" ]]; then echo \"ERROR: qsctl not found. Build/install Quantum Shield or set QSCTL_BIN.\" >&2; exit 127; fi\nURL=\"$1\"; shift\nexec \"$QSCTL\" website-audit \"$URL\" \"$@\"\n"
    );
    files.push((
        "website-audit.sh".to_owned(),
        website_audit_script.into_bytes(),
        0o700,
    ));

    let software_script = format!(
        "#!/usr/bin/env bash\n# {MARKER}\nset -Eeuo pipefail\nif (($# < 1)); then echo \"Usage: $0 audit /path/to/app | run /path/to/cli [args...]\" >&2; echo \"For backwards compatibility, an executable path without 'run' starts that CLI in the sandbox. GUI applications are not supported by this wrapper.\" >&2; exit 2; fi\nMODE=run\ncase \"$1\" in audit) MODE=audit; shift ;; run) shift ;; esac\nQSCTL=\"${{QSCTL_BIN:-}}\"\nif [[ -z \"$QSCTL\" ]]; then QSCTL={qsctl_shell}; fi\nif [[ ! -x \"$QSCTL\" ]]; then QSCTL=\"$(command -v qsctl || true)\"; fi\nif [[ -z \"$QSCTL\" || ! -x \"$QSCTL\" ]]; then echo \"ERROR: qsctl not found. Build/install Quantum Shield or set QSCTL_BIN.\" >&2; exit 127; fi\nif [[ \"$MODE\" == audit ]]; then\n  (($# == 1)) || {{ echo \"Usage: $0 audit /path/to/app\" >&2; exit 2; }}\n  [[ -d \"$1\" ]] || {{ echo \"ERROR: application directory does not exist: $1\" >&2; exit 2; }}\n  exec \"$QSCTL\" app-audit \"$1\"\nfi\nif (($# < 1)); then echo \"Usage: $0 run /absolute/path/to/cli [args...]\" >&2; exit 2; fi\nEXECUTABLE=\"$1\"; shift\n[[ -f \"$EXECUTABLE\" && -x \"$EXECUTABLE\" ]] || {{ echo \"ERROR: executable does not exist or is not executable: $EXECUTABLE\" >&2; exit 2; }}\nexec \"$QSCTL\" sandbox-run \"$EXECUTABLE\" -- \"$@\"\n"
    );
    files.push((
        "software-shield.sh".to_owned(),
        software_script.into_bytes(),
        0o700,
    ));

    if upstream_override.is_some() && website_upstream.is_none() {
        println!("NOTE: the detected platform does not expose a server-side runtime adapter here; no website gateway config will be created.");
    }
    if let Some(upstream) = website_upstream.as_deref() {
        validate_local_gateway_upstream(upstream)?;
        let config_text = format!(
                "# {MARKER}\n# Local test gateway only. It never binds a public interface.\nschema_version = 1\n\n[[sites]]\nid = \"local-site\"\ndomain = \"localhost\"\nupstream = \"{}\"\n",
                escape_toml_string(upstream)
            );
        validate_generated_config(&config_text)?;
        files.push(("website.toml".to_owned(), config_text.into_bytes(), 0o600));
        let website_script = format!(
                "#!/usr/bin/env bash\n# {MARKER}\nset -Eeuo pipefail\nROOT=\"$(cd -- \"$(dirname -- \"${{BASH_SOURCE[0]}}\")/..\" && pwd -P)\"\nQSCTL=\"${{QSCTL_BIN:-}}\"\nif [[ -z \"$QSCTL\" ]]; then QSCTL={qsctl_shell}; fi\nif [[ ! -x \"$QSCTL\" ]]; then QSCTL=\"$(command -v qsctl || true)\"; fi\nif [[ -z \"$QSCTL\" || ! -x \"$QSCTL\" ]]; then echo \"ERROR: qsctl not found. Build/install Quantum Shield or set QSCTL_BIN.\" >&2; exit 127; fi\n\"$QSCTL\" validate \"$ROOT/{MANAGED_DIR}/website.toml\"\necho \"Starting loopback-only Quantum Shield gateway. Read the 'Listening on' line to get the OS-assigned port.\"\necho \"Use http://localhost:<port>/ so the Host header matches the generated localhost route.\"\necho \"This does not intercept traffic sent directly to the original app port or make a public deployment.\"\nexec \"$QSCTL\" serve-http \"$ROOT/{MANAGED_DIR}/website.toml\" --listen 127.0.0.1:0\n"
        );
        files.push((
            "website-shield.sh".to_owned(),
            website_script.into_bytes(),
            0o700,
        ));
    }

    let hook_path = git_hook_path(&root)?;
    let mut git_hook = None;
    if let Some(hook) = hook_path.as_ref() {
        if hook.exists() {
            let existing = fs::read_to_string(hook).unwrap_or_default();
            if existing.contains(MARKER) {
                println!(
                    "Existing Quantum Shield pre-commit hook already found; leaving it unchanged."
                );
            } else {
                println!("Existing user pre-commit hook detected; preserving it and not installing an automatic hook.");
            }
        } else {
            let hook_text = format!(
                "#!/usr/bin/env bash\n# {MARKER}\nset -Eeuo pipefail\nREPO_ROOT=\"$(git rev-parse --show-toplevel)\"\nexec \"$REPO_ROOT/{MANAGED_DIR}/repository-check.sh\"\n"
            );
            if let Some(parent) = hook.parent() {
                fs::create_dir_all(parent)?;
            }
            write_new_file(hook, hook_text.as_bytes(), 0o700)?;
            git_hook = Some(ManagedFile {
                relative_path: hook
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                drift_hash_fnv1a64: drift_hash(hook_text.as_bytes()),
            });
            println!(
                "Installed report-first Git pre-commit hook at {}.",
                hook.display()
            );
        }
    }

    fs::create_dir(&managed_dir)
        .with_context(|| format!("could not create {}", managed_dir.display()))?;
    let mut managed_files = Vec::new();
    for (name, contents, mode) in &files {
        let target = managed_dir.join(name);
        if let Err(error) = write_new_file(&target, contents, *mode) {
            // Roll back only files just created by this transaction.
            for item in &managed_files {
                let previous: &ManagedFile = item;
                let candidate = managed_dir.join(&previous.relative_path);
                if file_hash_matches(&candidate, &previous.drift_hash_fnv1a64) {
                    let _ = fs::remove_file(candidate);
                }
            }
            let _ = fs::remove_dir(&managed_dir);
            if let (Some(hook), Some(hook_record)) = (hook_path.as_ref(), git_hook.as_ref()) {
                if file_hash_matches(hook, &hook_record.drift_hash_fnv1a64) {
                    let _ = fs::remove_file(hook);
                }
            }
            return Err(error).with_context(|| format!("could not install {}", target.display()));
        }
        managed_files.push(ManagedFile {
            relative_path: name.clone(),
            drift_hash_fnv1a64: drift_hash(contents),
        });
    }

    let manifest = Manifest {
        marker: MARKER.to_owned(),
        schema_version: 1,
        project_root: root_display,
        detected_platform: detection.platform.clone(),
        files: managed_files,
        git_hook,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_path = managed_dir.join(MANIFEST_NAME);
    if let Err(error) = write_new_file(&manifest_path, &manifest_bytes, 0o600) {
        // Preserve an incomplete manifest-free directory for inspection rather than deleting any
        // file that may have been changed immediately after installation.
        return Err(error).context("integration files were created but the manifest could not be written; inspect .quantum-shield before retrying");
    }

    println!("\nQuantum Shield integration helpers installed.");
    println!("Project      : {}", root.display());
    println!("Platform     : {}", detection.platform);
    println!(
        "Managed files: {} in {}",
        managed_files_count(&manifest),
        managed_dir.display()
    );
    println!("Website      : {}", detection.website_mode);
    println!(
        "Repository   : run ./.quantum-shield/repository-check.sh; commit hook is report-first."
    );
    println!("Software     : run ./.quantum-shield/software-shield.sh /path/to/cli [args...].");
    if managed_dir.join("website-shield.sh").exists() {
        println!("Local gateway: run ./.quantum-shield/website-shield.sh; it binds loopback only and selects the port at bind time.");
    } else {
        println!("Local gateway: not generated (no safe/known web upstream or platform is managed/static).");
    }
    println!("Removal      : qsctl integrate remove {}", root.display());
    println!("Public traffic is NOT automatically rerouted by these helpers. Review .quantum-shield/README.md before deployment.");
    Ok(())
}

fn status_command(path: &Path) -> Result<()> {
    let root = canonical_project_root(path)?;
    let manifest_path = root.join(MANAGED_DIR).join(MANIFEST_NAME);
    if !manifest_path.is_file() {
        println!(
            "Quantum Shield integration: not installed in {}",
            root.display()
        );
        return Ok(());
    }
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("Quantum Shield integration manifest is invalid; no changes made")?;
    if manifest.marker != MARKER
        || manifest.schema_version != 1
        || manifest.project_root != root.to_string_lossy().into_owned()
    {
        bail!("integration manifest marker/schema/root mismatch; no changes made");
    }
    println!("Quantum Shield integration status");
    println!("Project : {}", root.display());
    println!("Platform: {}", manifest.detected_platform);
    let mut changed = 0;
    for item in &manifest.files {
        let target = safe_managed_target(&root, &item.relative_path)?;
        if file_hash_matches(&target, &item.drift_hash_fnv1a64) {
            println!(
                "OK      : {}",
                target.strip_prefix(&root).unwrap_or(&target).display()
            );
        } else {
            println!(
                "MISSING/EDITED: {} (will be preserved on remove)",
                target.strip_prefix(&root).unwrap_or(&target).display()
            );
            changed += 1;
        }
    }
    if let (Some(hook_record), Some(hook_path)) =
        (manifest.git_hook.as_ref(), git_hook_path(&root)?.as_ref())
    {
        if file_hash_matches(hook_path, &hook_record.drift_hash_fnv1a64) {
            println!(
                "OK      : managed Git pre-commit hook ({})",
                hook_path.display()
            );
        } else {
            println!(
                "MISSING/EDITED: Git pre-commit hook ({})",
                hook_path.display()
            );
            changed += 1;
        }
    }
    println!("Drifted files: {changed}");
    println!("Security note: drift hashes detect ordinary edits; they are not a tamper-proof attestation.");
    Ok(())
}

fn remove_command(path: &Path) -> Result<()> {
    let root = canonical_project_root(path)?;
    let managed_dir = root.join(MANAGED_DIR);
    if fs::symlink_metadata(&managed_dir).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!(
            "{} is a symlink; refusing to inspect it",
            managed_dir.display()
        );
    }
    let manifest_path = managed_dir.join(MANIFEST_NAME);
    if !manifest_path.is_file() {
        println!(
            "No Quantum Shield integration manifest at {}; no files removed.",
            manifest_path.display()
        );
        return Ok(());
    }
    let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("Quantum Shield integration manifest is invalid; refusing removal")?;
    if manifest.marker != MARKER
        || manifest.schema_version != 1
        || manifest.project_root != root.to_string_lossy().into_owned()
    {
        bail!("integration manifest marker/schema/root mismatch; refusing removal");
    }

    let mut removed = 0usize;
    let mut preserved = 0usize;
    for item in &manifest.files {
        let target = safe_managed_target(&root, &item.relative_path)?;
        if !target.exists() {
            continue;
        }
        if file_hash_matches(&target, &item.drift_hash_fnv1a64) {
            fs::remove_file(&target)
                .with_context(|| format!("could not remove managed file {}", target.display()))?;
            println!(
                "REMOVED : {}",
                target.strip_prefix(&root).unwrap_or(&target).display()
            );
            removed += 1;
        } else {
            println!(
                "PRESERVED: {} (edited since install)",
                target.strip_prefix(&root).unwrap_or(&target).display()
            );
            preserved += 1;
        }
    }

    if let Some(hook_record) = manifest.git_hook.as_ref() {
        if let Some(hook_path) = git_hook_path(&root)? {
            if hook_path.is_file() && file_hash_matches(&hook_path, &hook_record.drift_hash_fnv1a64)
            {
                fs::remove_file(&hook_path).with_context(|| {
                    format!("could not remove managed Git hook {}", hook_path.display())
                })?;
                println!("REMOVED : managed Git hook {}", hook_path.display());
                removed += 1;
            } else if hook_path.exists() {
                println!(
                    "PRESERVED: Git hook {} (missing or changed since install)",
                    hook_path.display()
                );
                preserved += 1;
            }
        }
    }

    // The manifest is a manager record, not an application file. Keep it if any managed file was
    // edited so a later status/removal attempt can still explain what remains.
    if preserved == 0 {
        fs::remove_file(&manifest_path)?;
        let _ = fs::remove_dir(&managed_dir);
    } else {
        println!(
            "PRESERVED: {} because edited managed files remain; remove those manually if desired.",
            manifest_path.display()
        );
    }
    println!("\nRemoval finished. Removed {removed}; preserved {preserved}. User application source/configuration was not rewritten.");
    Ok(())
}

fn validate_local_gateway_upstream(value: &str) -> Result<()> {
    let parsed = url::Url::parse(value).context("upstream must be an absolute HTTP URL")?;
    if parsed.scheme() != "http" || parsed.port().is_none() {
        bail!("local website preview requires http://loopback-host:PORT; HTTPS upstreams are not supported by this adapter");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("local website preview upstream must not contain credentials, query strings, or fragments");
    }
    if parsed.path() != "/" {
        bail!("local website preview accepts an origin URL only, without a path prefix");
    }
    let loopback = match parsed.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if !loopback {
        bail!("local website preview only connects to localhost/loopback. Docker service names must use the Docker Compose deployment adapter, and remote hosts are refused.");
    }
    if let Some(host) = parsed.host_str() {
        if let Ok(address) = host.parse::<IpAddr>() {
            if !address.is_loopback() {
                bail!("local website preview upstream IP must be loopback");
            }
        }
    }
    Ok(())
}

fn validate_generated_config(contents: &str) -> Result<()> {
    let cfg: crate::config::Config =
        toml::from_str(contents).context("generated website config is invalid TOML")?;
    cfg.validate().map_err(|errors| {
        anyhow::anyhow!(
            "generated website config failed validation: {}",
            errors.join("; ")
        )
    })
}

fn shell_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

fn escape_toml_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

fn write_new_file(path: &Path, contents: &[u8], unix_mode: u32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = unix_mode;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("refusing to overwrite existing file {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(unix_mode))?;
    }
    Ok(())
}

fn git_hook_path(root: &Path) -> Result<Option<PathBuf>> {
    if !root.join(".git").exists() {
        return Ok(None);
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-path", "hooks/pre-commit"])
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(_) => return Ok(None),
        Err(_) => return Ok(None),
    };
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    Ok(Some(path))
}

fn safe_managed_target(root: &Path, relative: &str) -> Result<PathBuf> {
    let rel = Path::new(relative);
    let mut components = rel.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("invalid managed filename in integration manifest; only top-level helper filenames are allowed");
    }
    let base = root.join(MANAGED_DIR);
    let target = base.join(rel);
    if !target.starts_with(&base) {
        bail!("managed path escapes integration directory");
    }
    Ok(target)
}

// Stable drift detector for accidental edits; explicitly not a cryptographic integrity check.
fn drift_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn file_hash_matches(path: &Path, expected: &str) -> bool {
    fs::read(path)
        .map(|bytes| drift_hash(&bytes) == expected)
        .unwrap_or(false)
}

fn managed_files_count(manifest: &Manifest) -> usize {
    manifest.files.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("qs-integrate-{label}-{}-{now}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn detects_next_and_default_port() {
        let root = temp_dir("next");
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"next":"15"},"scripts":{"start":"next start"}}"#,
        )
        .unwrap();
        let result = detect(&root);
        assert_eq!(result.platform, "Next.js-node");
        assert_eq!(
            result.default_upstream.as_deref(),
            Some("http://127.0.0.1:3000")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_script_port_overrides_framework_default() {
        assert_eq!(explicit_port("next start --port 3180"), Some(3180));
        assert_eq!(explicit_port("PORT=4201 npm run start"), Some(4201));
        assert_eq!(explicit_port("vite --port=4173"), Some(4173));
    }

    #[test]
    fn remove_preserves_managed_file_after_edit() {
        let root = temp_dir("edited");
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"next":"15"}}"#,
        )
        .unwrap();
        let managed = root.join(MANAGED_DIR);
        fs::create_dir(&managed).unwrap();
        let target = managed.join("README.md");
        fs::write(&target, "installed version").unwrap();
        let manifest = Manifest {
            marker: MARKER.to_owned(),
            schema_version: 1,
            project_root: root.canonicalize().unwrap().to_string_lossy().to_string(),
            detected_platform: "test".to_owned(),
            files: vec![ManagedFile {
                relative_path: "README.md".to_owned(),
                drift_hash_fnv1a64: drift_hash(b"installed version"),
            }],
            git_hook: None,
        };
        fs::write(
            managed.join(MANIFEST_NAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(&target, "user edited version").unwrap();
        assert!(!file_hash_matches(
            &target,
            &manifest.files[0].drift_hash_fnv1a64
        ));
        assert!(target.exists());
        remove_command(&root).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "user edited version");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_unmanaged_existing_integration_directory() {
        let root = temp_dir("conflict");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        fs::create_dir(root.join(MANAGED_DIR)).unwrap();
        fs::write(root.join(MANAGED_DIR).join("keep.txt"), "keep me").unwrap();
        assert!(install_command(&root, None).is_err());
        assert_eq!(
            fs::read_to_string(root.join(MANAGED_DIR).join("keep.txt")).unwrap(),
            "keep me"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_status_remove_lifecycle_is_reversible() {
        let root = temp_dir("lifecycle");
        fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"next":"15"},"scripts":{"start":"next start"}}"#,
        )
        .unwrap();
        install_command(&root, None).unwrap();
        assert!(root.join(MANAGED_DIR).join("manifest.json").is_file());
        assert!(root.join(MANAGED_DIR).join("website.toml").is_file());
        assert!(root.join(MANAGED_DIR).join("website-audit.sh").is_file());
        assert!(root.join(MANAGED_DIR).join("repository-check.sh").is_file());
        assert!(root.join(MANAGED_DIR).join("software-shield.sh").is_file());
        status_command(&root).unwrap();
        remove_command(&root).unwrap();
        assert!(!root.join(MANAGED_DIR).exists());
        assert!(root.join("package.json").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_gateway_config_accepts_loopback_and_rejects_remote_upstream() {
        let local = "schema_version = 1\n[[sites]]\nid = \"local-site\"\ndomain = \"localhost\"\nupstream = \"http://127.0.0.1:3000\"\n";
        assert!(validate_generated_config(local).is_ok());
        let remote = local.replace("http://127.0.0.1:3000", "http://example.org:3000");
        assert!(validate_generated_config(&remote).is_err());
        assert!(validate_local_gateway_upstream("http://web:3000").is_err());
        assert!(validate_local_gateway_upstream("http://127.0.0.1:3000").is_ok());
    }

    #[test]
    fn shell_single_quote_handles_spaces_and_apostrophes() {
        assert_eq!(
            shell_single_quote("/tmp/Quantum Shield's/qsctl"),
            "'/tmp/Quantum Shield'\\''s/qsctl'"
        );
    }
}
