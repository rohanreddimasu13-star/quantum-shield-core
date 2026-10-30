mod agents;
mod body_gate;
#[cfg(feature = "circuit_breaker")]
mod circuit_breaker;
mod config;
mod crypto;
mod deploy;
#[cfg(feature = "dlp")]
mod dlp;
mod integration;
mod key_management;
mod protect;
mod proxy;
#[cfg(target_os = "linux")]
mod sandbox;
#[cfg(not(target_os = "linux"))]
#[path = "sandbox_portable.rs"]
mod sandbox;
mod security;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "qsctl",
    version,
    about = "Quantum Shield — website, application, and repository security tools",
    long_about = "Quantum Shield combines a TLS reverse-proxy deployment adapter with passive website checks and read-only application/repository security scanning. These checks are bounded static/passive assessments, not a universal WAF or an independent security audit."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Detect, install, inspect, or remove reversible project integrations.
    Integrate {
        #[command(subcommand)]
        action: integration::IntegrationCommand,
    },
    /// Generate a short-lived DNS TXT challenge proving control of a public hostname.
    DomainChallenge {
        /// Public DNS hostname only, for example app.example.org.
        domain: String,
    },
    /// Verify a previously generated DNS TXT ownership challenge.
    DomainVerify {
        /// Public DNS hostname that has the challenge TXT record.
        domain: String,
    },
    /// Validate a Quantum Shield TOML config without changing anything.
    Validate {
        /// Path to the TOML configuration.
        config: PathBuf,
    },
    /// Show the proposed integration steps; performs no changes or network calls.
    Plan {
        /// Path to the TOML configuration.
        config: PathBuf,
    },
    /// Run the hardened HTTP prototype on loopback only. No TLS is provided.
    ServeHttp {
        /// Path to the TOML configuration.
        config: PathBuf,
        /// Loopback listener address. Defaults to 127.0.0.1:18082; non-loopback addresses are refused.
        #[arg(long, default_value = "127.0.0.1:18082")]
        listen: SocketAddr,
    },
    /// Run HTTPS using an existing PEM certificate and key. Public binding requires explicit opt-in.
    ServeHttps {
        /// Path to the validated TOML config.
        config: PathBuf,
        /// Listener address. Non-loopback addresses are refused unless --allow-public-listener is explicitly provided.
        #[arg(long, default_value = "127.0.0.1:18443")]
        listen: SocketAddr,
        /// PEM certificate chain (local test certificates are acceptable only for testing).
        #[arg(long)]
        cert: PathBuf,
        /// Unencrypted PEM private key; on Unix, group/other permissions must be disabled.
        #[arg(long)]
        key: PathBuf,
        /// Explicitly permit binding to non-loopback interfaces. Required for the Docker Compose adapter.
        #[arg(long)]
        allow_public_listener: bool,
        /// Internal Compose adapter handoff after host-side deployment authorization.
        #[arg(long, hide = true, requires = "allow_public_listener")]
        deployment_adapter: bool,
    },
    /// Prepare or apply an HTTPS edge-proxy adapter to an existing Docker Compose project. Use --local-test for loopback-only testing or explicitly acknowledge public exposure for a real deployment.
    DeployCompose {
        /// Validated Quantum Shield TOML configuration.
        config: PathBuf,
        /// Existing Compose file (compose.yaml, compose.yml, docker-compose.yml).
        #[arg(long)]
        compose_file: PathBuf,
        /// Existing PEM certificate chain. Supply with --key, or use --acme-email for automatic certificates.
        #[arg(long, requires = "key", conflicts_with = "acme_email")]
        cert: Option<PathBuf>,
        /// Matching PEM private key, protected from group/other access on Unix.
        #[arg(long, requires = "cert", conflicts_with = "acme_email")]
        key: Option<PathBuf>,
        /// Enable automatic ACME HTTP-01 issuance and renewal. Staging is the default.
        #[arg(long, conflicts_with_all = ["cert", "key", "local_test"])]
        acme_email: Option<String>,
        /// Persistent ACME account/certificate cache path. Defaults under $HOME/.local/state/quantum-shield/acme-{staging|production}.
        #[arg(long, requires = "acme_email")]
        acme_cache: Option<PathBuf>,
        /// Use Let's Encrypt production (real certificates). Requires a separate acknowledgement.
        #[arg(long, requires_all = ["acme_email", "acknowledge_production_issuance"])]
        production: bool,
        /// Acknowledge that production certificate orders will be created.
        #[arg(long, requires = "production")]
        acknowledge_production_issuance: bool,
        /// Actually start the HTTPS proxy after configuration validation. Without this flag, only generate and validate deployment files.
        #[arg(long)]
        apply: bool,
        /// Explicitly acknowledge that applying publishes public ports 80/443 (ACME) or 443 (supplied certificate).
        #[arg(long, conflicts_with = "local_test")]
        acknowledge_public_listener: bool,
        /// Apply only to loopback on a Docker-assigned host port; only available with an operator-supplied certificate.
        #[arg(long, conflicts_with_all = ["acknowledge_public_listener", "acme_email"])]
        local_test: bool,
        /// PEM client CA bundle for mutual TLS. Requires building qsctl with --features mTls.
        #[arg(long)]
        mtls_ca: Option<PathBuf>,
    },
    /// Print the compile-time feature set of this qsctl binary (deployment attestation).
    #[command(hide = true)]
    BuildFeatures,
    /// Validate ACME staging inputs without networking or filesystem changes.
    AcmePreflight {
        /// Path to the validated TOML config.
        config: PathBuf,
        /// Account contact email.
        #[arg(long)]
        email: String,
        /// Persistent staging cache path to use later; must be absolute.
        #[arg(long)]
        cache: Option<PathBuf>,
    },
    /// Run a Let's Encrypt STAGING-only ACME TLS-ALPN server. Requires a real domain and externally reachable TCP 443; production issuance is available only through the separately acknowledged HTTP-01 command.
    ServeAcmeStaging {
        /// Path to the validated TOML config; every configured site domain is included in the staging certificate request.
        config: PathBuf,
        /// Account contact email (used as ACME account contact).
        #[arg(long)]
        email: String,
        /// Listener address. If using port forwarding, map public TCP 443 to this local port.
        #[arg(long, default_value = "0.0.0.0:18443")]
        listen: SocketAddr,
        /// Persistent staging-only ACME account/certificate cache. Defaults under $HOME/.local/state/quantum-shield/acme-staging.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Required acknowledgement: this command opens a non-loopback listener. Use only with a disposable test upstream until the proxy receives a production security review.
        #[arg(long)]
        allow_public_listener: bool,
    },
    /// Run the HTTP-01 ACME reverse proxy with HTTP-to-HTTPS redirects and automatic certificate renewal. Staging is the default; production requires two explicit opt-ins.
    ServeAcmeHttp01 {
        /// Path to the validated TOML config; every configured domain is included in the certificate request.
        config: PathBuf,
        /// ACME account contact email.
        #[arg(long)]
        email: String,
        /// HTTP listener for HTTP-01 challenges and redirects. In Docker use 0.0.0.0:8080 and map host 80 to it.
        #[arg(long, default_value = "0.0.0.0:8080")]
        http_listen: SocketAddr,
        /// TLS listener for the proxy. In Docker use 0.0.0.0:18443 and map host 443 to it.
        #[arg(long, default_value = "0.0.0.0:18443")]
        https_listen: SocketAddr,
        /// Persistent account/certificate cache. Defaults to a mode-0700 directory under $HOME/.local/state/quantum-shield.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Use Let's Encrypt production. Staging remains the default.
        #[arg(long, requires = "acknowledge_production_issuance")]
        production: bool,
        /// Second acknowledgement required for real production certificate orders.
        #[arg(long, requires = "production")]
        acknowledge_production_issuance: bool,
        /// Explicit acknowledgement that this server opens non-loopback HTTP and HTTPS listeners.
        #[arg(long)]
        allow_public_listener: bool,
    },
    /// Read-only scan of a repository working tree for secret patterns and common unsafe configuration/code patterns.
    RepoScan {
        /// Repository root directory. Git history is not scanned.
        path: PathBuf,
        /// Maximum regular files to consider (hard-capped at 100,000).
        #[arg(long, default_value_t = 20_000)]
        max_files: usize,
        /// Maximum size of an individual text file in bytes (hard-capped at 10 MiB).
        #[arg(long, default_value_t = 2_097_152)]
        max_file_bytes: u64,
        /// Render JSON rather than human-readable text.
        #[arg(long)]
        json: bool,
        /// Write the report to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Return a non-zero exit status when at least one finding is present (useful in CI).
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// Static read-only security posture checks for a local application source/deployment directory.
    AppAudit {
        /// Application root directory. The app is never started and its code is never executed.
        path: PathBuf,
        /// Maximum regular files to consider (hard-capped at 100,000).
        #[arg(long, default_value_t = 20_000)]
        max_files: usize,
        /// Maximum size of an individual text file in bytes (hard-capped at 10 MiB).
        #[arg(long, default_value_t = 2_097_152)]
        max_file_bytes: u64,
        /// Render JSON rather than human-readable text.
        #[arg(long)]
        json: bool,
        /// Write the report to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Return a non-zero exit status when at least one finding is present (useful in CI).
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// Run a CLI executable using the current operating system sandbox backend; network sharing is opt-in.
    SandboxRun {
        /// Executable file (absolute or relative to the current directory).
        executable: PathBuf,
        /// Mount this clean application directory read-only; executable must be inside it.
        #[arg(long)]
        app_dir: Option<PathBuf>,
        /// Explicit host directory mounted writable inside the sandbox. Must not overlap the app/executable.
        #[arg(long)]
        writable_dir: Option<PathBuf>,
        /// Explicitly share the host network namespace. Use only for software that needs network access.
        #[arg(long)]
        share_network: bool,
        /// Resource profile: strict, balanced (default), or developer.
        #[arg(long, value_parser = ["strict", "balanced", "developer"], default_value = "balanced")]
        profile: String,
        /// Arguments passed directly to the program, without a shell; place them after `--`.
        #[arg(last = true, value_name = "ARG")]
        args: Vec<OsString>,
    },
    /// Passive HTTPS/header assessment of a website. Requires curl and issues a HEAD request only.
    WebsiteAudit {
        /// Absolute http:// or https:// URL. Do not include query parameters, fragments or credentials.
        url: String,
        /// curl total request timeout in seconds, clamped to 3–60 seconds.
        #[arg(long, default_value_t = 15)]
        timeout_seconds: u64,
        /// Render JSON rather than human-readable text.
        #[arg(long)]
        json: bool,
        /// Write the report to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Return a non-zero exit status when at least one finding is present (useful in CI).
        #[arg(long)]
        fail_on_findings: bool,
    },
    /// Scan secret patterns across commits reachable from local Git refs.
    GitHistoryScan {
        /// Repository root directory (must contain .git).
        path: PathBuf,
        /// Render JSON rather than human-readable text.
        #[arg(long)]
        json: bool,
        /// Write the report to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run cargo-audit if available to check dependencies for advisories.
    CargoAudit {
        /// Repository/project root directory containing Cargo.lock.
        path: PathBuf,
        /// Render JSON rather than human-readable text.
        #[arg(long)]
        json: bool,
        /// Write the report to this path instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate an AES-256-GCM key in the local private key store.
    KeyGenerate {
        #[arg(long)]
        id: String,
    },
    /// List local key IDs and their revocation status; never displays key material.
    KeyList,
    /// Encrypt a file into a new private output file. The plaintext source is retained.
    EncryptFile {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt a Quantum Shield encrypted file into a new private output file.
    DecryptFile {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Encrypt an application payload with an authenticated, stable context label.
    EncryptPayload {
        #[arg(long)]
        key_id: String,
        /// Non-secret label, e.g. customer-record:v1.
        #[arg(long)]
        context: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt an application payload using the original context label.
    DecryptPayload {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        context: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a key wrapped using a passphrase-derived key.
    KeyWrap {
        #[arg(long)]
        id: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import a passphrase-wrapped key. The ID must not already exist.
    KeyUnwrap {
        #[arg(long)]
        id: String,
        #[arg(long)]
        input: PathBuf,
    },
    /// Revoke a key for new encryption.
    KeyRevoke {
        #[arg(long)]
        id: String,
    },
    /// Display the local key-management audit log.
    KeyAudit,

    /// Unified protection workflow for local artifacts and website TLS.
    Protect {
        /// auto-detect a local file/repository/application, or select a target explicitly.
        #[arg(long, value_parser = ["auto", "file", "repository", "application", "website", "os", "cloud-server"], default_value = "auto")]
        kind: String,
        /// Source file or directory for local protection.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Existing Quantum Shield encryption key ID for local targets.
        #[arg(long)]
        key_id: Option<String>,
        /// New encrypted output path; it must not already exist.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Website adapter: validated Quantum Shield TOML configuration.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Website adapter: existing Docker Compose file.
        #[arg(long)]
        compose_file: Option<PathBuf>,
        /// Website adapter: existing PEM certificate chain.
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Website adapter: matching PEM private key.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Actually apply/start the website proxy; otherwise prepare/validate only.
        #[arg(long)]
        apply: bool,
        /// Explicitly acknowledge public exposure for an actual public deployment.
        #[arg(long, conflicts_with = "local_test")]
        acknowledge_public_listener: bool,
        /// Use the loopback-only website test mode.
        #[arg(long, conflicts_with = "acknowledge_public_listener")]
        local_test: bool,
        /// Simulate OS/cloud protection without touching disks or cloud resources.
        #[arg(long)]
        simulate: bool,
        /// Limit cloud simulation to one provider (defaults to all three).
        #[arg(long, value_parser = ["aws", "gcp", "azure"])]
        provider: Option<String>,
    },

    /// Show what this build can and cannot do on this machine.
    Doctor,
}

/// Compile-time feature identity, consumed by deployment attestation.
#[allow(unused_mut, clippy::vec_init_then_push)]
fn build_feature_list() -> String {
    let mut features: Vec<&'static str> = Vec::new();
    #[cfg(feature = "mTls")]
    features.push("mTls");
    #[cfg(feature = "dlp")]
    features.push("dlp");
    #[cfg(feature = "body_gate")]
    features.push("body_gate");
    #[cfg(feature = "prometheus")]
    features.push("prometheus");
    #[cfg(feature = "circuit_breaker")]
    features.push("circuit_breaker");
    features.join(",")
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildFeatures => {
            println!("{}", build_feature_list());
        }
        Commands::Integrate { action } => integration::run(action)?,
        Commands::DomainChallenge { domain } => create_domain_challenge(&domain)?,
        Commands::DomainVerify { domain } => verify_domain_challenge(&domain)?,
        Commands::Validate { config: path } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            println!(
                "OK: {} site(s) validated. No system changes made.",
                cfg.sites.len()
            );
        }
        Commands::Plan { config: path } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            println!("QUANTUM SHIELD — READ-ONLY INTEGRATION PLAN");
            println!("================================================");
            println!("Configuration: {}", path.display());
            println!("Sites: {}", cfg.sites.len());
            println!();

            for (index, site) in cfg.sites.iter().enumerate() {
                println!("{}. {}", index + 1, site.id);
                println!("   Public hostname : {}", site.domain);
                println!("   Local upstream  : {}", site.upstream);
                println!("   Planned action  : Docker Compose TLS edge; choose a supplied certificate or ACME HTTP-01 with persistent renewal cache");
                if site.domain == "example.com" || site.domain.ends_with(".example.com") {
                    println!("   Warning         : sample hostname; replace it before deployment");
                }
                println!();
            }

            println!("Preconditions the installer must verify before making changes:");
            println!("  - DNS A/AAAA records point to the intended host (not checked here).");
            println!("  - The operator controls the hostname and has permission to configure it.");
            println!("  - Required ports and firewall rules are available (not checked here).");
            println!("  - Compose can use a supplied certificate or ACME HTTP-01; ACME requires public DNS and routed TCP/80 and TCP/443.");
            println!("  - Local test binds only to 127.0.0.1 on a Docker-assigned host port and permits self-signed health checks for isolated tests.");
            println!();
            println!("SAFE MODE: this command made no files, network requests, or system changes.");
        }
        Commands::ServeHttp {
            config: path,
            listen,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            proxy::serve_http(cfg, listen).await?;
        }
        Commands::ServeHttps {
            config: path,
            listen,
            cert,
            key,
            allow_public_listener,
            deployment_adapter,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            validate_deployment_adapter_context(
                deployment_adapter,
                Path::new("/.dockerenv").is_file(),
            )?;
            if allow_public_listener && !deployment_adapter {
                require_recent_domain_proof(&cfg)?;
            }
            proxy::serve_https(cfg, listen, &cert, &key, allow_public_listener).await?;
        }
        Commands::DeployCompose {
            config: path,
            compose_file,
            cert,
            key,
            acme_email,
            acme_cache,
            production,
            acknowledge_production_issuance,
            apply,
            acknowledge_public_listener,
            local_test,
            mtls_ca,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            if apply && !local_test && acknowledge_public_listener {
                require_recent_domain_proof(&cfg)?;
            }
            let cache_path = if acme_email.is_some() {
                Some(match acme_cache {
                    Some(path) => path,
                    None => default_acme_cache_dir_for(production)?,
                })
            } else {
                None
            };
            let acme_options =
                acme_email
                    .as_deref()
                    .zip(cache_path.as_deref())
                    .map(|(email, cache_dir)| deploy::AcmeComposeOptions {
                        email,
                        cache_dir,
                        production,
                        acknowledge_production_issuance,
                    });
            deploy::deploy_compose(
                &cfg,
                &compose_file,
                cert.as_deref(),
                key.as_deref(),
                apply,
                acknowledge_public_listener,
                local_test,
                acme_options,
                mtls_ca.as_deref(),
            )?;
        }
        Commands::AcmePreflight {
            config: path,
            email,
            cache,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            let cache_dir = match cache {
                Some(path) => path,
                None => default_acme_cache_dir()?,
            };
            proxy::acme_staging_preflight(&cfg, &email, &cache_dir)?;
        }
        Commands::ServeAcmeStaging {
            config: path,
            email,
            listen,
            cache,
            allow_public_listener,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            if allow_public_listener {
                require_recent_domain_proof(&cfg)?;
            }
            let cache_dir = match cache {
                Some(path) => path,
                None => default_acme_cache_dir()?,
            };
            proxy::serve_acme_staging(cfg, listen, &email, &cache_dir, allow_public_listener)
                .await?;
        }
        Commands::ServeAcmeHttp01 {
            config: path,
            email,
            http_listen,
            https_listen,
            cache,
            production,
            acknowledge_production_issuance,
            allow_public_listener,
        } => {
            let cfg = load_config(&path)?;
            validate(&cfg)?;
            if allow_public_listener {
                require_recent_domain_proof(&cfg)?;
            }
            let cache_dir = match cache {
                Some(path) => path,
                None => default_acme_cache_dir_for(production)?,
            };
            proxy::serve_acme_http01(
                cfg,
                http_listen,
                https_listen,
                &email,
                &cache_dir,
                production,
                allow_public_listener,
                acknowledge_production_issuance,
            )
            .await?;
        }
        Commands::RepoScan {
            path,
            max_files,
            max_file_bytes,
            json,
            output,
            fail_on_findings,
        } => {
            let report = security::repository_scan(&path, max_files, max_file_bytes)?;
            let count = security::emit_report(&report, json, output.as_deref())?;
            if fail_on_findings && count > 0 {
                bail!("repository scan found {count} item(s); CI failure requested with --fail-on-findings");
            }
        }
        Commands::AppAudit {
            path,
            max_files,
            max_file_bytes,
            json,
            output,
            fail_on_findings,
        } => {
            let report = security::application_audit(&path, max_files, max_file_bytes)?;
            let count = security::emit_report(&report, json, output.as_deref())?;
            if fail_on_findings && count > 0 {
                bail!("application audit found {count} item(s); CI failure requested with --fail-on-findings");
            }
        }
        Commands::SandboxRun {
            executable,
            app_dir,
            writable_dir,
            share_network,
            profile,
            args,
        } => {
            sandbox::exec_sandboxed(
                &executable,
                app_dir.as_deref(),
                writable_dir.as_deref(),
                share_network,
                &args,
                &profile,
            )?;
        }
        Commands::WebsiteAudit {
            url,
            timeout_seconds,
            json,
            output,
            fail_on_findings,
        } => {
            let report = security::website_audit(&url, timeout_seconds)?;
            let count = security::emit_report(&report, json, output.as_deref())?;
            if fail_on_findings && count > 0 {
                bail!("website audit found {count} item(s); CI failure requested with --fail-on-findings");
            }
        }
        Commands::GitHistoryScan { path, json, output } => {
            let report = security::git_history_scan(&path)?;
            if json {
                let payload = serde_json::to_string_pretty(&report)?;
                if let Some(out_path) = output {
                    std::fs::write(&out_path, payload)?;
                    println!("Wrote Git history scan report to {}", out_path.display());
                } else {
                    println!("{}", payload);
                }
            } else {
                println!("Git history scan: {}", report.status);
                for note in &report.notes {
                    println!("  - {}", note);
                }
                for finding in &report.findings {
                    println!(
                        "  [{}] {}: {}",
                        finding.severity, finding.rule_id, finding.title
                    );
                    if let Some(loc) = &finding.location {
                        println!("      {}", loc);
                    }
                    println!("      {}", finding.recommendation);
                }
                if let Some(out_path) = output {
                    let payload = serde_json::to_string_pretty(&report)?;
                    std::fs::write(&out_path, payload)?;
                    println!("Wrote Git history scan report to {}", out_path.display());
                }
            }
        }
        Commands::CargoAudit { path, json, output } => {
            let report = security::cargo_audit_scan(&path)?;
            if json {
                let payload = serde_json::to_string_pretty(&report)?;
                if let Some(out_path) = output {
                    std::fs::write(&out_path, payload)?;
                    println!("Wrote cargo-audit report to {}", out_path.display());
                } else {
                    println!("{}", payload);
                }
            } else {
                println!("Cargo audit: {}", report.status);
                for note in &report.notes {
                    println!("  - {}", note);
                }
                if let Some(out_path) = output {
                    let payload = serde_json::to_string_pretty(&report)?;
                    std::fs::write(&out_path, payload)?;
                    println!("Wrote cargo-audit report to {}", out_path.display());
                }
            }
        }
        Commands::KeyGenerate { id } => {
            let path = crypto::generate_key(&id)?;
            println!("Created encryption key '{id}' at {}", path.display());
        }
        Commands::KeyList => {
            let ids = crypto::list_keys()?;
            if ids.is_empty() {
                println!("No local encryption keys found.");
            } else {
                for id in ids {
                    println!("{id}");
                }
            }
        }
        Commands::EncryptFile {
            key_id,
            input,
            output,
        } => {
            crypto::encrypt_file(&key_id, &input, &output)?;
            println!("Encrypted file written to {}", output.display());
        }
        Commands::DecryptFile {
            key_id,
            input,
            output,
        } => {
            crypto::decrypt_file(&key_id, &input, &output)?;
            println!("Decrypted file written to {}", output.display());
        }
        Commands::EncryptPayload {
            key_id,
            context,
            input,
            output,
        } => {
            crypto::encrypt_payload_file(&key_id, &input, &output, context.as_bytes())?;
            println!("Encrypted payload written to {}", output.display());
        }
        Commands::DecryptPayload {
            key_id,
            context,
            input,
            output,
        } => {
            crypto::decrypt_payload_file(&key_id, &input, &output, context.as_bytes())?;
            println!("Decrypted payload written to {}", output.display());
        }
        Commands::KeyWrap { id, output } => {
            key_management::wrap_key(&id, &output)?;
            println!("Wrapped key written to {}", output.display());
        }
        Commands::KeyUnwrap { id, input } => {
            key_management::unwrap_key(&id, &input)?;
            println!("Imported key '{id}'.");
        }
        Commands::KeyRevoke { id } => {
            key_management::revoke_key(&id)?;
            println!("Key '{id}' revoked for new encryption.");
        }
        Commands::KeyAudit => {
            print!("{}", key_management::read_audit_log()?);
        }
        Commands::Protect {
            kind,
            path,
            key_id,
            output,
            config,
            compose_file,
            cert,
            tls_key,
            apply,
            acknowledge_public_listener,
            local_test,
            simulate,
            provider,
        } => {
            let target_kind = if kind == "auto" {
                if config.is_some() || compose_file.is_some() || cert.is_some() || tls_key.is_some()
                {
                    "website".to_owned()
                } else {
                    protect::detect_local_kind(
                        path.as_deref()
                            .context("--path is required for automatic local-target detection")?,
                    )?
                    .to_owned()
                }
            } else {
                kind
            };

            if simulate {
                match target_kind.as_str() {
                    "os" => protect::simulate_protection("os", None)?,
                    "cloud-server" => {
                        protect::simulate_protection("cloud-server", provider.as_deref())?
                    }
                    _ => {
                        bail!("--simulate currently supports --kind os or --kind cloud-server only")
                    }
                }
                return Ok(());
            }

            match target_kind.as_str() {
                "file" | "repository" | "application" => {
                    if config.is_some()
                        || compose_file.is_some()
                        || cert.is_some()
                        || tls_key.is_some()
                        || apply
                        || acknowledge_public_listener
                        || local_test
                    {
                        bail!("website-only options cannot be combined with local artifact protection");
                    }
                    protect::protect_local(
                        &target_kind,
                        path.as_deref()
                            .context("--path is required for local protection")?,
                        key_id
                            .as_deref()
                            .context("--key-id is required for local protection")?,
                        output
                            .as_deref()
                            .context("--output is required for local protection")?,
                    )?;
                }
                "website" => {
                    if path.is_some() || key_id.is_some() || output.is_some() {
                        bail!("website protection uses --config, --compose-file, --cert, and --tls-key, not --path/--key-id/--output");
                    }
                    let config_path = config.context("website target requires --config")?;
                    let compose_path =
                        compose_file.context("website target requires --compose-file")?;
                    let cert_path =
                        cert.context("website target currently requires an existing --cert")?;
                    let tls_key_path = tls_key
                        .context("website target currently requires its matching --tls-key")?;

                    let cfg = load_config(&config_path)?;
                    validate(&cfg)?;
                    if apply && !local_test && acknowledge_public_listener {
                        require_recent_domain_proof(&cfg)?;
                    }
                    deploy::deploy_compose(
                        &cfg,
                        &compose_path,
                        Some(&cert_path),
                        Some(&tls_key_path),
                        apply,
                        acknowledge_public_listener,
                        local_test,
                        None,
                        None,
                    )?;
                    println!("Website adapter: HTTPS edge proxy configured/validated.");
                    println!("Scope: protects traffic through this proxy; it does not encrypt website files or databases.");
                }
                "os" => {
                    bail!("BLOCKED: native OS full-disk encryption is not implemented by this build. No changes were made. Use the operating system's supported disk-encryption workflow with verified recovery material.");
                }
                "cloud-server" => {
                    bail!("BLOCKED: cloud-provider disk/key-management adapters are not implemented by this build. No changes were made. Provider identity, permissions, recovery and rollback must be configured through a supported provider-specific adapter.");
                }
                _ => bail!("unsupported protection target"),
            }
        }
        Commands::Doctor => {
            println!("QUANTUM SHIELD DOCTOR");
            println!("=====================");
            println!("Build version : {}", env!("CARGO_PKG_VERSION"));
            println!("Operating OS  : {}", std::env::consts::OS);
            println!("Architecture  : {}", std::env::consts::ARCH);
            println!("Runtime mode  : HTTP/HTTPS reverse proxy; ACME HTTP-01 staging by default with explicit production opt-in");
            println!();
            println!("Implemented:");
            println!("  - Website module: TLS edge (Compose/direct HTTPS modes) plus passive HTTPS/header assessment via the website-audit command");
            println!("  - Application module: read-only manifest/configuration posture checks via app-audit");
            #[cfg(target_os = "linux")]
            println!("  - Software Shield CLI baseline sandbox via `sandbox-run` (Bubblewrap required; no network by default; selected app directory is read-only)");
            println!("  - Repository module: bounded current-working-tree secret-pattern and unsafe-configuration scan via repo-scan");
            println!("  - Git-history scan: all commits reachable from local refs, streamed without a fixed commit-count limit; no remote fetch");
            println!("  - Strict TOML schema parsing and route validation");
            println!("  - Loopback-only HTTP reverse proxy prototype");
            println!("  - HTTPS listener with operator-supplied PEM certificate/key; public binds require explicit opt-in");
            println!("  - Docker Compose TLS adapter with isolated overlay, existing-certificate validation, health check, and proxy-only rollback");
            println!("  - File and context-bound payload encryption CLI; Compose does not automatically encrypt upstream volumes or databases");
            println!("  - ACME HTTP-01 challenge handler, HTTPS redirects, persistent account/certificate cache, and renewal through the polled incoming stream");
            println!("  - Supplied-certificate HTTPS hot reload for new handshakes; existing TLS connections are not restarted");
            println!("  - Docker Compose json-file log rotation: max-size=10m, max-file=3");
            println!("  - Rustls AWS-LC provider with post-quantum key-exchange preference enabled by build features");
            println!("  - Logs the TLS protocol and negotiated key-exchange group for each completed handshake");
            println!("  - Reversible project integration manager: `qsctl integrate detect/install/status/remove PATH`");
            println!("  - Integration helpers do not rewrite app source; local gateway previews bind loopback only; public routing remains explicit");
            println!("  - Exact Host routing and hop-by-hop header filtering");
            println!("  - Request header byte/count limits and header read timeout");
            println!("  - Bounded active connections and short overload response");
            println!("  - Upstream connect and request/response timeouts");
            println!("  - Bounded idle upstream connection pool");
            println!("  - Ctrl+C shutdown with bounded drain window");
            println!("  - Replaced untrusted forwarding metadata");
            println!("  - Enforces a cumulative 16 MiB request-body cap while streaming, even if the upstream responds early");
            println!("  - Bounds request-body idle/total duration and uses a bounded body channel");
            println!("  - Withholds upstream responses until the inbound body is validated");
            println!("  - Rejects upstream early responses if the complete request body was not forwarded");
            println!();
            println!("Not implemented:");
            println!("  - Comprehensive SAST/data-flow analysis, authenticated dynamic testing, universal runtime instrumentation, and guaranteed vulnerability discovery");
            println!("  - Universal desktop GUI sandbox integration, syscall allowlist, resource quotas, and application-specific sandbox profiles; sandbox-run is a baseline CLI isolation profile only");
            println!("  - Universal platform support, WebSocket upgrades, HTTP/2, and independent security audit; per-client IP rate limiting is implemented with bounded process-local state");
            println!("  - Automated enforcement that clients negotiated hybrid post-quantum key exchange; inspect handshake logs instead");
            println!("  - Existing Caddy/NGINX/Apache/systemd adapters; the Compose adapter uses a separate overlay rather than editing the base file");
            println!("  - Automatic encryption of arbitrary upstream databases and Docker volumes; application persistence must explicitly use the payload API");
            println!();
            println!("HTTP-only mode refuses public binds. HTTPS/ACME/Compose public exposure requires explicit acknowledgement; production ACME additionally requires --production --acknowledge-production-issuance.");
        }
    }

    Ok(())
}

fn default_acme_cache_dir() -> Result<PathBuf> {
    default_acme_cache_dir_for(false)
}

fn default_acme_cache_dir_for(production: bool) -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set; pass --cache with an absolute path")?;
    let profile = if production {
        "acme-production"
    } else {
        "acme-staging"
    };
    Ok(home
        .join(".local")
        .join("state")
        .join("quantum-shield")
        .join(profile))
}

fn load_config(path: &Path) -> Result<config::Config> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("could not open config file {}", path.display()))?;
    // Bound input size so a malformed or unexpectedly large config cannot consume unbounded RAM.
    let mut contents = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("could not read config file {} as UTF-8", path.display()))?;
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        bail!(
            "config file exceeds the 1 MiB size limit: {}",
            path.display()
        );
    }
    let parsed: config::Config = toml::from_str(&contents)
        .with_context(|| format!("could not parse TOML config {}", path.display()))?;
    Ok(parsed)
}

fn validate(cfg: &config::Config) -> Result<()> {
    if let Err(errors) = cfg.validate() {
        let details = errors
            .into_iter()
            .map(|message| format!("  - {message}"))
            .collect::<Vec<_>>()
            .join("\n");
        bail!("configuration is invalid:\n{details}");
    }
    Ok(())
}

const DOMAIN_CHALLENGE_TTL_SECS: u64 = 30 * 60;
const DOMAIN_PROOF_TTL_SECS: u64 = 60 * 60;
const DOMAIN_PROOF_TXT_PREFIX: &str = "quantum-shield=";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainProofRecord {
    domain: String,
    token: String,
    created_at: u64,
    verified_at: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DomainProofStore {
    records: Vec<DomainProofRecord>,
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn normalize_proof_domain(value: &str) -> Result<String> {
    config::validate_public_domain(value).map_err(|err| anyhow::anyhow!(err))?;
    Ok(value.trim_end_matches('.').to_ascii_lowercase())
}

fn domain_proof_store_path() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                bail!("XDG_STATE_HOME must be an absolute path");
            }
            path
        }
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set; set XDG_STATE_HOME to an absolute private state directory")?
            .join(".local")
            .join("state"),
    };
    Ok(base.join("quantum-shield").join("domain-verification.json"))
}

fn load_domain_proof_store() -> Result<DomainProofStore> {
    let path = domain_proof_store_path()?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DomainProofStore::default())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "domain proof state must be a regular, non-symlink file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "domain proof state permissions are too broad; expected owner-only access on {}",
                path.display()
            );
        }
    }
    if metadata.len() > 1024 * 1024 {
        bail!("domain proof state exceeds the 1 MiB limit");
    }
    let content =
        std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&content)
        .with_context(|| format!("invalid domain proof state in {}", path.display()))
}

fn save_domain_proof_store(store: &DomainProofStore) -> Result<()> {
    let path = domain_proof_store_path()?;
    let parent = path
        .parent()
        .context("domain proof state has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create state directory {}", parent.display()))?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .with_context(|| format!("cannot inspect state directory {}", parent.display()))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!(
            "domain proof state directory must be a real directory, not a symlink: {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot secure state directory {}", parent.display()))?;
    }
    let tmp = parent.join(format!(
        ".domain-verification.json.tmp-{}",
        std::process::id()
    ));
    let bytes = serde_json::to_vec_pretty(store).context("cannot serialize domain proof state")?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> Result<()> {
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("cannot create private temp state {}", tmp.display()))?;
        file.write_all(&bytes)
            .context("cannot write domain proof state")?;
        file.sync_all().context("cannot sync domain proof state")?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("cannot atomically update {}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
}

fn random_domain_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("cannot access the operating system random source (/dev/urandom)")?
        .read_exact(&mut bytes)
        .context("cannot read secure random bytes")?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as FmtWrite;
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn create_domain_challenge(input: &str) -> Result<()> {
    let domain = normalize_proof_domain(input)?;
    let now = unix_now()?;
    let token = random_domain_token()?;
    let mut store = load_domain_proof_store()?;
    store.records.retain(|record| record.domain != domain);
    if store.records.len() >= 256 {
        bail!("the local proof store has 256 entries; verify or clear old entries before creating another challenge");
    }
    store.records.push(DomainProofRecord {
        domain: domain.clone(),
        token: token.clone(),
        created_at: now,
        verified_at: None,
    });
    save_domain_proof_store(&store)?;
    println!("QUANTUM SHIELD — DNS OWNERSHIP CHALLENGE");
    println!("Domain: {domain}");
    println!("TXT record name: _quantum-shield-challenge.{domain}");
    println!("TXT record value: {DOMAIN_PROOF_TXT_PREFIX}{token}");
    println!("Expires in 30 minutes. Add this TXT record in your authoritative DNS, wait for propagation, then run:");
    println!("  qsctl domain-verify {domain}");
    println!("This proves DNS control only; it does not authorize or perform deployment.");
    Ok(())
}

fn verify_domain_challenge(input: &str) -> Result<()> {
    let domain = normalize_proof_domain(input)?;
    let now = unix_now()?;
    let mut store = load_domain_proof_store()?;
    let record = store
        .records
        .iter_mut()
        .find(|record| record.domain == domain)
        .context(
            "no challenge exists for this domain; run `qsctl domain-challenge <domain>` first",
        )?;
    if record.verified_at.is_some() || record.token.is_empty() {
        bail!(
            "this challenge has already been used; create a fresh challenge before verifying again"
        );
    }
    if now < record.created_at || now.saturating_sub(record.created_at) > DOMAIN_CHALLENGE_TTL_SECS
    {
        bail!("the DNS challenge has expired; create a fresh challenge");
    }
    let record_name = format!("_quantum-shield-challenge.{domain}");
    let output = Command::new("dig")
        .arg("+time=3")
        .arg("+tries=1")
        .arg("+short")
        .arg("TXT")
        .arg(&record_name)
        .output()
        .context("DNS TXT verification needs the `dig` command (install bind-utils/dnsutils for your distribution)")?;
    if !output.status.success() {
        bail!(
            "dig could not resolve the DNS TXT record for {record_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let expected = format!("{DOMAIN_PROOF_TXT_PREFIX}{}", record.token);
    let answer = String::from_utf8_lossy(&output.stdout);
    let found = answer
        .lines()
        .any(|line| line.split('"').any(|part| part.trim() == expected));
    if !found {
        bail!("the expected TXT value was not found at {record_name}; check the exact value and DNS propagation, then retry before the challenge expires");
    }
    record.verified_at = Some(now);
    record.token.clear(); // The one-time challenge cannot be reused after successful verification.
    save_domain_proof_store(&store)?;
    println!("VERIFIED: DNS control of {domain} confirmed.");
    println!("This proof is valid for public-listener gating for up to one hour. Deployment still requires separate explicit authorization.");
    Ok(())
}

fn is_recent_domain_proof(record: &DomainProofRecord, now: u64) -> bool {
    record
        .verified_at
        .is_some_and(|verified_at| now >= verified_at && now - verified_at <= DOMAIN_PROOF_TTL_SECS)
}

fn validate_deployment_adapter_context(
    deployment_adapter: bool,
    running_in_container: bool,
) -> Result<()> {
    if deployment_adapter && !running_in_container {
        bail!(
            "--deployment-adapter is reserved for the generated Docker container;              use deploy-compose so host-side DNS ownership checks are enforced"
        );
    }
    Ok(())
}

fn require_recent_domain_proof(config: &config::Config) -> Result<()> {
    let now = unix_now()?;
    let store = load_domain_proof_store()?;
    for site in &config.sites {
        let domain = normalize_proof_domain(&site.domain)?;
        let verified = store
            .records
            .iter()
            .any(|record| record.domain == domain && is_recent_domain_proof(record, now));
        if !verified {
            bail!("public deployment blocked: no fresh DNS ownership proof for '{}'. Run `qsctl domain-challenge {}`; add the displayed TXT record; then run `qsctl domain-verify {}` and retry. Local test mode is not affected.", domain, domain, domain);
        }
    }
    Ok(())
}

#[cfg(test)]
mod domain_proof_tests {
    use super::*;

    #[test]
    fn deployment_adapter_flag_is_rejected_outside_container() {
        assert!(validate_deployment_adapter_context(true, false).is_err());
        assert!(validate_deployment_adapter_context(true, true).is_ok());
        assert!(validate_deployment_adapter_context(false, false).is_ok());
    }

    #[test]
    fn normalize_proof_domain_accepts_valid_domain() {
        assert_eq!(
            normalize_proof_domain("App.Example.com.").unwrap(),
            "app.example.com"
        );
    }

    #[test]
    fn normalize_proof_domain_rejects_localhost() {
        assert!(normalize_proof_domain("localhost").is_err());
        assert!(normalize_proof_domain("app.localhost").is_err());
    }

    #[test]
    fn recent_proof_validates_timing() {
        let now = 10000;
        let valid_record = DomainProofRecord {
            domain: "app.example.org".to_string(),
            token: String::new(),
            created_at: now - 1800,
            verified_at: Some(now - 60),
        };
        assert!(is_recent_domain_proof(&valid_record, now));

        let expired_record = DomainProofRecord {
            domain: "app.example.org".to_string(),
            token: String::new(),
            created_at: now - 7200,
            verified_at: Some(now - 3601),
        };
        assert!(!is_recent_domain_proof(&expired_record, now));

        let unverified_record = DomainProofRecord {
            domain: "app.example.org".to_string(),
            token: "tok".to_string(),
            created_at: now - 60,
            verified_at: None,
        };
        assert!(!is_recent_domain_proof(&unverified_record, now));
    }
}
