//! Explicitly approved Docker Compose deployment adapter.
//!
//! This adapter publishes an HTTPS edge, using either a supplied certificate/key
//! or explicit ACME HTTP-01 mode. It leaves the user's Compose file untouched,
//! applies bounded Docker log rotation, and rolls back only its own service if
//! apply or health checks fail. File/payload utilities are separate; database/volume encryption is not automatic.

use crate::config::Config;
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Host, Url};

const GENERATED_SERVICE_PREFIX: &str = "quantum-shield";

// Embedded upstream CRS request rules. The deployment image does not depend
// on the source checkout being present on the deployment host.
const CRS_SETUP_BYTES: &[u8] =
    include_bytes!("../third_party/owasp-crs-4.30.0/crs-setup.conf.example");
const CRS_REQUEST_ASSETS: &[(&str, &[u8])] = &[
    ("rules/REQUEST-901-INITIALIZATION.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-901-INITIALIZATION.conf")),
    ("rules/REQUEST-905-COMMON-EXCEPTIONS.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-905-COMMON-EXCEPTIONS.conf")),
    ("rules/REQUEST-911-METHOD-ENFORCEMENT.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-911-METHOD-ENFORCEMENT.conf")),
    ("rules/REQUEST-913-SCANNER-DETECTION.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-913-SCANNER-DETECTION.conf")),
    ("rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf")),
    ("rules/REQUEST-921-PROTOCOL-ATTACK.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-921-PROTOCOL-ATTACK.conf")),
    ("rules/REQUEST-922-MULTIPART-ATTACK.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-922-MULTIPART-ATTACK.conf")),
    ("rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf")),
    ("rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf")),
    ("rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf")),
    ("rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf")),
    ("rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf")),
    ("rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf")),
    ("rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")),
    ("rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf")),
    ("rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf")),
    ("rules/REQUEST-949-BLOCKING-EVALUATION.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf")),
    ("rules/REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf", include_bytes!("../third_party/owasp-crs-4.30.0/rules/REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf")),
    ("rules/ai-critical-artifacts.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/ai-critical-artifacts.data")),
    ("rules/java-classes.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/java-classes.data")),
    ("rules/lfi-os-files.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/lfi-os-files.data")),
    ("rules/php-function-names-933150.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/php-function-names-933150.data")),
    ("rules/php-variables.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/php-variables.data")),
    ("rules/restricted-files.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/restricted-files.data")),
    ("rules/scanners-user-agents.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/scanners-user-agents.data")),
    ("rules/ssrf-no-scheme.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/ssrf-no-scheme.data")),
    ("rules/ssrf.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/ssrf.data")),
    ("rules/unix-shell.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/unix-shell.data")),
    ("rules/windows-powershell-commands.data", include_bytes!("../third_party/owasp-crs-4.30.0/rules/windows-powershell-commands.data")),
];

/// ACME deployment settings. Staging is the default; production requires a separate
/// explicit acknowledgement because it creates real publicly trusted certificate orders.
#[derive(Debug, Clone, Copy)]
pub struct AcmeComposeOptions<'a> {
    pub email: &'a str,
    pub cache_dir: &'a Path,
    pub production: bool,
    pub acknowledge_production_issuance: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn deploy_compose(
    config: &Config,
    compose_file: &Path,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    apply: bool,
    acknowledge_public_listener: bool,
    local_test: bool,
    acme: Option<AcmeComposeOptions<'_>>,
    mtls_ca: Option<&Path>,
) -> Result<()> {
    if config.sites.len() != 1 {
        bail!("the initial Docker Compose adapter supports exactly one configured site per deployment");
    }
    if local_test && (acknowledge_public_listener || acme.is_some()) {
        bail!("--local-test is available only for supplied-certificate mode and conflicts with public/ACME deployment");
    }
    if cert_path.is_some() != key_path.is_some() {
        bail!("--cert and --key must be supplied together");
    }
    if acme.is_some() && (cert_path.is_some() || key_path.is_some()) {
        bail!("choose either an existing --cert/--key pair or --acme-email, not both");
    }
    if acme.is_none() && cert_path.is_none() {
        bail!("provide --cert and --key, or select automatic ACME with --acme-email");
    }
    verify_mtls_deployment(mtls_ca)?;
    if apply && !local_test && !acknowledge_public_listener {
        bail!("applying to public TCP/443 (and TCP/80 in ACME mode) requires --acknowledge-public-listener; use --local-test for a loopback-only supplied-certificate test");
    }
    if let Some(options) = acme {
        crate::proxy::validate_acme_email(options.email)?;
        if options.production && !options.acknowledge_production_issuance {
            bail!("production ACME requires --production and --acknowledge-production-issuance; validate the domain against staging first");
        }
        if !options.cache_dir.is_absolute() {
            bail!("ACME cache path must be absolute");
        }
        crate::proxy::validate_acme_domain(&config.sites[0].domain)?;
        if let Ok(meta) = fs::symlink_metadata(options.cache_dir) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                bail!("ACME cache path must be an existing real directory or a new directory path, not a symlink/file: {}", options.cache_dir.display());
            }
        }
    }

    let compose_file = compose_file
        .canonicalize()
        .with_context(|| format!("cannot resolve Compose file {}", compose_file.display()))?;
    if !compose_file.is_file() {
        bail!(
            "Compose path is not a regular file: {}",
            compose_file.display()
        );
    }
    let project_dir = compose_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Compose file has no parent directory"))?;

    let cert_path = cert_path
        .map(|path| {
            path.canonicalize()
                .with_context(|| format!("cannot resolve certificate file {}", path.display()))
        })
        .transpose()?;
    let key_path = key_path
        .map(|path| {
            path.canonicalize()
                .with_context(|| format!("cannot resolve private-key file {}", path.display()))
        })
        .transpose()?;
    for (label, path) in std::iter::once(("Compose file", &compose_file))
        .chain(cert_path.as_ref().map(|path| ("certificate", path)))
        .chain(key_path.as_ref().map(|path| ("private key", path)))
    {
        if path.to_string_lossy().chars().any(char::is_control) {
            bail!("{label} path contains a control character, which is not supported");
        }
    }

    let (host_uid, host_gid) = current_user_ids()?;
    if host_uid == 0 {
        bail!("for container isolation, run the Quantum Shield adapter as an unprivileged host user with Docker access; running the GUI/CLI as root is not supported");
    }
    if let (Some(cert_path), Some(key_path)) = (cert_path.as_ref(), key_path.as_ref()) {
        if !cert_path.is_file() || !key_path.is_file() {
            bail!("certificate and private key must both be regular files");
        }
        validate_private_key_permissions(key_path)?;
        validate_private_key_owner(key_path, host_uid)?;
        fs::File::open(cert_path).with_context(|| {
            format!(
                "the current user cannot read certificate {}",
                cert_path.display()
            )
        })?;
        fs::File::open(key_path).with_context(|| {
            format!(
                "the current user cannot read private key {}",
                key_path.display()
            )
        })?;
        crate::proxy::validate_tls_material(cert_path, key_path)?;
    }

    let site = &config.sites[0];
    if !local_test {
        validate_public_deployment_domain(&site.domain)?;
    }
    let upstream = Url::parse(&site.upstream).context("invalid configured upstream URL")?;
    let upstream_service_name = match upstream.host() {
        Some(Host::Domain(host))
            if !host.eq_ignore_ascii_case("localhost")
                && !host.contains('.')
                && host.parse::<IpAddr>().is_err() => host.to_owned(),
        _ => bail!("Docker Compose mode requires a single-label service upstream such as http://web:3000; loopback and external upstreams are not supported by this adapter"),
    };

    // Use Docker Compose's normalized JSON configuration to avoid editing or
    // attempting to parse arbitrary YAML ourselves.
    let base_config = run_compose(
        &compose_file,
        None,
        project_dir,
        &["config", "--format", "json"],
    )?;
    let compose_json: Value = serde_json::from_slice(&base_config.stdout)
        .context("Docker Compose config did not produce valid JSON")?;
    let services = compose_json
        .get("services")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Docker Compose config has no services object"))?;
    let upstream_service = services
        .get(&upstream_service_name)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "upstream service '{upstream_service_name}' was not found in the Compose project"
            )
        })?;

    if upstream_service
        .get("network_mode")
        .and_then(Value::as_str)
        .is_some_and(|mode| mode == "host" || mode.starts_with("service:"))
    {
        bail!("upstream service '{upstream_service_name}' uses host/shared network mode; this adapter requires a private Compose network");
    }
    if upstream_service
        .get("ports")
        .and_then(Value::as_array)
        .is_some_and(|ports| !ports.is_empty())
    {
        bail!("upstream service '{upstream_service_name}' publishes host ports. Remove its public port mappings first so clients cannot bypass Quantum Shield's HTTPS edge; this adapter will not edit your Compose file automatically");
    }

    for (name, service) in services {
        if name == &upstream_service_name {
            continue;
        }
        let Some(ports) = service.get("ports").and_then(Value::as_array) else {
            continue;
        };
        for port in ports {
            let published = port.get("published").and_then(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| value.as_u64().map(|n| n.to_string()))
            });
            let conflicts = if local_test {
                // Docker chooses an ephemeral host port bound only to loopback.
                // No fixed host port is reserved by this local test adapter.
                false
            } else if acme.is_some() {
                published.as_deref() == Some("80") || published.as_deref() == Some("443")
            } else {
                published.as_deref() == Some("443")
            };
            if conflicts {
                bail!("Compose service '{name}' already publishes host port {}; this adapter needs that public port free to avoid competing listeners", published.as_deref().unwrap_or("unknown"));
            }
        }
    }

    let networks =
        supported_private_network(&compose_json, upstream_service, &upstream_service_name)?;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_nanos();
    let mut slug = safe_slug(&site.id);
    slug.truncate(30);
    let service_name = format!(
        "{GENERATED_SERVICE_PREFIX}-{slug}-{}",
        stamp % 1_000_000_000_000u128
    );
    if services.contains_key(&service_name) {
        bail!("the Compose project already defines the generated service name '{service_name}'; retry after reviewing the project");
    }
    let build_dir_name = format!(".quantum-shield-{slug}-{stamp}");
    let build_dir = project_dir.join(&build_dir_name);
    let overlay_name = format!("compose.quantum-shield-{slug}-{stamp}.yaml");
    let overlay_path = project_dir.join(&overlay_name);

    create_private_dir(&build_dir).with_context(|| {
        format!(
            "cannot create private adapter build directory {}",
            build_dir.display()
        )
    })?;
    let mut overlay_created = false;
    let result = (|| -> Result<()> {
        // Copy the already-built CLI into a tiny runtime image. This avoids a
        // second Cargo resolution/build inside Docker, which may not have crates.io access.
        let executable_path = find_qsctl_executable()?;
        attest_qsctl_features(&executable_path, mtls_ca.is_some())?;
        let executable_bytes = fs::read(&executable_path).with_context(|| {
            format!("cannot read qsctl executable {}", executable_path.display())
        })?;
        write_private_file(&build_dir.join("qsctl"), &executable_bytes)?;
        let generated_config = render_site_config(site, config.schema_version)?;
        write_private_file(
            &build_dir.join("qs-config.toml"),
            generated_config.as_bytes(),
        )?;
        write_crs_assets(&build_dir)?;
        write_private_file(&build_dir.join("Dockerfile"), DOCKERFILE)?;
        let overlay = render_compose_overlay(
            &service_name,
            &build_dir_name,
            cert_path.as_deref(),
            key_path.as_deref(),
            &networks,
            host_uid,
            host_gid,
            local_test,
            acme,
            mtls_ca,
        );
        write_private_file(&overlay_path, overlay.as_bytes())?;
        overlay_created = true;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&build_dir);
        if overlay_created {
            let _ = fs::remove_file(&overlay_path);
        }
        return Err(error);
    }

    let merged = run_compose(
        &compose_file,
        Some(&overlay_path),
        project_dir,
        &["config", "--quiet"],
    );
    if let Err(error) = merged {
        eprintln!("Generated files were retained for inspection:");
        eprintln!("  build context: {}", build_dir.display());
        eprintln!("  overlay      : {}", overlay_path.display());
        return Err(error).context("generated Docker Compose overlay did not validate");
    }

    println!("QUANTUM SHIELD — DOCKER COMPOSE HTTPS ADAPTER");
    println!("==============================================");
    println!("Domain         : {}", site.domain);
    println!(
        "Upstream       : {} ({upstream_service_name})",
        site.upstream
    );
    println!("Proxy service  : {service_name}");
    println!("Compose file   : {}", compose_file.display());
    println!("Generated overlay: {}", overlay_path.display());
    println!("Generated build : {}", build_dir.display());
    if local_test {
        println!("Mode           : LOCAL TEST (loopback only; self-signed cert allowed for local health check)");
        println!("Host binding   : 127.0.0.1:<Docker-assigned-port> -> container TCP/18443");
    } else {
        println!("Mode           : PUBLIC HTTPS EDGE (explicit operator acknowledgement required)");
        println!("Host binding   : host TCP/443 -> container TCP/18443 on host interfaces");
    }
    if let Some(options) = acme {
        println!(
            "Certificate    : automatic ACME HTTP-01 ({})",
            if options.production {
                "production"
            } else {
                "staging"
            }
        );
        println!(
            "ACME cache     : {} (persistent; directory permissions 0700 on Unix)",
            options.cache_dir.display()
        );
        println!("HTTP listener  : TCP/80 for challenge responses and HTTPS redirects");
        println!("Certificate renewal: handled by the continuously polled rustls-acme TLS incoming stream");
    } else {
        println!("Certificate    : existing PEM certificate/key mounted read-only");
        println!("Certificate hot reload: enabled for direct Rustls serving; atomic file replacement across individual Docker file bind mounts may require re-creation");
    }
    println!("Container user : non-root UID:GID {host_uid}:{host_gid}");
    println!("Docker logs    : json-file rotation max-size=10m, max-file=3");
    println!("Original Compose file: not modified");
    println!("File encryption: available via qsctl encrypt-file; upstream volumes are not automatically encrypted");
    println!("Payload encryption: context-bound qsctl utilities available; application integration is required");
    println!();
    println!("This adapter enables the TLS edge only. It does not claim a complete multi-layer protection profile.");

    if !apply {
        println!();
        println!("DRY RUN: files generated and Docker Compose configuration validated; no containers were started.");
        if local_test {
            println!("To apply as a loopback-only test, run again with --apply --local-test. Docker will allocate a free loopback host port and the adapter will print the resulting URL.");
        } else if acme.is_some() {
            println!("To apply ACME HTTP-01 after verifying public DNS and TCP/80+443 routing, run again with --apply --acknowledge-public-listener.");
            if acme.is_some_and(|options| !options.production) {
                println!("Staging is active by default; staging certificates are not trusted by browsers.");
            }
        } else {
            println!("To apply publicly after reviewing the overlay, run again with --apply --acknowledge-public-listener.");
            println!("For an isolated self-signed test, use --local-test instead; Docker will allocate an ephemeral host port bound only to 127.0.0.1.");
        }
        return Ok(());
    }

    if let Some(options) = acme {
        prepare_host_acme_cache(options.cache_dir)?;
    }
    let up_result = run_compose(
        &compose_file,
        Some(&overlay_path),
        project_dir,
        &[
            "up",
            "--detach",
            "--build",
            "--no-deps",
            service_name.as_str(),
        ],
    );
    if let Err(error) = up_result {
        return match rollback_service(&compose_file, &overlay_path, project_dir, &service_name) {
            Ok(()) => Err(error).context("Docker Compose could not start Quantum Shield; the generated proxy service was removed"),
            Err(rollback_error) => bail!("Docker Compose could not start Quantum Shield ({error:#}); rollback also failed ({rollback_error:#}). Original Compose file was not modified. Inspect generated service '{service_name}' and remove it manually if it remains present."),
        };
    }

    let mut healthy = false;
    let mut local_test_port: Option<u16> = None;
    let mut last_detail = String::from("no HTTPS health response yet");
    // ACME issuance has network/DNS validation latency; never switch production
    // certificate validation off, but allow untrusted staging certificates only.
    let staging_acme = acme.is_some_and(|options| !options.production);
    let attempts = if acme.is_some() { 60 } else { 12 };
    for _ in 0..attempts {
        if local_test && local_test_port.is_none() {
            match local_compose_published_port(
                &compose_file,
                &overlay_path,
                project_dir,
                &service_name,
            ) {
                Ok(port) => {
                    println!("Local-test host port allocated by Docker: 127.0.0.1:{port}");
                    local_test_port = Some(port);
                }
                Err(error) => {
                    last_detail =
                        format!("could not discover the Docker-assigned loopback port: {error:#}");
                    thread::sleep(Duration::from_millis(250));
                    continue;
                }
            }
        }
        let health_port = local_test_port.unwrap_or(443);
        match https_health_check(&site.domain, health_port, local_test, staging_acme) {
            Ok((code, _detail)) if (200..500).contains(&code) => {
                println!("HTTPS health check passed: HTTP {code}");
                healthy = true;
                break;
            }
            Ok((code, detail)) => last_detail = format!("HTTP {code}: {detail}"),
            Err(error) => last_detail = error.to_string(),
        }
        thread::sleep(Duration::from_secs(if acme.is_some() { 2 } else { 1 }));
    }

    if !healthy {
        if local_test {
            eprintln!("--- Quantum Shield local-test diagnostics ---");
            for (label, args) in [
                (
                    "container logs",
                    vec!["logs", "--no-color", "--tail", "100", service_name.as_str()],
                ),
                (
                    "container status",
                    vec!["ps", "--all", "--no-trunc", service_name.as_str()],
                ),
            ] {
                match run_compose(&compose_file, Some(&overlay_path), project_dir, &args) {
                    Ok(output) => {
                        eprintln!("--- {label} ---");
                        eprint!("{}", String::from_utf8_lossy(&output.stdout));
                        eprint!("{}", String::from_utf8_lossy(&output.stderr));
                    }
                    Err(error) => {
                        eprintln!("--- {label} failed: {error:#} ---");
                    }
                }
            }
        }

        let rollback_result =
            rollback_service(&compose_file, &overlay_path, project_dir, &service_name);
        if let Err(error) = rollback_result {
            bail!("HTTPS health check failed ({last_detail}); automatic rollback also failed ({error}). Original Compose file was not modified. Inspect service '{service_name}' and stop it manually if still running.");
        }
        bail!("HTTPS health check failed ({last_detail}); the new Quantum Shield container '{service_name}' was removed. The original Compose file and other services were not modified.");
    }

    match run_compose(
        &compose_file,
        Some(&overlay_path),
        project_dir,
        &["logs", "--no-color", "--tail", "100", service_name.as_str()],
    ) {
        Ok(logs) => {
            let output = format!("{}\n{}", String::from_utf8_lossy(&logs.stdout), String::from_utf8_lossy(&logs.stderr));
            if output.contains("key_exchange=X25519MLKEM768") {
                println!("TLS key exchange: hybrid X25519MLKEM768 observed on a local health-check connection.");
            } else if output.contains("key_exchange=") {
                println!("TLS key exchange: a negotiated group was logged, but hybrid X25519MLKEM768 was not observed on the local health-check connection.");
            } else {
                println!("TLS key exchange: not present in the last 100 log lines; inspect `docker compose logs {service_name}` before claiming hybrid negotiation.");
            }
        }
        Err(error) => println!("TLS key exchange: deployment health succeeded, but logs could not be inspected automatically ({error:#})."),
    }
    println!();
    if local_test {
        if let Some(port) = local_test_port {
            println!("Local test URL : https://{}:{port}/", site.domain);
        }
        println!("APPLIED (LOCAL TEST): loopback-only TLS edge passed an HTTPS health check. Certificate trust was intentionally bypassed for this local test; this is not production validation.");
    } else {
        println!("APPLIED: TLS edge is active and the domain passed a certificate-validating HTTPS health check.");
    }
    println!("Encryption scope: file/payload utilities are available; automatic database and volume encryption remains unimplemented.");
    println!(
        "Rollback command: docker compose -f {} -f {} rm --stop --force {}",
        shell_quote(&compose_file.display().to_string()),
        shell_quote(&overlay_path.display().to_string()),
        shell_quote(&service_name),
    );
    if acme.is_some() {
        println!("Certificate renewal: rustls-acme handles renewal and reuses the persistent cache on restart.");
    } else {
        println!("Certificate renewal: external certificate refresh is not managed by this adapter; direct serve-https mode watches cert/key paths, but re-create the proxy after host-file rotation if a bind-mounted file was replaced atomically.");
    }
    Ok(())
}

fn validate_public_deployment_domain(domain: &str) -> Result<()> {
    let canonical = domain.trim_end_matches('.').to_ascii_lowercase();
    let reserved_suffixes = [".test", ".invalid", ".localhost", ".local"];
    let placeholder = ["example.com", "example.org", "example.net"].contains(&canonical.as_str())
        || canonical.split('.').any(|label| label == "example")
        || reserved_suffixes
            .iter()
            .any(|suffix| canonical.ends_with(suffix));
    if placeholder {
        bail!("domain '{domain}' is reserved for examples/tests/local use; choose a real public hostname you control");
    }
    Ok(())
}

fn current_user_ids() -> Result<(u32, u32)> {
    #[cfg(unix)]
    {
        fn id_value(flag: &str) -> Result<u32> {
            let output = Command::new("id")
                .arg(flag)
                .output()
                .context("could not execute 'id' to determine the current non-root user")?;
            if !output.status.success() {
                bail!("'id {flag}' failed while checking the container user identity");
            }
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .with_context(|| format!("'id {flag}' returned a non-numeric identity"))
        }
        Ok((id_value("-u")?, id_value("-g")?))
    }
    #[cfg(not(unix))]
    {
        bail!("the live Docker Compose deployment adapter currently supports Unix-like hosts only")
    }
}

fn supported_private_network(
    compose_json: &Value,
    upstream_service: &serde_json::Map<String, Value>,
    service_name: &str,
) -> Result<Vec<String>> {
    if upstream_service
        .get("network_mode")
        .is_some_and(|mode| !mode.is_null())
    {
        bail!("upstream service '{service_name}' sets network_mode; this adapter requires a normal private Compose network");
    }

    let mut networks: Vec<String> = match upstream_service.get("networks") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(values)) => values.keys().cloned().collect(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|network| {
                network.as_str().map(str::to_owned).ok_or_else(|| {
                    anyhow::anyhow!(
                        "upstream service '{service_name}' has an unsupported network declaration"
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?,
        Some(_) => {
            bail!("upstream service '{service_name}' has an unsupported network declaration")
        }
    };
    if networks.is_empty() {
        networks.push("default".to_owned());
    }
    networks.sort();
    networks.dedup();
    if networks.len() != 1 {
        bail!("upstream service '{service_name}' is attached to {} networks; this initial adapter permits exactly one network to avoid creating a network bridge", networks.len());
    }
    let network = &networks[0];
    let external = compose_json
        .get("networks")
        .and_then(Value::as_object)
        .and_then(|root_networks| root_networks.get(network))
        .and_then(|network_config| network_config.get("external"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if external {
        bail!("upstream service '{service_name}' uses external network '{network}'; this adapter only supports a project-managed private Compose network");
    }
    if network.eq_ignore_ascii_case("host") {
        bail!("upstream service '{service_name}' uses a host network, which is not supported by this adapter");
    }
    Ok(networks)
}

fn run_compose(
    compose_file: &Path,
    overlay: Option<&Path>,
    project_dir: &Path,
    args: &[&str],
) -> Result<Output> {
    let mut command = Command::new("docker");
    command.arg("compose").arg("-f").arg(compose_file);
    if let Some(overlay) = overlay {
        command.arg("-f").arg(overlay);
    }
    command.args(args).current_dir(project_dir);
    let output = command.output().context("could not execute 'docker compose'; install Docker Engine with the Compose plugin and ensure this user can access the Docker daemon")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        bail!(
            "docker compose {} failed (exit {}): {}{}",
            args.join(" "),
            output.status,
            stderr,
            if stdout.is_empty() {
                String::new()
            } else {
                format!("\n{stdout}")
            }
        );
    }
    Ok(output)
}

fn rollback_service(
    compose_file: &Path,
    overlay: &Path,
    project_dir: &Path,
    service_name: &str,
) -> Result<()> {
    run_compose(
        compose_file,
        Some(overlay),
        project_dir,
        &["rm", "--stop", "--force", service_name],
    )?;
    Ok(())
}

fn local_compose_published_port(
    compose_file: &Path,
    overlay: &Path,
    project_dir: &Path,
    service_name: &str,
) -> Result<u16> {
    let output = run_compose(
        compose_file,
        Some(overlay),
        project_dir,
        &["port", service_name, "18443"],
    )?;
    parse_loopback_published_port(&String::from_utf8_lossy(&output.stdout))
}

fn parse_loopback_published_port(output: &str) -> Result<u16> {
    let endpoint = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| anyhow::anyhow!("`docker compose port` returned no endpoint"))?;
    if !endpoint.starts_with("127.0.0.1:") {
        bail!("Docker returned unexpected local-test endpoint '{endpoint}'; refusing to health-check a non-loopback binding");
    }
    let port = endpoint
        .rsplit(':')
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not parse port from Docker endpoint '{endpoint}'"))?
        .parse::<u16>()
        .with_context(|| format!("Docker returned an invalid port in '{endpoint}'"))?;
    if port == 0 {
        bail!("Docker returned port 0 for the local-test listener");
    }
    Ok(port)
}

fn https_health_check(
    domain: &str,
    port: u16,
    local_test: bool,
    staging_acme: bool,
) -> Result<(u16, String)> {
    let resolve = format!("{domain}:{port}:127.0.0.1");
    let url = if local_test {
        format!("https://{domain}:{port}/")
    } else {
        format!("https://{domain}/")
    };
    let mut args = vec![
        "--noproxy",
        "*",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--connect-timeout",
        "3",
        "--max-time",
        "8",
    ];
    // This exception is confined to a host port mapped only to 127.0.0.1.
    // Public mode always verifies the certificate chain normally.
    if local_test || staging_acme {
        // Staging ACME certificates are intentionally untrusted; production mode
        // never disables certificate verification.
        args.push("--insecure");
    }
    args.extend(["--resolve", resolve.as_str(), url.as_str()]);
    let output = Command::new("curl")
        .args(args)
        .output()
        .context("could not run curl for the HTTPS health check; install curl or run the health check manually")?;
    let response = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let code = response.parse::<u16>().unwrap_or(0);
    if code == 0 || !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "HTTPS health check did not complete successfully: {}",
            if detail.is_empty() {
                "no valid HTTP response".to_owned()
            } else {
                detail
            }
        );
    }
    Ok((code, response))
}

#[allow(clippy::too_many_arguments)]
/// Fail closed when mutual TLS is requested but the running `qsctl` was built
/// without the `mTls` feature. This is self-attestation of the compiled binary,
/// not a cryptographic build manifest: it prevents silently deploying an edge
/// that would ignore `--mtls-ca`.
/// Verify the exact binary that will be copied into the image advertises the
/// features the deployment relies on. This closes the gap where `deploy-compose`
/// runs under one build while copying a differently built `qsctl`.
fn attest_qsctl_features(executable: &Path, require_mtls: bool) -> Result<()> {
    if !require_mtls {
        return Ok(());
    }
    let output = Command::new(executable)
        .arg("build-features")
        .output()
        .with_context(|| {
            format!(
                "cannot query build features of qsctl executable {}",
                executable.display()
            )
        })?;
    if !output.status.success() {
        bail!(
            "qsctl executable {} does not support build-feature attestation; rebuild it from this revision",
            executable.display()
        );
    }
    let features = String::from_utf8_lossy(&output.stdout);
    if !features.split(',').any(|feature| feature.trim() == "mTls") {
        bail!(
            "qsctl executable {} was not built with --features mTls; refusing to deploy an edge that would ignore --mtls-ca",
            executable.display()
        );
    }
    Ok(())
}

fn verify_mtls_deployment(mtls_ca: Option<&Path>) -> Result<()> {
    let Some(ca) = mtls_ca else {
        return Ok(());
    };
    if !cfg!(feature = "mTls") {
        bail!("--mtls-ca requires a qsctl binary built with --features mTls; refusing to deploy a non-enforcing edge");
    }
    let meta = fs::symlink_metadata(ca).with_context(|| {
        format!(
            "cannot inspect mutual-TLS client CA bundle {}",
            ca.display()
        )
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("mutual-TLS client CA bundle must be a regular non-symlink file");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_compose_overlay(
    service_name: &str,
    build_dir_name: &str,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    networks: &[String],
    host_uid: u32,
    host_gid: u32,
    local_test: bool,
    acme: Option<AcmeComposeOptions<'_>>,
    mtls_ca: Option<&Path>,
) -> String {
    let mut output = format!(
        "services:\n  {service_name}:\n    build:\n      context: ./{build_dir_name}\n      dockerfile: Dockerfile\n    image: {service_name}:local\n    user: \"{host_uid}:{host_gid}\"\n    restart: unless-stopped\n    logging:\n      driver: \"json-file\"\n      options:\n        max-size: \"10m\"\n        max-file: \"3\"\n    read_only: true\n    cap_drop:\n      - ALL\n    security_opt:\n      - no-new-privileges:true\n    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=16m\n    command:\n"
    );
    if let Some(options) = acme {
        output.push_str("      - serve-acme-http01\n      - /etc/quantum-shield/qs-config.toml\n      - --email\n");
        output.push_str(&format!("      - {}\n", yaml_single_quote(options.email)));
        output.push_str("      - --cache\n      - /var/lib/quantum-shield/acme-cache\n      - --http-listen\n      - 0.0.0.0:8080\n      - --https-listen\n      - 0.0.0.0:18443\n");
        if options.production {
            output.push_str("      - --production\n      - --acknowledge-production-issuance\n");
        }
        output.push_str("    ports:\n      - \"80:8080/tcp\"\n      - \"443:18443/tcp\"\n    volumes:\n      - type: bind\n");
        output.push_str(&format!(
            "        source: {}\n",
            yaml_single_quote(&options.cache_dir.display().to_string())
        ));
        output.push_str("        target: /var/lib/quantum-shield/acme-cache\n        read_only: false\n        bind:\n          create_host_path: true\n");
    } else {
        let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
            // This is an internal invariant, not an input error: validated by deploy_compose.
            unreachable!("static TLS mode must have both certificate and key paths")
        };
        let port_mapping = if local_test {
            "127.0.0.1::18443/tcp"
        } else {
            "443:18443/tcp"
        };
        output.push_str("      - serve-https\n      - /etc/quantum-shield/qs-config.toml\n      - --listen\n      - 0.0.0.0:18443\n      - --cert\n      - /run/quantum-shield/fullchain.pem\n      - --key\n      - /run/quantum-shield/privkey.pem\n      - --allow-public-listener\n      - --deployment-adapter\n");
        output.push_str(&format!("    ports:\n      - \"{port_mapping}\"\n    volumes:\n      - type: bind\n        source: {}\n        target: /run/quantum-shield/fullchain.pem\n        read_only: true\n        bind:\n          create_host_path: false\n      - type: bind\n        source: {}\n        target: /run/quantum-shield/privkey.pem\n        read_only: true\n        bind:\n          create_host_path: false\n", yaml_single_quote(&cert_path.display().to_string()), yaml_single_quote(&key_path.display().to_string())));
    }
    if let Some(ca) = mtls_ca {
        output.push_str(&format!(
            "      - type: bind\n        source: {}\n        target: /run/quantum-shield/client-ca.pem\n        read_only: true\n        bind:\n          create_host_path: false\n",
            yaml_single_quote(&ca.display().to_string())
        ));
        output.push_str(
            "    environment:\n      - QUANTUM_SHIELD_MTLS_CA=/run/quantum-shield/client-ca.pem\n",
        );
    }
    output.push_str("    networks:\n");
    for network in networks {
        output.push_str(&format!("      - {}\n", yaml_single_quote(network)));
    }
    output
}

fn find_qsctl_executable() -> Result<std::path::PathBuf> {
    let current =
        std::env::current_exe().context("cannot locate the running Quantum Shield executable")?;
    if current.file_name().and_then(|name| name.to_str()) == Some("qsctl") {
        return Ok(current);
    }
    // The desktop wizard can invoke the same adapter; use the sibling CLI built by
    // `cargo build --bins`. Refuse ambiguous paths instead of copying an arbitrary executable.
    let sibling = current
        .parent()
        .map(|parent| parent.join("qsctl"))
        .ok_or_else(|| anyhow::anyhow!("current executable has no parent directory"))?;
    if sibling.is_file() {
        return Ok(sibling);
    }
    bail!("could not find the qsctl CLI beside {}. Build/install the matching qsctl binary before applying the Docker adapter", current.display())
}

fn prepare_host_acme_cache(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("ACME cache directory must be absolute: {}", path.display());
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            bail!(
                "ACME cache path must be a real directory, not a symlink/file: {}",
                path.display()
            );
        }
    }
    fs::create_dir_all(path)
        .with_context(|| format!("cannot create persistent ACME cache {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "cannot restrict ACME cache permissions at {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct GeneratedConfig<'a> {
    schema_version: u32,
    sites: Vec<GeneratedSite<'a>>,
}

#[derive(serde::Serialize)]
struct GeneratedSite<'a> {
    id: &'a str,
    domain: &'a str,
    upstream: &'a str,
}

fn render_site_config(site: &crate::config::SiteConfig, schema_version: u32) -> Result<String> {
    // Serialize TOML instead of interpolating raw values so strings are escaped
    // and cannot inject additional settings or [[sites]] sections.
    let config = GeneratedConfig {
        schema_version,
        sites: vec![GeneratedSite {
            id: &site.id,
            domain: &site.domain,
            upstream: &site.upstream,
        }],
    };
    toml::to_string(&config)
        .context("could not serialize generated Quantum Shield TOML configuration")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn yaml_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn safe_slug(value: &str) -> String {
    let mut slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect::<String>();
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "site".to_owned()
    } else {
        slug
    }
}

fn validate_private_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .with_context(|| format!("cannot inspect private key {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!("private key {} is accessible to group/others; restrict it to owner-only access (for example chmod 600)", path.display());
        }
    }
    Ok(())
}

fn validate_private_key_owner(path: &Path, expected_uid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(path)
            .with_context(|| format!("cannot inspect private key owner {}", path.display()))?
            .uid();
        if owner != expected_uid {
            bail!("private key {} is owned by UID {owner}, but the container will run as UID {expected_uid}; place a securely permissioned copy owned by the current user in a private directory", path.display());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected_uid);
        bail!("private-key ownership validation for the live adapter currently requires a Unix-like host")
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("cannot create private directory {}", path.display()))
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create generated file {}", path.display()))?;
    if let Err(error) = file.write_all(contents) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error)
            .with_context(|| format!("cannot write generated file {}", path.display()));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error)
            .with_context(|| format!("cannot sync generated file {}", path.display()));
    }
    Ok(())
}

fn render_crs_waf_config(crs_root: &Path) -> String {
    let mut config = String::from("SecRuleEngine On\nSecRequestBodyAccess On\n");
    config.push_str(&format!(
        "Include {}\n",
        crs_root.join("crs-setup.conf").display()
    ));

    // Preserve CRS's required request-phase ordering.
    for (relative, _) in CRS_REQUEST_ASSETS {
        if relative.starts_with("rules/REQUEST-") {
            config.push_str(&format!("Include {}\n", crs_root.join(relative).display()));
        }
    }

    config.push_str("Include /etc/quantum-shield/custom-waf.conf\n");
    config
}

fn write_crs_assets(build_dir: &Path) -> Result<()> {
    let context_crs_root = build_dir.join("crs");
    fs::create_dir_all(context_crs_root.join("rules"))
        .context("could not create private CRS build-context directories")?;

    write_private_file(&context_crs_root.join("crs-setup.conf"), CRS_SETUP_BYTES)?;

    for (relative, contents) in CRS_REQUEST_ASSETS {
        write_private_file(&context_crs_root.join(relative), contents)?;
    }

    write_private_file(
        &build_dir.join("custom-waf.conf"),
        crate::proxy::QUANTUM_SHIELD_WAF_RULES.as_bytes(),
    )?;

    // This path is inside the generated container, not on the deployment host.
    let runtime_crs_root = Path::new("/usr/share/quantum-shield/crs");
    let config = render_crs_waf_config(runtime_crs_root);
    write_private_file(&build_dir.join("waf.conf"), config.as_bytes())?;

    Ok(())
}

const DOCKERFILE: &[u8] = br#"FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN mkdir -p /etc/quantum-shield /var/lib/quantum-shield /usr/share/quantum-shield
COPY qsctl /usr/local/bin/qsctl
COPY qs-config.toml /etc/quantum-shield/qs-config.toml
COPY waf.conf /etc/quantum-shield/waf.conf
COPY custom-waf.conf /etc/quantum-shield/custom-waf.conf
COPY crs/ /usr/share/quantum-shield/crs/
RUN chmod 0555 /usr/local/bin/qsctl && chmod 0444 /etc/quantum-shield/qs-config.toml /etc/quantum-shield/waf.conf /etc/quantum-shield/custom-waf.conf && chmod -R a+rX /usr/share/quantum-shield/crs && mkdir -p /var/lib/quantum-shield/acme-cache
ENV QUANTUM_SHIELD_WAF_CONFIG=/etc/quantum-shield/waf.conf
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/qsctl"]
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn deploy_temp_file(label: &str, bytes: &[u8]) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "qs-deploy-{label}-{}-{nonce}.pem",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write temporary CA fixture");
        path
    }

    #[cfg(not(feature = "mTls"))]
    #[test]
    fn mtls_deployment_is_refused_when_binary_lacks_the_feature() {
        let path = deploy_temp_file("no-feature", b"fixture");
        let error = verify_mtls_deployment(Some(&path)).expect_err("must refuse without mTls");
        assert!(error.to_string().contains("built with --features mTls"));
        let _ = fs::remove_file(path);
    }

    #[cfg(feature = "mTls")]
    #[test]
    fn mtls_deployment_rejects_symlinked_ca_bundle() {
        use std::os::unix::fs::symlink;
        let path = deploy_temp_file("symlink-target", b"fixture");
        let link = path.with_extension("link.pem");
        let _ = fs::remove_file(&link);
        symlink(&path, &link).expect("create CA symlink");
        let error =
            verify_mtls_deployment(Some(&link)).expect_err("must reject a symlinked CA bundle");
        assert!(error.to_string().contains("regular non-symlink file"));
        let _ = fs::remove_file(link);
        let _ = fs::remove_file(path);
    }

    #[cfg(feature = "mTls")]
    #[test]
    fn mtls_deployment_accepts_regular_ca_bundle() {
        let path = deploy_temp_file("regular", b"fixture");
        verify_mtls_deployment(Some(&path)).expect("regular CA file should be accepted");
        let _ = fs::remove_file(path);
    }

    #[cfg(all(unix, feature = "mTls"))]
    #[test]
    fn feature_attestation_rejects_binary_without_mtls() {
        use std::os::unix::fs::PermissionsExt;
        let path = deploy_temp_file(
            "attest",
            b"#!/bin/sh\nprintf 'dlp,body_gate'
",
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        let error = attest_qsctl_features(&path, true).expect_err("must reject binary");
        assert!(error.to_string().contains("not built with --features mTls"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_image_is_pinned_and_uses_the_prebuilt_binary() {
        let dockerfile = std::str::from_utf8(DOCKERFILE).expect("Dockerfile should be UTF-8");
        assert!(dockerfile.contains("debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad"));
        assert!(dockerfile.contains("COPY qsctl /usr/local/bin/qsctl"));
        assert!(!dockerfile.contains("cargo build"));
        assert!(!dockerfile.contains("apt-get"));
    }

    #[test]
    fn runtime_image_uses_pinned_base_and_prebuilt_binary_without_network_build() {
        let dockerfile = std::str::from_utf8(DOCKERFILE).expect("Dockerfile must be UTF-8");
        assert!(dockerfile.contains("debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad"));
        assert!(dockerfile.contains("COPY qsctl /usr/local/bin/qsctl"));
        assert!(!dockerfile.contains("cargo build"));
        assert!(!dockerfile.contains("apt-get"));
    }

    #[test]
    fn runtime_image_packages_request_crs_and_waf_configuration() {
        let dockerfile = std::str::from_utf8(DOCKERFILE).expect("Dockerfile must be UTF-8");
        assert!(dockerfile.contains("COPY crs/ /usr/share/quantum-shield/crs/"));
        assert!(dockerfile.contains("COPY waf.conf /etc/quantum-shield/waf.conf"));
        assert!(dockerfile.contains("COPY custom-waf.conf /etc/quantum-shield/custom-waf.conf"));
        assert!(dockerfile.contains("ENV QUANTUM_SHIELD_WAF_CONFIG=/etc/quantum-shield/waf.conf"));
        assert!(dockerfile.contains("chmod -R a+rX /usr/share/quantum-shield/crs"));

        let config = render_crs_waf_config(Path::new("/usr/share/quantum-shield/crs"));
        assert!(config.starts_with("SecRuleEngine On\nSecRequestBodyAccess On\n"));
        assert!(config.contains("crs-setup.conf"));
        assert!(config.contains("REQUEST-901-INITIALIZATION.conf"));
        assert!(config.contains("REQUEST-949-BLOCKING-EVALUATION.conf"));
        assert!(config.contains("REQUEST-999-COMMON-EXCEPTIONS-AFTER.conf"));
        assert!(config.contains("Include /etc/quantum-shield/custom-waf.conf"));
        assert!(!config.contains("RESPONSE-"));
        assert_eq!(
            CRS_REQUEST_ASSETS
                .iter()
                .filter(|(path, _)| path.starts_with("rules/REQUEST-"))
                .count(),
            18
        );
        assert_eq!(CRS_REQUEST_ASSETS.len(), 29);
    }

    #[test]
    fn slug_is_bounded_and_yaml_safe() {
        let slug = safe_slug(&"A very long / unsafe site id".repeat(5));
        assert!(slug.len() <= 40);
        assert!(slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn generated_toml_escapes_values_and_does_not_create_extra_sites() {
        let site = crate::config::SiteConfig {
            id: "safe-site".to_owned(),
            domain: "app.example.org".to_owned(),
            upstream: "http://localhost:3000\n\n[[sites]]\nid = \"injected\"".to_owned(),
        };
        let text = render_site_config(&site, 1).expect("TOML serialization should succeed");
        let parsed: crate::config::Config =
            toml::from_str(&text).expect("serialized TOML should parse");
        assert_eq!(parsed.sites.len(), 1);
        assert_eq!(parsed.sites[0].upstream, site.upstream);
    }

    #[test]
    fn yaml_quote_escapes_single_quotes() {
        assert_eq!(yaml_single_quote("/tmp/a'b.pem"), "'/tmp/a''b.pem'");
    }

    #[test]
    fn shell_quote_is_safe_for_paths_with_single_quotes() {
        assert_eq!(shell_quote("/tmp/owner's site"), "'/tmp/owner'\\''s site'");
    }

    #[test]
    fn rejects_reserved_deployment_domains() {
        assert!(validate_public_deployment_domain("app.example.com").is_err());
        assert!(validate_public_deployment_domain("service.invalid").is_err());
        assert!(validate_public_deployment_domain("app.real-domain.dev").is_ok());
    }

    #[test]
    fn rejects_upstream_attached_to_multiple_networks() {
        let compose = serde_json::json!({
            "networks": {"front": {}, "back": {}},
            "services": {}
        });
        let service = serde_json::json!({"networks": {"front": {}, "back": {}}});
        let object = service.as_object().expect("service object");
        assert!(supported_private_network(&compose, object, "web").is_err());
    }

    #[test]
    fn rejects_external_network() {
        let compose = serde_json::json!({
            "networks": {"shared": {"external": true}},
            "services": {}
        });
        let service = serde_json::json!({"networks": {"shared": {}}});
        let object = service.as_object().expect("service object");
        assert!(supported_private_network(&compose, object, "web").is_err());
    }

    #[test]
    fn defaults_to_one_project_network_when_not_declared() {
        let compose = serde_json::json!({"services": {}});
        let service = serde_json::json!({});
        let object = service.as_object().expect("service object");
        assert_eq!(
            supported_private_network(&compose, object, "web").unwrap(),
            vec!["default".to_owned()]
        );
    }

    #[test]
    fn local_test_port_parser_accepts_docker_assigned_loopback_port() {
        assert_eq!(
            parse_loopback_published_port("127.0.0.1:49153\n").unwrap(),
            49153
        );
    }

    #[test]
    fn local_test_port_parser_rejects_non_loopback_and_invalid_ports() {
        assert!(parse_loopback_published_port("0.0.0.0:49153\n").is_err());
        assert!(parse_loopback_published_port("127.0.0.1:0\n").is_err());
        assert!(parse_loopback_published_port("127.0.0.1:not-a-port\n").is_err());
        assert!(parse_loopback_published_port("\n").is_err());
    }

    #[test]
    fn compose_overlay_uses_read_only_key_mount_and_internal_adapter_mode() {
        let yaml = render_compose_overlay(
            "quantum-shield-test-123",
            ".qs-build",
            Some(Path::new("/tmp/cert.pem")),
            Some(Path::new("/tmp/key.pem")),
            &["default".to_owned()],
            1000,
            1000,
            false,
            None,
            None,
        );
        assert!(yaml.contains("--allow-public-listener"));
        assert!(yaml.contains("--deployment-adapter"));
        assert!(!yaml.contains("--compose-adapter"));
        assert!(yaml.contains("user: \"1000:1000\""));
        assert!(yaml.contains("read_only: true"));
        assert!(yaml.contains("443:18443/tcp"));
        assert!(yaml.contains("source: '/tmp/key.pem'"));
        assert!(yaml.contains("max-size: \"10m\""));
        assert!(yaml.contains("max-file: \"3\""));
    }

    #[test]
    fn mtls_overlay_mounts_client_ca_and_sets_runtime_env() {
        let yaml = render_compose_overlay(
            "quantum-shield-test-123",
            ".qs-build",
            Some(Path::new("/tmp/cert.pem")),
            Some(Path::new("/tmp/key.pem")),
            &["default".to_owned()],
            1000,
            1000,
            false,
            None,
            Some(Path::new("/etc/qs/client-ca.pem")),
        );
        assert!(yaml.contains("source: '/etc/qs/client-ca.pem'"));
        assert!(yaml.contains("target: /run/quantum-shield/client-ca.pem"));
        assert!(yaml.contains("QUANTUM_SHIELD_MTLS_CA=/run/quantum-shield/client-ca.pem"));
    }

    #[test]
    fn local_test_overlay_binds_only_to_loopback_and_uses_test_port() {
        let yaml = render_compose_overlay(
            "quantum-shield-test-123",
            ".qs-build",
            Some(Path::new("/tmp/cert.pem")),
            Some(Path::new("/tmp/key.pem")),
            &["default".to_owned()],
            1000,
            1000,
            true,
            None,
            None,
        );
        assert!(yaml.contains("127.0.0.1::18443/tcp"));
        assert!(!yaml.contains("443:18443/tcp"));
        assert!(yaml.contains("max-size: \"10m\""));
    }

    #[test]
    fn acme_overlay_has_persistent_cache_http01_redirect_and_log_rotation() {
        let options = AcmeComposeOptions {
            email: "ops@real-domain.dev",
            cache_dir: Path::new("/home/test/.local/state/quantum-shield/acme"),
            production: false,
            acknowledge_production_issuance: false,
        };
        let yaml = render_compose_overlay(
            "quantum-shield-test-123",
            ".qs-build",
            None,
            None,
            &["default".to_owned()],
            1000,
            1000,
            false,
            Some(options),
            None,
        );
        assert!(yaml.contains("serve-acme-http01"));
        assert!(yaml.contains("80:8080/tcp"));
        assert!(yaml.contains("443:18443/tcp"));
        assert!(yaml.contains("target: /var/lib/quantum-shield/acme-cache"));
        assert!(yaml.contains("create_host_path: true"));
        assert!(yaml.contains("max-size: \"10m\""));
        assert!(!yaml.contains("--production"));
    }
}
