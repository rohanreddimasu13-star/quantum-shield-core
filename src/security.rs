//! Quantum Shield's passive website, application, and repository security checks.
//!
//! The scanner is read-only: it never runs code from the target repository and never
//! edits target files. It is a static assessment aid, not proof that a system is secure.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const HARD_MAX_FILES: usize = 100_000;
const HARD_MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 64;
const MAX_ENTRIES_PER_DIRECTORY: usize = 100_000;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Info => "INFO",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub rule_id: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub module: String,
    pub target: String,
    pub generated_at_unix: u64,
    pub files_scanned: usize,
    pub files_skipped_large: usize,
    pub files_skipped_binary_or_non_utf8: usize,
    pub scan_truncated: bool,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    #[serde(skip)]
    scanned_paths: Vec<PathBuf>,
}

impl ScanReport {
    fn new(module: &str, target: String) -> Self {
        Self {
            schema_version: 1,
            module: module.to_owned(),
            target,
            generated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            files_scanned: 0,
            files_skipped_large: 0,
            files_skipped_binary_or_non_utf8: 0,
            scan_truncated: false,
            findings: Vec::new(),
            notes: Vec::new(),
            scanned_paths: Vec::new(),
        }
    }

    fn add(
        &mut self,
        severity: Severity,
        rule_id: &str,
        title: &str,
        location: Option<String>,
        line: Option<usize>,
        recommendation: &str,
    ) {
        // Keep reports deterministic and avoid repeated findings from the same rule/line.
        if self.findings.iter().any(|finding| {
            finding.rule_id == rule_id && finding.location == location && finding.line == line
        }) {
            return;
        }
        let bounded_title = truncate(title, 256);
        let bounded_location = location.map(|value| truncate(&value, 1024));
        let bounded_recommendation = truncate(recommendation, 2048);
        self.findings.push(Finding {
            severity,
            rule_id: truncate(rule_id, 128),
            title: bounded_title,
            location: bounded_location,
            line,
            recommendation: bounded_recommendation,
        });
    }

    fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.location.cmp(&b.location))
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct ScanLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl ScanLimits {
    fn new(max_files: usize, max_file_bytes: u64) -> Self {
        Self {
            max_files: max_files.clamp(1, HARD_MAX_FILES),
            max_file_bytes: max_file_bytes.clamp(1024, HARD_MAX_FILE_BYTES),
            max_total_bytes: HARD_MAX_TOTAL_BYTES,
        }
    }
}

/// Scan a repository's current working tree without running project code or following symlinks.
pub fn repository_scan(root: &Path, max_files: usize, max_file_bytes: u64) -> Result<ScanReport> {
    let canonical = root
        .canonicalize()
        .with_context(|| format!("cannot resolve repository path {}", root.display()))?;
    if !canonical.is_dir() {
        bail!(
            "repository scan target is not a directory: {}",
            canonical.display()
        );
    }

    let limits = ScanLimits::new(max_files, max_file_bytes);
    let mut report = ScanReport::new("repository-security", canonical.display().to_string());
    report.notes.extend([
        "Read-only static scan: no target code was executed and no target files were changed.".to_owned(),
        "Scans the current working tree only; Git history, remote CI secrets, compiled binaries, and files in skipped dependency/build directories are not examined. Git tracking status is not checked, so a local/untracked .env file can be reported too.".to_owned(),
        format!(
            "Safety bounds: at most {} files, {} bytes per file, {} total bytes; directory depth limited to {}.",
            limits.max_files, limits.max_file_bytes, limits.max_total_bytes, MAX_SCAN_DEPTH
        ),
        "Pattern matches can be false positives or miss obfuscated/encoded secrets. Review findings before making changes.".to_owned(),
    ]);

    let mut stack = vec![(canonical.clone(), 0usize)];
    let mut total_bytes = 0u64;
    let mut files_considered = 0usize;
    let mut unique_keys = BTreeSet::new();

    'scan: while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_SCAN_DEPTH {
            report.scan_truncated = true;
            report
                .notes
                .push("Scan stopped descending after the maximum directory depth.".to_owned());
            continue;
        }

        let mut entries = Vec::new();
        let mut listing_truncated = false;
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("cannot read directory {}", directory.display()))?
            .take(MAX_ENTRIES_PER_DIRECTORY + 1)
        {
            if entries.len() >= MAX_ENTRIES_PER_DIRECTORY {
                listing_truncated = true;
                break;
            }
            match entry {
                Ok(entry) => entries.push(entry),
                Err(_) => report.notes.push(format!(
                    "An entry under {} could not be enumerated and was skipped.",
                    directory
                        .strip_prefix(&canonical)
                        .unwrap_or(&directory)
                        .display()
                )),
            }
        }
        if listing_truncated {
            report.scan_truncated = true;
            report.notes.push(format!(
                "Directory listing under {} exceeded the per-directory entry limit and was truncated.",
                directory.strip_prefix(&canonical).unwrap_or(&directory).display()
            ));
        }
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.file_type().is_symlink() {
                continue;
            }

            if metadata.is_dir() {
                let name = entry.file_name();
                if should_skip_directory(name.to_string_lossy().as_ref()) {
                    continue;
                }
                stack.push((path, depth + 1));
                continue;
            }
            if !metadata.is_file() {
                continue;
            }

            if files_considered >= limits.max_files || total_bytes >= limits.max_total_bytes {
                report.scan_truncated = true;
                break 'scan;
            }

            files_considered += 1;
            let relative = path
                .strip_prefix(&canonical)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            check_sensitive_filename(&mut report, &relative);

            if is_binary_extension(&path) {
                report.files_skipped_binary_or_non_utf8 += 1;
                continue;
            }
            if metadata.len() > limits.max_file_bytes
                || metadata.len() > limits.max_total_bytes.saturating_sub(total_bytes)
            {
                report.files_skipped_large += 1;
                continue;
            }

            // Bound the actual read as well as the metadata check, so a file that grows
            // between metadata() and read() cannot cause an unbounded allocation.
            let file = match fs::File::open(&path) {
                Ok(file) => file,
                Err(_) => {
                    report
                        .notes
                        .push(format!("Could not read {relative}; it was skipped."));
                    continue;
                }
            };
            let mut bytes = Vec::with_capacity(metadata.len().min(limits.max_file_bytes) as usize);
            if file
                .take(limits.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .is_err()
            {
                report
                    .notes
                    .push(format!("Could not read {relative}; it was skipped."));
                continue;
            }
            if bytes.len() as u64 > limits.max_file_bytes {
                report.files_skipped_large += 1;
                continue;
            }
            if bytes.contains(&0) {
                report.files_skipped_binary_or_non_utf8 += 1;
                continue;
            }
            let content = match String::from_utf8(bytes) {
                Ok(content) => content,
                Err(_) => {
                    report.files_skipped_binary_or_non_utf8 += 1;
                    continue;
                }
            };

            total_bytes = total_bytes.saturating_add(content.len() as u64);
            report.files_scanned += 1;
            report.scanned_paths.push(path.clone());
            scan_text_file(&mut report, &relative, &content, &mut unique_keys);
        }
    }

    if report.scan_truncated {
        report.notes.push(
            "Scan bounds were reached. Review the truncated flag and rerun with intentional limits if more coverage is required.".to_owned(),
        );
    }
    report.sort();
    Ok(report)
}

/// Static application assessment. It includes repository checks plus deployability/config checks.
pub fn application_audit(root: &Path, max_files: usize, max_file_bytes: u64) -> Result<ScanReport> {
    let mut report = repository_scan(root, max_files, max_file_bytes)?;
    report.module = "application-security".to_owned();
    report.notes.push(
        "Application checks are static and read-only; they do not start the app, authenticate to it, or prove runtime behavior.".to_owned(),
    );

    let canonical = root
        .canonicalize()
        .with_context(|| format!("cannot resolve application path {}", root.display()))?;
    let top_level = fs::read_dir(&canonical)
        .with_context(|| format!("cannot read application directory {}", canonical.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect::<BTreeSet<_>>();

    let has_cargo = top_level.contains("Cargo.toml");
    let has_npm = top_level.contains("package.json");
    let has_go = top_level.contains("go.mod");
    let has_python = top_level.iter().any(|name| {
        matches!(
            name.as_str(),
            "pyproject.toml" | "requirements.txt" | "Pipfile" | "setup.py"
        )
    });
    let has_java = top_level.iter().any(|name| {
        matches!(
            name.as_str(),
            "pom.xml" | "build.gradle" | "build.gradle.kts"
        )
    });
    // Static sites do not need a package-manager manifest. Recognize their
    // conventional top-level entry points instead of labelling them unknown.
    let has_static_web = top_level.contains("index.html") || top_level.contains("index.htm");
    let app_kinds = [
        (has_cargo, "Rust/Cargo"),
        (has_npm, "JavaScript/Node.js"),
        (has_go, "Go"),
        (has_python, "Python"),
        (has_java, "Java/JVM"),
        (has_static_web, "Static website (HTML/CSS/JavaScript)"),
    ]
    .into_iter()
    .filter_map(|(present, label)| present.then_some(label))
    .collect::<Vec<_>>();

    if app_kinds.is_empty() {
        report.add(
            Severity::Info,
            "APP_TYPE_UNRECOGNIZED",
            "No known top-level application manifest was detected",
            None,
            None,
            "Select or add the manifest appropriate to the real application stack; generic file scanning still ran.",
        );
    } else {
        report.notes.push(format!(
            "Detected application types: {}.",
            app_kinds.join(", ")
        ));
        if has_static_web {
            report.notes.push(
                "Static website profile inferred from a top-level index.html/index.htm entry point; a package manifest is not required for this profile.".to_owned(),
            );
        }
    }

    if has_cargo && !top_level.contains("Cargo.lock") {
        report.add(
            Severity::Medium,
            "APP_CARGO_LOCK_MISSING",
            "Cargo.lock is missing from the application root",
            Some("Cargo.toml".to_owned()),
            None,
            "Generate and review Cargo.lock, include it in release builds, and run cargo-audit against that exact lockfile.",
        );
    }
    if has_npm
        && ![
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lockb",
            "bun.lock",
        ]
        .iter()
        .any(|name| top_level.contains(*name))
    {
        report.add(
            Severity::Medium,
            "APP_JS_LOCK_MISSING",
            "JavaScript package lockfile is missing",
            Some("package.json".to_owned()),
            None,
            "Commit the lockfile for the package manager in use and install release dependencies in frozen/lockfile mode.",
        );
    }
    if has_go && !top_level.contains("go.sum") {
        report.add(
            Severity::Medium,
            "APP_GO_SUM_MISSING",
            "go.sum is missing",
            Some("go.mod".to_owned()),
            None,
            "Generate and review go.sum and use reproducible module verification during release builds.",
        );
    }
    if has_python
        && ![
            "requirements.txt",
            "poetry.lock",
            "uv.lock",
            "Pipfile.lock",
            "pdm.lock",
        ]
        .iter()
        .any(|name| top_level.contains(*name))
    {
        report.add(
            Severity::Medium,
            "APP_PY_LOCK_MISSING",
            "Python dependency lock or pinned requirements file is missing",
            None,
            None,
            "Use a reviewed lockfile or pinned requirements and reproduce the environment from that file in release CI.",
        );
    }

    for path in report.scanned_paths.clone() {
        let relative = path
            .strip_prefix(&canonical)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if path.file_name().and_then(|name| name.to_str()) != Some("requirements.txt") {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(_) => continue,
        };
        for (index, line) in content.lines().enumerate() {
            let requirement = line.trim();
            if requirement.is_empty()
                || requirement.starts_with('#')
                || requirement.starts_with('-')
                || requirement.contains(" @ ")
            {
                continue;
            }
            if !(requirement.contains("==") || requirement.contains("===")) {
                report.add(
                    Severity::Low,
                    "APP_PYTHON_DEPENDENCY_UNPINNED",
                    "Python dependency is not pinned to an exact version",
                    Some(relative.clone()),
                    Some(index + 1),
                    "Pin dependencies or use a reviewed lockfile with hashes when appropriate for the package manager.",
                );
            }
        }
    }

    // Framework-specific hardening checks use bounded reads from files already within scan limits.
    for path in report.scanned_paths.clone() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name != "settings.py" {
            continue;
        }
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        let relative = path
            .strip_prefix(&canonical)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        for (index, line) in contents.lines().enumerate() {
            let lower = line.to_ascii_lowercase().replace(' ', "");
            if lower.starts_with("debug=") && lower.contains("true") {
                report.add(
                    Severity::High,
                    "APP_DJANGO_DEBUG_ENABLED",
                    "Django DEBUG appears enabled in settings.py",
                    Some(relative.clone()),
                    Some(index + 1),
                    "Disable DEBUG in production and load this setting from environment-specific deployment configuration.",
                );
            }
            if lower.starts_with("allowed_hosts=")
                && (lower.contains("['*']") || lower.contains("[\"*\"]"))
            {
                report.add(
                    Severity::High,
                    "APP_DJANGO_WILDCARD_HOSTS",
                    "Django ALLOWED_HOSTS appears to allow every hostname",
                    Some(relative.clone()),
                    Some(index + 1),
                    "Set ALLOWED_HOSTS to the explicit trusted hostnames for each environment.",
                );
            }
        }
    }

    report.sort();
    Ok(report)
}

/// Passive HTTPS/HTTP-header assessment. Requires curl and performs a HEAD request only.
pub fn website_audit(raw_url: &str, timeout_seconds: u64) -> Result<ScanReport> {
    let initial = Url::parse(raw_url).context("URL must be an absolute http:// or https:// URL")?;
    if !matches!(initial.scheme(), "http" | "https") {
        bail!("only http:// and https:// website URLs are supported");
    }
    if initial.host_str().is_none()
        || !initial.username().is_empty()
        || initial.password().is_some()
    {
        bail!("URL must include a host and must not contain embedded credentials");
    }
    if initial.query().is_some() || initial.fragment().is_some() {
        bail!("omit query parameters and fragments from the audit URL so tokens are not exposed in process arguments or reports");
    }

    let mut report = ScanReport::new("website-security", sanitized_url(&initial));
    report.notes.extend([
        "Passive check only: a single HEAD request is used; no exploit attempts, authentication testing, crawler, or load test is performed.".to_owned(),
        "curl performs normal certificate verification. This check does not enumerate every TLS cipher or prove application-layer security.".to_owned(),
        "Some sites do not implement HEAD correctly; a 403/405 response may make header checks incomplete.".to_owned(),
    ]);

    let timeout = timeout_seconds.clamp(3, 60).to_string();
    let output = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--head")
        .arg("--location")
        .arg("--max-redirs")
        .arg("5")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg(timeout)
        .arg("--proto")
        .arg("=http,https")
        .arg("--proto-redir")
        .arg("=https")
        .arg("--dump-header")
        .arg("-")
        .arg("--output")
        .arg("/dev/null")
        .arg("--write-out")
        .arg("\nQS_META\t%{http_code}\t%{url_effective}\t%{ssl_verify_result}\t%{time_total}\t%{remote_ip}\n")
        .arg(initial.as_str())
        .output()
        .context("could not run curl; install curl and retry the passive website audit")?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    // Do not copy curl's raw stderr into the report: redirects/errors can contain URL paths.
    let meta_index = stdout.rfind("QS_META\t");
    let (header_text, meta_text) = match meta_index {
        Some(index) => (&stdout[..index], Some(stdout[index..].trim())),
        None => (stdout.as_str(), None),
    };
    let (status, effective_scheme, verify_result) = if let Some(meta) = meta_text {
        let fields = meta.split('\t').collect::<Vec<_>>();
        let status = fields.get(1).and_then(|field| field.parse::<u16>().ok());
        let effective = fields.get(2).and_then(|field| Url::parse(field).ok());
        let verify = fields.get(3).and_then(|field| field.parse::<i32>().ok());
        (status, effective.map(|url| url.scheme().to_owned()), verify)
    } else {
        (None, None, None)
    };

    if !output.status.success()
        && (status.is_none() || (status == Some(0) && verify_result.unwrap_or(0) == 0))
    {
        report.add(
            Severity::High,
            "WEB_REQUEST_FAILED",
            "Website request failed before a response could be assessed",
            Some(sanitized_url(&initial)),
            None,
            "Check DNS, reachability, TLS certificate validity, proxy settings, and curl diagnostics; do not bypass TLS verification to silence errors.",
        );
        report.notes.push("curl did not provide a complete response; raw curl diagnostics were intentionally omitted so redirected URL paths cannot leak into reports.".to_owned());
        report.sort();
        return Ok(report);
    }

    if initial.scheme() == "http" && effective_scheme.as_deref() != Some("https") {
        report.add(
            Severity::High,
            "WEB_HTTP_NOT_UPGRADED",
            "HTTP URL did not end at an HTTPS URL",
            Some(sanitized_url(&initial)),
            None,
            "Configure a permanent redirect to HTTPS and verify that all authenticated pages and resources use HTTPS.",
        );
    }
    if effective_scheme.as_deref() != Some("https") {
        report.add(
            Severity::High,
            "WEB_HTTPS_NOT_CONFIRMED",
            "Final URL was not confirmed as HTTPS",
            Some(sanitized_url(&initial)),
            None,
            "Serve the website over HTTPS with a publicly trusted certificate and redirect HTTP traffic to HTTPS.",
        );
    }
    if verify_result.is_some_and(|value| value != 0) {
        report.add(
            Severity::Critical,
            "WEB_TLS_CERTIFICATE_INVALID",
            "TLS certificate verification reported an error",
            Some(sanitized_url(&initial)),
            None,
            "Replace the invalid/expired/mismatched certificate and maintain the full certificate chain; never disable verification as a workaround.",
        );
    }
    if let Some(status) = status {
        if status >= 500 {
            report.add(
                Severity::High,
                "WEB_SERVER_5XX",
                &format!("Website returned HTTP {status}"),
                Some(sanitized_url(&initial)),
                None,
                "Check the application and reverse-proxy health, recent logs, upstream connectivity, and error handling.",
            );
        } else if status >= 400 {
            report.add(
                Severity::Medium,
                "WEB_SERVER_4XX",
                &format!("Website returned HTTP {status} to a HEAD request"),
                Some(sanitized_url(&initial)),
                None,
                "Confirm that the public route is intended to be accessible and that HEAD is supported; this may be an intentional authorization response.",
            );
        }
        report
            .notes
            .push(format!("HTTP response status: {status}."));
    }

    let blocks = parse_header_blocks(header_text);
    let headers = blocks.last().cloned().unwrap_or_default();
    if effective_scheme.as_deref() == Some("https") {
        require_header(
            &mut report,
            &headers,
            "strict-transport-security",
            Severity::Medium,
            "WEB_HSTS_MISSING",
            "Strict-Transport-Security (HSTS) header is missing",
            "Add HSTS after confirming all relevant subdomains work over HTTPS; use includeSubDomains/preload only after reviewing their impact.",
        );
    }
    require_header(
        &mut report,
        &headers,
        "content-security-policy",
        Severity::Medium,
        "WEB_CSP_MISSING",
        "Content-Security-Policy header is missing",
        "Define a site-specific Content-Security-Policy, test it in report-only mode first, and avoid blindly copying a permissive policy.",
    );
    require_header(
        &mut report,
        &headers,
        "x-content-type-options",
        Severity::Medium,
        "WEB_NOSNIFF_MISSING",
        "X-Content-Type-Options header is missing",
        "Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.",
    );
    let frame_protected = headers.contains_key("x-frame-options")
        || headers
            .get("content-security-policy")
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|v| v.to_ascii_lowercase().contains("frame-ancestors"))
            });
    if !frame_protected {
        report.add(
            Severity::Medium,
            "WEB_CLICKJACKING_POLICY_MISSING",
            "No X-Frame-Options header or CSP frame-ancestors directive was observed",
            Some(sanitized_url(&initial)),
            None,
            "Set an appropriate Content-Security-Policy frame-ancestors directive or X-Frame-Options for the intended embedding policy.",
        );
    }
    require_header(
        &mut report,
        &headers,
        "referrer-policy",
        Severity::Low,
        "WEB_REFERRER_POLICY_MISSING",
        "Referrer-Policy header is missing",
        "Choose a referrer policy that avoids unnecessarily disclosing full paths or query data to other origins.",
    );
    require_header(
        &mut report,
        &headers,
        "permissions-policy",
        Severity::Low,
        "WEB_PERMISSIONS_POLICY_MISSING",
        "Permissions-Policy header is missing",
        "Disable browser features the application does not need, using a policy compatible with its intended behavior.",
    );

    if let Some(server_values) = headers.get("server") {
        if server_values
            .iter()
            .any(|value| value.chars().any(|ch| ch.is_ascii_digit()))
        {
            report.add(
                Severity::Low,
                "WEB_SERVER_VERSION_DISCLOSURE",
                "Server header may disclose implementation/version details",
                Some(sanitized_url(&initial)),
                None,
                "Consider removing detailed server version strings from public response headers; do not treat header hiding as a substitute for patching.",
            );
        }
    }

    if let Some(cookies) = headers.get("set-cookie") {
        for cookie in cookies {
            let lower = cookie.to_ascii_lowercase();
            if effective_scheme.as_deref() == Some("https")
                && !lower.split(';').any(|part| part.trim() == "secure")
            {
                report.add(
                    Severity::Medium,
                    "WEB_COOKIE_MISSING_SECURE",
                    "A Set-Cookie response appears to omit the Secure attribute",
                    Some(sanitized_url(&initial)),
                    None,
                    "For cookies that must only travel over HTTPS, add Secure and verify behavior for all supported clients.",
                );
            }
            if !lower.split(';').any(|part| part.trim() == "httponly") {
                report.add(
                    Severity::Low,
                    "WEB_COOKIE_MISSING_HTTPONLY",
                    "A Set-Cookie response appears to omit HttpOnly",
                    Some(sanitized_url(&initial)),
                    None,
                    "Mark session/authentication cookies HttpOnly where JavaScript access is not required; assess intentionally script-readable cookies separately.",
                );
            }
            if !lower
                .split(';')
                .any(|part| part.trim().starts_with("samesite="))
            {
                report.add(
                    Severity::Low,
                    "WEB_COOKIE_MISSING_SAMESITE",
                    "A Set-Cookie response appears to omit SameSite",
                    Some(sanitized_url(&initial)),
                    None,
                    "Choose SameSite=Lax/Strict, or None together with Secure, according to the application's cross-site login and embedding requirements.",
                );
            }
        }
    }

    if headers.is_empty() {
        report.notes.push(
            "No final response header block could be parsed; result coverage is incomplete."
                .to_owned(),
        );
    }
    report.sort();
    Ok(report)
}

/// Render a report as JSON or human-readable text, optionally saving it to a file.
pub fn emit_report(report: &ScanReport, json: bool, output: Option<&Path>) -> Result<usize> {
    let rendered = if json {
        serde_json::to_string_pretty(report).context("could not serialize the security report")?
    } else {
        render_human(report)
    };

    if let Some(path) = output {
        fs::write(path, rendered.as_bytes())
            .with_context(|| format!("could not write report to {}", path.display()))?;
        println!("Report written to {}", path.display());
        println!(
            "{}: {} finding(s); {} file(s) scanned.",
            report.module,
            report.findings.len(),
            report.files_scanned
        );
    } else {
        println!("{rendered}");
    }
    Ok(report.findings.len())
}

fn render_human(report: &ScanReport) -> String {
    let mut output = format!(
        "QUANTUM SHIELD — {} REPORT\n{}\nTarget: {}\nGenerated (Unix): {}\nFiles scanned: {}\nLarge files skipped: {}\nBinary/non-UTF-8 files skipped: {}\nScan truncated: {}\nFindings: {}\n\n",
        report.module.to_ascii_uppercase(),
        "=".repeat(76),
        report.target,
        report.generated_at_unix,
        report.files_scanned,
        report.files_skipped_large,
        report.files_skipped_binary_or_non_utf8,
        report.scan_truncated,
        report.findings.len()
    );

    if report.findings.is_empty() {
        output.push_str(
            "No findings from the checks that ran. This is not a guarantee of security.\n\n",
        );
    } else {
        for (index, finding) in report.findings.iter().enumerate() {
            output.push_str(&format!(
                "{}. [{}] {} — {}\n",
                index + 1,
                finding.severity,
                finding.rule_id,
                finding.title
            ));
            if let Some(location) = &finding.location {
                output.push_str(&format!("   Location: {location}"));
                if let Some(line) = finding.line {
                    output.push_str(&format!(":{line}"));
                }
                output.push('\n');
            }
            output.push_str(&format!(
                "   Recommendation: {}\n\n",
                finding.recommendation
            ));
        }
    }
    if !report.notes.is_empty() {
        output.push_str("Coverage notes:\n");
        for note in &report.notes {
            output.push_str(&format!("- {note}\n"));
        }
    }
    output
}

/// Return the physical line numbers where a structurally complete private-key PEM block starts.
/// A bare header in Rust test code (for example an escaped string containing `\n`) is not key material.
/// The payload check is intentionally conservative: every payload line must be base64 characters and
/// the encoded payload must be long enough to represent key material. The scanner never emits payload.
fn private_key_pem_header_lines(content: &str) -> BTreeSet<usize> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut headers = BTreeSet::new();

    for (index, raw_header) in lines.iter().enumerate() {
        let header = raw_header.trim();
        let Some(label) = header
            .strip_prefix("-----BEGIN ")
            .and_then(|value| value.strip_suffix("-----"))
        else {
            continue;
        };
        if !label.ends_with("PRIVATE KEY") || label.is_empty() {
            continue;
        }

        let footer = format!("-----END {label}-----");
        let mut encoded_len = 0usize;
        let mut saw_payload = false;
        let mut valid_payload = true;
        let mut found_footer = false;

        for raw_line in lines.iter().skip(index + 1) {
            let payload_line = raw_line.trim();
            if payload_line == footer {
                found_footer = true;
                break;
            }
            if payload_line.starts_with("-----END ") || payload_line.starts_with("-----BEGIN ") {
                valid_payload = false;
                break;
            }
            if payload_line.is_empty() {
                continue;
            }
            if !payload_line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
            {
                valid_payload = false;
                break;
            }
            saw_payload = true;
            encoded_len = encoded_len.saturating_add(payload_line.len());
        }

        if found_footer && valid_payload && saw_payload && encoded_len >= 48 {
            headers.insert(index + 1);
        }
    }

    headers
}

fn scan_text_file(
    report: &mut ScanReport,
    relative: &str,
    content: &str,
    seen: &mut BTreeSet<(String, usize, String)>,
) {
    let lower_path = relative.to_ascii_lowercase();
    // Vendor sources remain eligible for secret-pattern scanning, but noisy code-pattern
    // checks are intentionally handled separately below.
    let is_third_party = lower_path.starts_with("third_party/");
    let private_key_header_lines = private_key_pem_header_lines(content);
    let is_dockerfile = relative
        .rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("dockerfile"));
    let mut docker_has_nonroot_user = false;
    let mut docker_has_user = false;

    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        let lower = line.to_ascii_lowercase();
        if is_dockerfile && lower.trim_start().starts_with("user ") {
            docker_has_user = true;
            let user = lower.trim_start().trim_start_matches("user ").trim();
            if !user.is_empty()
                && user != "root"
                && user != "0"
                && !user.starts_with("root:")
                && !user.starts_with("0:")
            {
                docker_has_nonroot_user = true;
            }
        }

        let mut line_findings: Vec<(&str, Severity, &str, &str)> = Vec::new();
        if private_key_header_lines.contains(&number) {
            line_findings.push((
                "SECRET_PRIVATE_KEY",
                Severity::Critical,
                "Private-key material appears in a scanned text file",
                "Remove the key from the repository, rotate/revoke it, investigate exposure history, and store key material in a secret manager or protected external file. Removing the current line alone is not enough if it was committed previously.",
            ));
        } else if has_aws_access_key(line) {
            line_findings.push((
                "SECRET_AWS_ACCESS_KEY",
                Severity::High,
                "AWS access-key ID pattern detected",
                "Revoke or rotate the credential, inspect cloud audit logs, and move secrets into a managed secret store. The report does not print the matched value.",
            ));
        } else if has_known_token(line) {
            line_findings.push((
                "SECRET_KNOWN_TOKEN",
                Severity::High,
                "Known API-token pattern detected",
                "Revoke or rotate the token at its issuer, inspect access logs, and use a managed secret store or runtime secret injection.",
            ));
        } else if has_secret_assignment(line) {
            line_findings.push((
                "SECRET_HARDCODED_ASSIGNMENT",
                Severity::High,
                "A hard-coded credential-like assignment appears in source/configuration",
                "Replace the literal with runtime secret injection, rotate it if real, and review repository history. The report never includes the suspected secret value.",
            ));
        }

        if contains_any(
            &lower,
            &[
                concat!("rejectunauthorized", ": ", "false"),
                concat!("reject_unauthorized", ": ", "false"),
                concat!("node_tls_reject_unauthorized", "=", "0"),
                concat!("verify", "=", "false"),
                concat!("verify", " = ", "false"),
                concat!("danger_accept_invalid_certs", "(", "true", ")"),
                concat!("sslmode", "=", "disable"),
                concat!("ssl_mode", " = ", "\"disable\""),
            ],
        ) {
            line_findings.push((
                "TLS_VERIFICATION_DISABLED",
                Severity::High,
                "TLS certificate verification may be disabled",
                "Restore normal certificate and hostname verification. Never disable certificate checks to work around an invalid certificate.",
            ));
        }
        if lower.contains(concat!("privileged", ": ", "true")) {
            line_findings.push((
                "CONTAINER_PRIVILEGED",
                Severity::High,
                "Container configuration enables privileged mode",
                "Remove privileged mode unless a documented, reviewed requirement proves it necessary; use least privilege and narrowly scoped capabilities.",
            ));
        }
        if lower.contains(concat!("/var/run/", "docker.sock"))
            || lower.contains(concat!("/run/", "docker.sock"))
        {
            line_findings.push((
                "CONTAINER_DOCKER_SOCKET_MOUNT",
                Severity::High,
                "Docker socket is referenced or mounted",
                "Avoid exposing the Docker daemon socket to application containers; if unavoidable, use a dedicated constrained proxy and threat-model host takeover risk.",
            ));
        }
        if lower.contains(concat!("network_mode", ": ", "host"))
            || lower.trim() == concat!("network_mode", ": ", "host")
        {
            line_findings.push((
                "CONTAINER_HOST_NETWORK",
                Severity::Medium,
                "Container uses host networking",
                "Prefer an isolated project network and explicitly published ports; document any host-networking requirement.",
            ));
        }
        if !is_third_party
            && (lower.contains(concat!("shell", "=", "true"))
                || lower.contains(concat!("shell", " = ", "true")))
        {
            line_findings.push((
                "CODE_SHELL_EXECUTION",
                Severity::Medium,
                "Subprocess execution may use a shell",
                "Prefer an argument vector with a fixed executable; if shell execution is essential, strictly validate all untrusted inputs and review every call site.",
            ));
        }
        if lower.contains(concat!("pickle", ".loads(")) {
            line_findings.push((
                "CODE_UNSAFE_PICKLE_DESERIALIZATION",
                Severity::High,
                "Python pickle deserialization pattern detected",
                "Never unpickle data from an untrusted or tamperable source; use a data-only format with explicit schema validation.",
            ));
        }
        if lower.contains(concat!("yaml", ".load(")) && !lower.contains("safeloader") {
            line_findings.push((
                "CODE_UNSAFE_YAML_LOAD",
                Severity::Medium,
                "YAML loading may use an unsafe loader",
                "Use a safe data-only YAML loader and explicit schema validation for untrusted input.",
            ));
        }
        let dynamic_eval_language = [
            ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".rb", ".pl",
            ".pm", ".lua", ".sh", ".bash", ".zsh",
        ]
        .iter()
        .any(|extension| lower_path.ends_with(extension));
        let python_exec_language = lower_path.ends_with(".py") || lower_path.ends_with(".pyw");
        if (dynamic_eval_language && lower.contains(concat!("eval", "(")))
            || (python_exec_language && lower.contains(concat!("exec", "(")))
        {
            line_findings.push((
                "CODE_DYNAMIC_EVALUATION",
                Severity::Medium,
                "Dynamic evaluation pattern detected; inspect its data flow",
                "Avoid evaluating untrusted strings as code. If dynamic evaluation is essential, constrain input sources and isolate the operation.",
            ));
        }

        // Static indicators for potentially dangerous command construction.
        // These are review signals, not proof of attacker-controlled data flow.
        let command_api = [
            "os.system(",
            "os.popen(",
            "subprocess.call(",
            "subprocess.run(",
            "subprocess.popen(",
            "child_process.exec(",
            "child_process.execsync(",
            "runtime.getruntime().exec(",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let command_shell = lower.contains("command::new(\"sh\")")
            || lower.contains("command::new(\"bash\")")
            || lower.contains("command::new(\"/bin/sh\")")
            || lower.contains("command::new(\"/bin/bash\")");
        let command_dynamic = lower.contains("format!(")
            || lower.contains("format!(")
            || lower.contains("concat!(")
            || lower.contains(" + ")
            || lower.contains(" . ");
        if (command_api && command_dynamic)
            || (command_shell && (lower.contains("\"-c\"") || lower.contains("'-c'")))
        {
            line_findings.push((
                "CODE_COMMAND_INJECTION_RISK",
                Severity::High,
                "Command execution appears to combine a shell or process API with dynamic input",
                "Trace every value reaching this call. Prefer a fixed executable with separate arguments; avoid shell command strings and validate inputs against a strict allowlist.",
            ));
        }

        // SQL execution combined with dynamic string construction.
        let sql_execution = [
            ".execute(",
            ".executemany(",
            ".query(",
            ".raw_query(",
            ".executequery(",
            ".executesql(",
            "execute sql",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let sql_statement = [
            "select ", "insert ", "update ", "delete ", " from ", " where ",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let sql_dynamic = lower.contains("format!(")
            || lower.contains("format!(")
            || lower.contains("concat!(")
            || lower.contains(" f\"")
            || lower.contains(" f'")
            || lower.contains(" + ")
            || lower.contains("${");
        if sql_execution && sql_statement && sql_dynamic {
            line_findings.push((
                "CODE_SQL_INJECTION_RISK",
                Severity::High,
                "SQL execution appears to use dynamically constructed query text",
                "Use parameterized queries or prepared statements. Trace whether request, user, or other untrusted data can influence the query; do not rely on escaping alone.",
            ));
        }

        // Filesystem operations receiving values that look request-derived.
        let filesystem_api = [
            "read_to_string(",
            "read_to_string(",
            "readfile(",
            "file_get_contents(",
            "open(",
            "create(",
            "remove_file(",
            "remove_dir_all(",
            "send_file(",
            "download_file(",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        let path_construction = lower.contains("join(")
            || lower.contains("resolve(")
            || lower.contains("normalize(")
            || lower.contains("format!(")
            || lower.contains(" + ");
        let possible_external_path = [
            "request",
            "params",
            "query",
            "user_input",
            "userinput",
            "filename",
            "file_name",
            "filepath",
            "file_path",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        if filesystem_api && path_construction && possible_external_path {
            line_findings.push((
                "CODE_PATH_TRAVERSAL_RISK",
                Severity::High,
                "Filesystem path appears to be constructed from a potentially external value",
                "Trace the path back to its source. Canonicalize it, enforce containment within an intended base directory, reject traversal and symlink escapes, and use safe file identifiers where possible.",
            ));
        }

        // Additional unsafe deserialization APIs.
        if lower.contains("objectinputstream") && lower.contains("readobject(") {
            line_findings.push((
                "CODE_UNSAFE_JAVA_DESERIALIZATION",
                Severity::High,
                "Java native object deserialization pattern detected",
                "Avoid deserializing untrusted Java object streams. Prefer a data-only format with explicit schemas and strict type allowlists.",
            ));
        }
        if lower.contains("unserialize(") {
            line_findings.push((
                "CODE_UNSAFE_PHP_DESERIALIZATION",
                Severity::High,
                "PHP unserialize pattern detected",
                "Do not unserialize untrusted or tamperable data. Prefer JSON or another data-only format; if unavoidable, restrict allowed classes and validate the result.",
            ));
        }
        if lower.contains("marshal.load(") || lower.contains("marshal.restore(") {
            line_findings.push((
                "CODE_UNSAFE_RUBY_DESERIALIZATION",
                Severity::High,
                "Ruby Marshal deserialization pattern detected",
                "Do not load Marshal data from untrusted sources. Use a data-only format with explicit schema validation.",
            ));
        }

        // Weak or unsuitable primitives in security-sensitive contexts.
        if lower.contains("md5(")
            || lower.contains("sha1(")
            || lower.contains("md5::")
            || lower.contains("sha1::")
        {
            line_findings.push((
                "CODE_WEAK_HASH_PRIMITIVE",
                Severity::Medium,
                "Legacy MD5 or SHA-1 hashing primitive detected",
                "Do not use MD5 or SHA-1 for passwords, signatures, integrity against attackers, or security tokens. Use a modern purpose-appropriate primitive; use Argon2id for password storage.",
            ));
        }
        let security_sensitive_random_context = [
            "token", "secret", "password", "nonce", "session", "csrf", "key",
        ]
        .iter()
        .any(|marker| lower.contains(marker));
        if lower.contains("math.random(") && security_sensitive_random_context {
            line_findings.push((
                "CODE_INSECURE_RANDOM_SECURITY_CONTEXT",
                Severity::High,
                "Non-cryptographic random generator appears in a security-sensitive context",
                "Use an operating-system-backed cryptographically secure random generator for tokens, secrets, nonces, session identifiers, and keys.",
            ));
        }

        if lower.contains(concat!("access-control-allow-origin", ": ", "*")) {
            line_findings.push((
                "WEB_CORS_WILDCARD",
                Severity::Low,
                "Wildcard CORS origin pattern detected",
                "Confirm that anonymous cross-origin access is intended; use an explicit origin allowlist for credentialed or sensitive APIs.",
            ));
        }
        let docker_image = if is_dockerfile && lower.trim_start().starts_with("from ") {
            lower
                .trim_start()
                .strip_prefix("from ")
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or_default()
        } else {
            ""
        };
        if docker_image.ends_with(":latest") {
            line_findings.push((
                "CONTAINER_FLOATING_IMAGE_TAG",
                Severity::Medium,
                "Container image uses the floating latest tag",
                "Pin a reviewed image version or digest and refresh it through a controlled patch process.",
            ));
        }

        for (rule, severity, title, recommendation) in line_findings {
            let key = (relative.to_owned(), number, rule.to_owned());
            if seen.insert(key) {
                report.add(
                    severity,
                    rule,
                    title,
                    Some(relative.to_owned()),
                    Some(number),
                    recommendation,
                );
            }
        }
    }

    if is_dockerfile && (!docker_has_user || !docker_has_nonroot_user) {
        report.add(
            Severity::Medium,
            "CONTAINER_NONROOT_USER_UNCONFIRMED",
            "Dockerfile does not clearly set a non-root runtime user",
            Some(relative.to_owned()),
            None,
            "Create/use a dedicated unprivileged runtime user and set USER to that identity. Verify actual runtime UID separately.",
        );
    }

    if lower_path.contains(".github/workflows/")
        && !content.to_ascii_lowercase().contains("permissions:")
    {
        report.add(
            Severity::Medium,
            "CI_PERMISSIONS_UNSPECIFIED",
            "GitHub Actions workflow does not declare a top-level permissions policy",
            Some(relative.to_owned()),
            None,
            "Declare the minimum required workflow permissions, normally starting from permissions: read-all or an explicit contents: read policy.",
        );
    }
}

fn check_sensitive_filename(report: &mut ScanReport, relative: &str) {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or(relative)
        .to_ascii_lowercase();
    if name == ".env"
        || name.starts_with(".env.")
            && name != ".env.example"
            && name != ".env.sample"
            && name != ".env.template"
    {
        report.add(
            Severity::Medium,
            "SECRET_ENV_FILE_IN_TREE",
            "An environment-specific .env file is present in the scanned tree",
            Some(relative.to_owned()),
            None,
            "Keep real environment files outside version control, restrict file permissions, and rotate any real credentials if this file has been committed or shared.",
        );
    }
    if matches!(
        name.as_str(),
        "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
    ) || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name.ends_with(".key")
    {
        report.add(
            Severity::High,
            "SECRET_KEY_MATERIAL_FILENAME",
            "A file name commonly associated with private key material is present",
            Some(relative.to_owned()),
            None,
            "Confirm that the file is not needed in source control; remove it from the repository, rotate affected credentials, and store it in a protected secret location.",
        );
    }
}

fn should_skip_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "target"
            | "node_modules"
            | "vendor"
            | "dist"
            | "build"
            | ".next"
            | ".turbo"
            | ".venv"
            | "venv"
            | ".tox"
            | ".cache"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".ruff_cache"
    )
}

fn is_binary_extension(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "pdf"
            | "zip"
            | "gz"
            | "tar"
            | "7z"
            | "rar"
            | "wasm"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "mp4"
            | "mp3"
            | "sqlite"
            | "db"
            | "bin"
            | "so"
            | "dll"
            | "exe"
            | "class"
            | "jar"
            | "pyc"
            | "o"
            | "a"
            | "dylib"
            | "icns"
            | "heic"
            | "avif"
    )
}

fn has_aws_access_key(line: &str) -> bool {
    line.as_bytes().windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

fn has_known_token(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    for prefix in [
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "sk_live_",
        "rk_live_",
    ] {
        if let Some(index) = lower.find(prefix) {
            let suffix = &lower[index + prefix.len()..];
            let token_length = suffix
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                .count();
            let minimum = if prefix == "github_pat_" {
                40
            } else if prefix.starts_with("gh") {
                24
            } else {
                16
            };
            if token_length >= minimum && !looks_like_placeholder(suffix) {
                return true;
            }
        }
    }
    false
}

fn has_secret_assignment(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    for key in [
        "password",
        "passwd",
        "client_secret",
        "api_key",
        "apikey",
        "access_token",
        "auth_token",
        "private_key",
        "secret_key",
        "aws_secret_access_key",
        "database_url",
    ] {
        let mut offset = 0usize;
        while let Some(index) = lower[offset..].find(key) {
            let absolute = offset + index;
            let after_key = absolute + key.len();
            let before_char = lower[..absolute].chars().next_back();
            let after_char = lower[after_key..].chars().next();
            let is_key_char = |ch: char| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-';

            // Match complete key names rather than substrings like `password` in
            // `password-hash`, or `api_key` embedded in a longer identifier.
            // Skip if the key is preceded by an alphanumeric char (makes it a substring)
            // or followed by an alphanumeric char (makes it a substring).
            if before_char.is_some_and(is_key_char) || after_char.is_some_and(is_key_char) {
                offset = after_key;
                if offset >= lower.len() {
                    break;
                }
                continue;
            }

            // Do not match PRIVATE_KEY_* identifiers (task requirement)
            if key == "private_key" {
                let before_text = &line[..absolute].to_ascii_uppercase();
                // Check if PRIVATE_KEY_ immediately precedes the key name
                // by checking the original line text before the key position
                if before_text.ends_with("PRIVATE_KEY_")
                    || before_text.contains(" PRIVATE_KEY_")
                    || before_text.starts_with("PRIVATE_KEY_")
                {
                    offset = after_key;
                    if offset >= lower.len() {
                        break;
                    }
                    continue;
                }
            }

            let tail = &line[after_key..];
            let mut separator_tail = tail.trim_start();
            // JSON/TOML quoted keys have a closing quote immediately after the name.
            if separator_tail.starts_with('\'')
                || separator_tail.starts_with('"')
                || separator_tail.starts_with('`')
            {
                separator_tail = separator_tail[1..].trim_start();
            }
            let Some(separator) = separator_tail.chars().next() else {
                offset = after_key;
                if offset >= lower.len() {
                    break;
                }
                continue;
            };
            if separator != '=' && separator != ':' {
                offset = after_key;
                if offset >= lower.len() {
                    break;
                }
                continue;
            }

            let rhs = separator_tail[separator.len_utf8()..].trim_start();
            if rhs.starts_with("${")
                || rhs.starts_with("$env")
                || rhs.starts_with("env(")
                || rhs.starts_with("os.getenv")
                || rhs.starts_with("process.env")
                || rhs.starts_with("getenv(")
            {
                offset = after_key;
                if offset >= lower.len() {
                    break;
                }
                continue;
            }

            let quoted = rhs.starts_with('\'') || rhs.starts_with('"');
            let value = if quoted {
                let quote = rhs.chars().next().unwrap_or(' ');
                rhs[1..].split(quote).next().unwrap_or_default().trim()
            } else {
                rhs.split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';' || ch == '}')
                    .next()
                    .unwrap_or_default()
                    .trim_matches(&['\'', '"', '`'][..])
            };

            if !looks_like_placeholder(value)
                && ((quoted && value.len() >= 8)
                    || (!quoted
                        && value.len() >= 24
                        && value
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || "_-/+=".contains(ch))))
            {
                return true;
            }

            offset = after_key;
            if offset >= lower.len() {
                break;
            }
        }
    }
    false
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value
        .trim()
        .trim_matches(&['\'', '"', '`'][..])
        .to_ascii_lowercase();
    lower.is_empty()
        || matches!(
            lower.as_str(),
            "none" | "null" | "todo" | "test" | "changeme"
        )
        || [
            "example",
            "placeholder",
            "change-me",
            "change_me",
            "your_",
            "your-",
            "replace",
            "redacted",
            "dummy",
            "not-a-real",
            "neutral-test",
            "synthetic-test",
            "fixture_",
            "fixture-",
            "test_",
            "test-",
            "xxxx",
            "<secret",
            "<password",
        ]
        .iter()
        .any(|marker| lower.starts_with(marker))
}

fn contains_any(value: &str, markers: &[&str]) -> bool {
    markers.iter().any(|marker| value.contains(marker))
}

fn require_header(
    report: &mut ScanReport,
    headers: &BTreeMap<String, Vec<String>>,
    header: &str,
    severity: Severity,
    rule_id: &str,
    title: &str,
    recommendation: &str,
) {
    if !headers.contains_key(header) {
        report.add(
            severity,
            rule_id,
            title,
            Some(report.target.clone()),
            None,
            recommendation,
        );
    }
}

fn parse_header_blocks(raw: &str) -> Vec<BTreeMap<String, Vec<String>>> {
    let mut blocks = Vec::new();
    for block in raw.split("\r\n\r\n") {
        let mut lines = block.lines();
        if !lines
            .next()
            .is_some_and(|line| line.trim_start().starts_with("HTTP/"))
        {
            continue;
        }
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers
                    .entry(name.trim().to_ascii_lowercase())
                    .or_default()
                    .push(value.trim().to_owned());
            }
        }
        blocks.push(headers);
    }
    blocks
}

fn sanitized_url(url: &Url) -> String {
    let mut clean = url.clone();
    clean.set_query(None);
    clean.set_fragment(None);
    if clean.path().is_empty() {
        clean.set_path("/");
    }
    clean.to_string()
}

fn truncate(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let sanitized = value.replace(['\n', '\r'], " ");
    if sanitized.chars().count() <= max_chars {
        return sanitized;
    }

    // The limit includes the ellipsis character.
    let mut result = sanitized.chars().take(max_chars - 1).collect::<String>();
    result.push('…');
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "qs-security-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp directory");
        path
    }

    #[test]
    fn detects_private_key_without_copying_secret_into_report() {
        let root = temp_dir("private-key");
        let path = root.join("config.txt");
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        // Synthetic base64-looking payload exercises whole-PEM detection without real key material.
        let synthetic_payload = "QUFB".repeat(20);
        let fixture_material = format!("{begin}\n{synthetic_payload}\n{end}\n");
        fs::write(&path, fixture_material).expect("write fixture");
        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan fixture");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SECRET_PRIVATE_KEY"));
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(!json.contains(synthetic_payload.as_str()));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn does_not_flag_private_key_header_in_source_string_literal() {
        let root = temp_dir("private-key-header-literal");
        let path = root.join("body_gate.rs");
        fs::write(
            &path,
            r##"let body = br#"{"note":"-----BEGIN PRIVATE KEY-----\nMIIB"}"#;"##,
        )
        .expect("write source-like fixture");
        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan fixture");
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SECRET_PRIVATE_KEY"));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn secret_assignment_detection_requires_a_complete_key_name() {
        assert!(!has_secret_assignment(
            r#"{"name":"password-hash","version":"0.1.0"}"#
        ));
        assert!(!has_secret_assignment(
            "let private_key = PrivateKeyDer::from_pem_file(key_path)"
        ));
        let assignment_fixture = ["pass", "word = \"", "a-realistic-secret-value", "\""].concat();
        assert!(has_secret_assignment(&assignment_fixture));
        assert!(!has_secret_assignment(
            r#"password = "not-a-real-password""#
        ));
    }

    #[test]
    fn detects_all_seven_additional_sast_patterns() {
        let root = temp_dir("sast-seven-rules");
        let fixture = r#"
os.system("echo " + user_input)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
open(base_dir.join(request.params["filename"]))
ObjectInputStream(input).readObject()
$value = unserialize($data);
value = Marshal.load(data)
digest = md5(value)
session_token = Math.random()
"#;
        fs::write(root.join("sample.py"), fixture).expect("write fixture");

        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan SAST fixture");

        let expected = [
            "CODE_COMMAND_INJECTION_RISK",
            "CODE_SQL_INJECTION_RISK",
            "CODE_PATH_TRAVERSAL_RISK",
            "CODE_UNSAFE_JAVA_DESERIALIZATION",
            "CODE_UNSAFE_PHP_DESERIALIZATION",
            "CODE_UNSAFE_RUBY_DESERIALIZATION",
            "CODE_WEAK_HASH_PRIMITIVE",
            "CODE_INSECURE_RANDOM_SECURITY_CONTEXT",
        ];

        for rule in expected {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == rule),
                "expected SAST rule {rule} to be reported; findings: {:?}",
                report
                    .findings
                    .iter()
                    .map(|f| &f.rule_id)
                    .collect::<Vec<_>>()
            );
        }

        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn does_not_flag_basic_safe_sast_examples() {
        let root = temp_dir("sast-safe-examples");
        let fixture = r#"
subprocess.run(["echo", user_input])
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
open(safe_path)
ObjectInputStream(input)
$value = json_decode($data);
value = Marshal.dump(data)
digest = hashlib.sha256(value)
session_token = secrets.token_urlsafe(32)
"#;
        fs::write(root.join("safe.py"), fixture).expect("write fixture");

        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan safe fixture");

        let prohibited = [
            "CODE_COMMAND_INJECTION_RISK",
            "CODE_SQL_INJECTION_RISK",
            "CODE_PATH_TRAVERSAL_RISK",
            "CODE_UNSAFE_JAVA_DESERIALIZATION",
            "CODE_UNSAFE_PHP_DESERIALIZATION",
            "CODE_UNSAFE_RUBY_DESERIALIZATION",
            "CODE_WEAK_HASH_PRIMITIVE",
            "CODE_INSECURE_RANDOM_SECURITY_CONTEXT",
        ];

        for rule in prohibited {
            assert!(
                !report
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == rule),
                "safe fixture unexpectedly triggered {rule}"
            );
        }

        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn does_not_flag_placeholder_password() {
        let root = temp_dir("placeholder");
        let label_left = ["pass", "word"].concat();
        let label_right = ["change", "-me-", "pass", "word"].concat();
        let assignment_sep = [" ", "=", " "].concat();
        let quote = "\"";
        let newline = "\n";
        let fixture = [
            label_left.as_str(),
            assignment_sep.as_str(),
            quote,
            label_right.as_str(),
            quote,
            newline,
        ]
        .concat();
        fs::write(root.join("config.txt"), fixture).expect("write fixture");
        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan fixture");
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SECRET_HARDCODED_ASSIGNMENT"));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn flags_tls_verification_disabled() {
        let root = temp_dir("tls-disable");
        let fixture = format!("requests.get(url, {}False)\n", "verify=");
        fs::write(root.join("client.py"), fixture).expect("write fixture");
        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan fixture");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "TLS_VERIFICATION_DISABLED"));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn application_audit_recognizes_static_website_without_package_manifest() {
        let root = temp_dir("static-web-profile");
        fs::write(
            root.join("index.html"),
            "<!doctype html><html><head><title>Example</title></head><body>Site</body></html>",
        )
        .expect("write static website entry point");
        fs::create_dir_all(root.join("assets")).expect("create assets directory");
        fs::write(
            root.join("assets/site.css"),
            "body { color: #111; }
",
        )
        .expect("write static stylesheet");

        let report = application_audit(&root, 100, 1024 * 1024).expect("audit static website");
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "APP_TYPE_UNRECOGNIZED"));
        assert!(report.notes.iter().any(|note| {
            note.contains("Static website (HTML/CSS/JavaScript)")
                || note.contains("Static website profile inferred")
        }));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn truncate_bounds_output_and_removes_line_breaks() {
        assert_eq!(truncate("hello\nworld\r", 32), "hello world ");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abcdef", 0), "");
    }

    #[test]
    fn application_audit_reports_missing_cargo_lock() {
        let root = temp_dir("cargo-lock");
        fs::write(root.join("Cargo.toml"), "[package]\nname='sample'\n").expect("write fixture");
        let report = application_audit(&root, 100, 1024 * 1024).expect("audit fixture");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "APP_CARGO_LOCK_MISSING"));
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn website_url_rejects_credentials_and_queries() {
        assert!(website_audit("https://user:secret@example.org/", 10).is_err());
        assert!(website_audit("https://example.org/?token=not-for-logs", 10).is_err());
        assert!(website_audit("file:///etc/passwd", 10).is_err());
    }

    #[test]
    fn parser_keeps_multiple_set_cookie_headers() {
        let parsed = parse_header_blocks(
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=b; Secure\r\nSet-Cookie: c=d\r\n\r\n",
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].get("set-cookie").map(Vec::len), Some(2));
    }
    #[test]
    fn repository_scan_does_not_follow_symlinked_files_or_directories() {
        let root = temp_dir("symlink-root");
        let outside = temp_dir("symlink-outside");
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        let secret = outside.join("secret.txt");
        fs::write(&secret, format!("{begin}\n{}\n{end}\n", "QUFB".repeat(20)))
            .expect("write outside secret");
        std::os::unix::fs::symlink(&secret, root.join("linked-secret.txt"))
            .expect("create file symlink");
        std::os::unix::fs::symlink(&outside, root.join("linked-directory"))
            .expect("create directory symlink");

        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan symlink fixture");
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "SECRET_PRIVATE_KEY"),
            "scanner followed a symlink outside the repository root"
        );
        assert_eq!(
            report.files_scanned, 0,
            "symlinked content must not be read"
        );
        fs::remove_dir_all(root).expect("clean root");
        fs::remove_dir_all(outside).expect("clean outside");
    }

    #[test]
    fn repository_scan_enforces_file_count_bound_and_reports_truncation() {
        let root = temp_dir("file-bound");
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        for index in 0..8 {
            fs::write(
                root.join(format!("secret-{index}.txt")),
                format!("{begin}\n{}\n{end}\n", "QUFB".repeat(20)),
            )
            .expect("write fixture");
        }
        let report = repository_scan(&root, 2, 1024 * 1024).expect("scan bounded fixture");
        assert!(report.files_scanned <= 2, "max_files was not enforced");
        assert!(
            report.scan_truncated,
            "truncation must be reported, not silent"
        );
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn repository_scan_skips_oversized_files_without_reading_secret_material() {
        let root = temp_dir("oversized");
        let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
        let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
        let mut content = format!("{begin}\n{}\n{end}\n", "QUFB".repeat(20));
        content.push_str(&"A".repeat(4096));
        fs::write(root.join("oversized.txt"), content).expect("write oversized fixture");
        let report = repository_scan(&root, 100, 1024).expect("scan oversized fixture");
        assert_eq!(
            report.files_scanned, 0,
            "oversized file must not be scanned"
        );
        assert!(
            report.files_skipped_large >= 1,
            "oversized file must be counted as skipped"
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "SECRET_PRIVATE_KEY"),
            "oversized fixture should not produce findings from a partial read"
        );
        fs::remove_dir_all(root).expect("clean fixture");
    }

    #[test]
    fn repository_scan_stops_at_maximum_depth_and_reports_it() {
        let root = temp_dir("depth-bound");
        let mut current = root.clone();
        for index in 0..70 {
            current = current.join(format!("d{index}"));
            fs::create_dir(&current).expect("create nested directory");
        }
        fs::write(current.join("deep.txt"), "ordinary text\n").expect("write deep fixture");
        let report = repository_scan(&root, 100, 1024 * 1024).expect("scan deep fixture");
        assert!(report.scan_truncated, "depth limit must be reported");
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("maximum directory depth")),
            "depth truncation note missing"
        );
        fs::remove_dir_all(root).expect("clean fixture");
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GitHistoryScanReport {
    pub status: String,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

pub fn git_history_scan(repo_root: &Path) -> Result<GitHistoryScanReport> {
    let mut report = GitHistoryScanReport {
        status: "unknown".to_string(),
        findings: Vec::new(),
        notes: Vec::new(),
    };

    let canonical = repo_root
        .canonicalize()
        .with_context(|| format!("cannot resolve repository path {}", repo_root.display()))?;

    if !canonical.join(".git").exists() {
        report.status = "unavailable".to_string();
        report.notes.push(
            "No .git directory or worktree marker found; Git history scanning unavailable."
                .to_string(),
        );
        return Ok(report);
    }

    // Stream every patch reachable from local refs. Do not fetch remotes,
    // execute external diff/textconv helpers, or print any matched secret.
    let child = Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args([
            "log",
            "--all",
            "--full-history",
            "--patch",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--format=",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();

    match child {
        Ok(mut child) => {
            let stdout = child
                .stdout
                .take()
                .context("could not read Git history output")?;
            let reader = BufReader::new(stdout);
            let mut seen_rules = BTreeSet::new();

            for line_result in reader.lines() {
                let line = line_result.context("could not read streamed Git history")?;

                // Skip diff file headers, then inspect added and deleted content.
                if line.starts_with("+++ ") || line.starts_with("--- ") {
                    continue;
                }
                let Some(changed_line) = line.strip_prefix('+').or_else(|| line.strip_prefix('-'))
                else {
                    continue;
                };
                let candidate = changed_line.trim_start();

                let matched = if candidate.contains("BEGIN")
                    && candidate.contains("PRIVATE KEY")
                    && !looks_like_placeholder(candidate)
                {
                    Some((
                        "GIT_SECRET_PRIVATE_KEY",
                        Severity::Critical,
                        "Private-key material found in Git history",
                        "Remove exposed key material from history using a reviewed history-rewrite procedure, rotate/revoke the key, and investigate its exposure.",
                    ))
                } else if has_known_token(candidate) && !looks_like_placeholder(candidate) {
                    Some((
                        "GIT_SECRET_TOKEN",
                        Severity::High,
                        "Potential secret token found in Git history",
                        "Review and rotate the credential if real. The report intentionally omits the matched value.",
                    ))
                } else if has_secret_assignment(candidate) && !looks_like_placeholder(candidate) {
                    Some((
                        "GIT_SECRET_ASSIGNMENT",
                        Severity::High,
                        "Potential secret assignment found in Git history",
                        "Review and rotate the credential if real. The report intentionally omits the matched value.",
                    ))
                } else {
                    None
                };

                if let Some((rule_id, severity, title, recommendation)) = matched {
                    if seen_rules.insert(rule_id.to_string()) {
                        report.findings.push(Finding {
                            severity,
                            rule_id: rule_id.to_string(),
                            title: title.to_string(),
                            location: Some(format!(
                                "{} (locally reachable Git history)",
                                canonical.display()
                            )),
                            line: None,
                            recommendation: recommendation.to_string(),
                        });
                    }
                }
            }

            let status = child
                .wait()
                .context("could not wait for Git history scan")?;
            report.notes.push(
                "Scanned changed lines across all commits reachable from locally available Git refs; no 50-commit limit. No remote was fetched. Unreachable Git objects and remote history absent from this clone are not included.".to_string(),
            );

            if !status.success() {
                report.status = "failed".to_string();
                report
                    .notes
                    .push("Git history command failed; results may be incomplete.".to_string());
            } else if report.findings.is_empty() {
                report.status = "clean".to_string();
                report.notes.push(
                    "No matches from the Git-history secret-pattern rules. This is not proof that the history contains no secrets.".to_string(),
                );
            } else {
                report.status = "findings".to_string();
            }
        }
        Err(error) => {
            report.status = "unavailable".to_string();
            report.notes.push(format!("git not available: {error}"));
        }
    }

    Ok(report)
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoAuditReport {
    pub status: String,
    pub advisories: Vec<String>,
    pub notes: Vec<String>,
}

pub fn cargo_audit_scan(repo_root: &Path) -> Result<CargoAuditReport> {
    let mut report = CargoAuditReport {
        status: "unknown".to_string(),
        advisories: Vec::new(),
        notes: Vec::new(),
    };
    let output = Command::new("cargo-audit")
        .args(["--json"])
        .current_dir(repo_root)
        .output();
    match output {
        Ok(out) => {
            if !out.status.success() {
                // Try to parse anyway
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("vulnerability") || text.contains("advisory") {
                    report.status = "vulnerabilities".to_string();
                    report.notes.push(
                        "Advisories/vulnerabilities reported (parsed defensively).".to_string(),
                    );
                    return Ok(report);
                }
                report.status = "failed".to_string();
                report
                    .notes
                    .push("cargo-audit failed or returned invalid output.".to_string());
                return Ok(report);
            }
            let text = String::from_utf8_lossy(&out.stdout);
            // Defensive parse - look for vulnerability count
            if text.contains("\"vulnerabilities\"") && text.contains("\"count\"") {
                // Try to detect count
                if text.contains("\"count\": 0") || !text.contains("RUSTSEC") {
                    report.status = "clean".to_string();
                    report
                        .notes
                        .push("cargo-audit completed with no reported advisories.".to_string());
                } else {
                    report.status = "vulnerabilities".to_string();
                    report
                        .notes
                        .push("Vulnerabilities/advisories found.".to_string());
                }
            } else {
                report.status = "clean".to_string();
                report
                    .notes
                    .push("cargo-audit completed (no obvious advisories).".to_string());
            }
        }
        Err(e) => {
            report.status = "unavailable".to_string();
            report
                .notes
                .push(format!("cargo-audit not available: {}", e));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod quantum_shield_git_history_regression {
    use super::git_history_scan;
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TemporaryDirectory(PathBuf);

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("start Git");

        assert!(
            output.status.success(),
            "Git fixture setup failed for command: git {}",
            args.join(" ")
        );
    }

    fn has_nonempty_finding_list(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Object(object) => {
                object.iter().any(|(key, value)| {
                    let key = key.to_ascii_lowercase();
                    let finding_key = key.contains("finding")
                        || key.contains("secret")
                        || key.contains("match")
                        || key.contains("issue");

                    finding_key
                        && value
                            .as_array()
                            .map(|items| !items.is_empty())
                            .unwrap_or(false)
                }) || object.values().any(has_nonempty_finding_list)
            }
            serde_json::Value::Array(items) => items.iter().any(has_nonempty_finding_list),
            _ => false,
        }
    }

    #[test]
    fn git_history_finds_synthetic_private_key_and_redacts_value() {
        const MARKER: &str = "QS_HISTORY_SYNTHETIC_PRIVATE_KEY_DO_NOT_USE_9f8c2a";

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();

        let root = std::env::temp_dir().join(format!(
            "qs-git-history-test-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temporary repository");
        let _cleanup = TemporaryDirectory(root.clone());

        git(&root, &["init", "--quiet"]);
        git(&root, &["config", "user.name", "Quantum Shield Test"]);
        git(&root, &["config", "user.email", "qs-test@example.invalid"]);

        let fixture = format!("-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----\n");
        fs::write(root.join("synthetic-key.txt"), fixture).expect("write synthetic test fixture");

        git(&root, &["add", "--", "synthetic-key.txt"]);
        git(
            &root,
            &[
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "synthetic scanner regression fixture",
            ],
        );

        // Keep the secret in an old commit so a 50-commit scanner would miss it.
        for index in 0..55 {
            fs::write(
                root.join("safe-history-churn.txt"),
                format!("benign history entry {index}\n"),
            )
            .expect("write benign history entry");
            git(&root, &["add", "--", "safe-history-churn.txt"]);
            let message = format!("benign history churn {index}");
            git(
                &root,
                &[
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    &message,
                ],
            );
        }

        let report = git_history_scan(&root).expect("scan temporary Git history");
        let serialized = serde_json::to_string(&report).expect("serialize report");
        let value = serde_json::to_value(&report).expect("convert report to JSON");

        assert!(
            !serialized.contains(MARKER),
            "synthetic private-key material leaked into the report"
        );

        assert!(
            has_nonempty_finding_list(&value),
            "Git-history scan did not report the committed synthetic private-key finding"
        );
    }
}
