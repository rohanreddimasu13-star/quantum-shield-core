use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use url::{Host, Url};

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;
const MAX_SITES_PER_CONFIG: usize = 100;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub id: String,
    pub domain: String,
    pub upstream: String,
}

impl Config {
    /// Validate the declarative configuration only. This function performs no I/O.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                SUPPORTED_SCHEMA_VERSION, self.schema_version
            ));
        }

        if self.sites.is_empty() {
            errors.push("at least one [[sites]] entry is required".to_owned());
        }
        if self.sites.len() > MAX_SITES_PER_CONFIG {
            errors.push(format!(
                "at most {MAX_SITES_PER_CONFIG} sites are supported in one config"
            ));
        }

        let mut ids = HashSet::new();
        let mut domains = HashSet::new();

        for (index, site) in self.sites.iter().enumerate() {
            let prefix = format!("sites[{}]", index + 1);

            if !valid_id(&site.id) {
                errors.push(format!(
                    "{prefix}.id must use 1–63 lowercase ASCII letters, digits, or hyphens; it must start with a letter or digit"
                ));
            } else if !ids.insert(site.id.clone()) {
                errors.push(format!("duplicate site id: {}", site.id));
            }

            match validate_domain(&site.domain) {
                Ok(()) => {
                    let canonical = site.domain.trim_end_matches('.').to_ascii_lowercase();
                    if !domains.insert(canonical) {
                        errors.push(format!("duplicate hostname: {}", site.domain));
                    }
                }
                Err(reason) => errors.push(format!("{prefix}.domain: {reason}")),
            }

            if let Err(reason) = validate_upstream(&site.upstream) {
                errors.push(format!("{prefix}.upstream: {reason}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn valid_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn validate_domain(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 253 {
        return Err("must be a hostname between 1 and 253 bytes".to_owned());
    }
    if value != value.trim() {
        return Err("must not contain leading or trailing whitespace".to_owned());
    }
    if value.contains('*') {
        return Err("wildcard hostnames are not supported in v1".to_owned());
    }
    if value.contains('/') || value.contains(':') || value.contains('@') {
        return Err(
            "provide a hostname only, without a scheme, port, path, or credentials".to_owned(),
        );
    }
    if !value.is_ascii() {
        return Err(
            "internationalized names must be supplied in ASCII IDNA form (punycode)".to_owned(),
        );
    }

    let canonical = value.trim_end_matches('.').to_ascii_lowercase();
    if IpAddr::from_str(&canonical).is_ok() {
        return Err("use a public DNS hostname, not an IP address".to_owned());
    }

    let labels: Vec<&str> = canonical.split('.').collect();
    // `localhost` is accepted so a loopback-only local test configuration can
    // use it as the routed host. Public domain-proof validation rejects it via
    // `validate_public_domain` below.
    if labels.len() < 2 && canonical != "localhost" {
        return Err("must be a fully qualified hostname (for example, app.example.org)".to_owned());
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("contains an empty or overlong DNS label".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS labels must not start or end with a hyphen".to_owned());
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err("contains characters not allowed in a DNS hostname".to_owned());
        }
    }

    Ok(())
}

/// Validate a hostname that is meant to be proven through public DNS.
///
/// Local names are valid for loopback-only test configurations, but they must
/// never satisfy the public domain-proof gate.
// Used by the qsctl binary. The desktop binary embeds this module via
// `#[path]` and does not expose the domain-proof command.
#[allow(dead_code)]
pub fn validate_public_domain(value: &str) -> Result<(), String> {
    validate_domain(value)?;
    let canonical = value.trim_end_matches('.').to_ascii_lowercase();
    if canonical == "localhost" || canonical.ends_with(".localhost") {
        return Err(
            "domain proof requires a public DNS hostname, not localhost or a .localhost name"
                .to_owned(),
        );
    }
    Ok(())
}

/// V1 intentionally permits only local app endpoints and Docker service names.
/// Remote upstreams, proxy credentials, URL query strings and paths are out of scope.
fn validate_upstream(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value)
        .map_err(|_| "must be an absolute URL such as http://127.0.0.1:3000".to_owned())?;

    if parsed.scheme() != "http" {
        return Err(
            "HTTPS upstreams are not supported until verified upstream TLS and trust configuration are available".to_owned(),
        );
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("credentials must not be embedded in upstream URLs".to_owned());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("query strings and fragments are not allowed in upstream URLs".to_owned());
    }
    if parsed.path() != "/" {
        return Err(
            "upstream path prefixes are not supported in v1; use the origin URL only".to_owned(),
        );
    }
    if parsed.port().is_none() {
        return Err("an explicit upstream port is required in v1".to_owned());
    }

    let host = parsed
        .host()
        .ok_or_else(|| "upstream URL must include a host".to_owned())?;

    match host {
        Host::Ipv4(ip) if ip.is_loopback() => return Ok(()),
        Host::Ipv6(ip) if ip.is_loopback() => return Ok(()),
        Host::Ipv4(_) | Host::Ipv6(_) => {
            return Err("IP upstreams must be loopback addresses in v1".to_owned());
        }
        Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => return Ok(()),
        Host::Domain(host) if !host.contains('.') && valid_service_name(host) => return Ok(()),
        Host::Domain(_) => {}
    }

    // A single DNS label is reserved here for a service name on a private container network.
    // Multi-label/public DNS names are rejected to avoid turning this into an open proxy.
    Err("upstream must be loopback (localhost/127.0.0.1/::1) or a single-label Docker service name; remote hosts are disabled in v1".to_owned())
}

fn valid_service_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_site(domain: &str, upstream: &str) -> Config {
        Config {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            sites: vec![SiteConfig {
                id: "demo-site".to_owned(),
                domain: domain.to_owned(),
                upstream: upstream.to_owned(),
            }],
        }
    }

    #[test]
    fn rejects_https_loopback_upstream_until_tls_support_exists() {
        assert!(one_site("example.test", "https://127.0.0.1:3443")
            .validate()
            .is_err());
    }

    #[test]
    fn rejects_https_private_service_upstream_until_tls_support_exists() {
        assert!(one_site("example.test", "https://web:3443")
            .validate()
            .is_err());
    }

    #[test]
    fn accepts_loopback_upstream() {
        assert!(one_site("app.example.org", "http://127.0.0.1:3000")
            .validate()
            .is_ok());
    }

    #[test]
    fn accepts_single_label_container_service() {
        assert!(one_site("app.example.org", "http://web:3000")
            .validate()
            .is_ok());
    }

    #[test]
    fn rejects_public_upstream() {
        let result = one_site("app.example.org", "http://public.example.net:8080").validate();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_non_loopback_ip_upstream() {
        let result = one_site("app.example.org", "http://192.168.1.50:3000").validate();
        assert!(result.is_err());
    }

    #[test]
    fn accepts_ipv6_loopback_upstream() {
        assert!(one_site("app.example.org", "http://[::1]:3000")
            .validate()
            .is_ok());
    }

    #[test]
    fn rejects_upstream_without_explicit_port() {
        let result = one_site("app.example.org", "http://localhost").validate();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_credentials_in_upstream() {
        let result = one_site("app.example.org", "http://user:secret@localhost:3000").validate();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wildcard_hostname() {
        let result = one_site("*.example.org", "http://localhost:3000").validate();
        assert!(result.is_err());
    }

    #[test]
    fn allows_localhost_only_for_local_testing_configs() {
        assert!(one_site("localhost", "http://localhost:3000")
            .validate()
            .is_ok());

        // The public domain-proof path must stay strict even though loopback
        // test configurations may route `localhost`.
        assert!(validate_public_domain("localhost").is_err());
        assert!(validate_public_domain("app.localhost").is_err());
        assert!(validate_public_domain("app.example.org").is_ok());
    }

    #[test]
    fn rejects_duplicate_domain_case_insensitively() {
        let mut cfg = one_site("app.example.org", "http://localhost:3000");
        cfg.sites.push(SiteConfig {
            id: "second".to_owned(),
            domain: "APP.EXAMPLE.ORG".to_owned(),
            upstream: "http://localhost:3001".to_owned(),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut cfg = one_site("app.example.org", "http://localhost:3000");
        cfg.schema_version = 99;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_site_id() {
        let mut cfg = one_site("app.example.org", "http://localhost:3000");
        cfg.sites.push(SiteConfig {
            id: "demo-site".to_owned(),
            domain: "other.example.org".to_owned(),
            upstream: "http://localhost:3001".to_owned(),
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_unknown_toml_fields() {
        let source = r#"
            schema_version = 1
            enable_magic = true
            [[sites]]
            id = "demo"
            domain = "app.example.org"
            upstream = "http://localhost:3000"
        "#;
        assert!(toml::from_str::<Config>(source).is_err());
    }
}
