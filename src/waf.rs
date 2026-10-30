//! QuantumShield Forge - Deep Packet Inspection & Inline Text Sanitization
//! Production-ready streaming WAF with zero-copy chunk inspection and outbound DLP

// The proxy currently uses its inline WAF. This standalone engine is kept for
// the planned module integration and is exercised by its own unit tests.
#![allow(dead_code)]

use anyhow::Result;
use bytes::Bytes;
use http::header::HeaderValue;
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Body as HttpBody;
use regex::RegexSet;
use std::sync::Arc;

#[derive(Clone)]
pub struct WafEngine {
    request_patterns: Arc<RegexSet>,
    dlp_patterns: Arc<Vec<(regex::Regex, &'static str)>>,
}

impl WafEngine {
    pub fn new() -> Result<Self> {
        let request_patterns = RegexSet::new([
            // SQL Injection
            r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|exec\s*\(|xp_cmdshell|'\s*or\s*'1'\s*=\s*'1)",
            // XSS
            r"(?i)(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|<iframe|<img[^>]+onerror)",
            // Command Injection
            r"(?i)(;|\||`|\$\(|&&|\|\|)\s*(cat|ls|wget|curl|nc|bash|sh|cmd|powershell|/bin/)",
            // Path Traversal / LFI
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|/etc/passwd|/etc/shadow|proc/self)",
        ])?;

        let dlp_patterns = vec![
            // Credit Card (basic Luhn-like patterns)
            (regex::Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap(), "[REDACTED-CC]"),
            // SSN
            (regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(), "[REDACTED-SSN]"),
            // AWS Keys
            (regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "[REDACTED-AWS-KEY]"),
            // Database connection strings
            (regex::Regex::new(r"(?i)(mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@[^\s]+").unwrap(), "[REDACTED-DB-CONN]"),
            // Stack traces
            (regex::Regex::new(r"(?i)(stack trace|traceback|exception in thread|fatal error:.*line \d+)").unwrap(), "[REDACTED-STACKTRACE]"),
            // PHP/MySQL errors
            (regex::Regex::new(r"(?i)(Warning|Fatal error):.*mysql_").unwrap(), "[REDACTED-DB-ERROR]"),
        ];

        Ok(Self {
            request_patterns: Arc::new(request_patterns),
            dlp_patterns: Arc::new(dlp_patterns),
        })
    }

    pub fn check_request_chunk(&self, chunk: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(chunk) {
            self.request_patterns.is_match(s)
        } else {
            false
        }
    }

    pub fn redact_response(&self, body: &mut String) {
        for (pattern, replacement) in self.dlp_patterns.iter() {
            *body = pattern.replace_all(body, *replacement).to_string();
        }
    }

    pub fn redact_bytes(&self, bytes: &mut Vec<u8>) {
        if let Ok(mut s) = String::from_utf8(bytes.clone()) {
            let original = s.clone();
            for (pattern, replacement) in self.dlp_patterns.iter() {
                s = pattern.replace_all(&s, *replacement).to_string();
            }
            if s != original {
                *bytes = s.as_bytes().to_vec();
            }
        }
    }
}

pub async fn inspect_request_body_streaming<B>(
    mut body: B,
    waf: Arc<WafEngine>,
) -> Result<Vec<u8>, StatusCode>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: std::fmt::Debug,
{
    let mut buffer = Vec::with_capacity(16 * 1024);
    const MAX_BODY: usize = 16 * 1024 * 1024;

    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if buffer.len() + data.len() > MAX_BODY {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }

                    // Stream inspection - check chunks as they arrive
                    if waf.check_request_chunk(data) {
                        return Err(StatusCode::BAD_REQUEST);
                    }

                    buffer.extend_from_slice(data);
                }
                if frame.is_trailers() {
                    break;
                }
            }
            Some(Err(_)) => return Err(StatusCode::BAD_REQUEST),
            None => break,
        }
    }

    Ok(buffer)
}

pub fn filter_response_headers(headers: &mut http::HeaderMap) {
    // Strip identifying backend headers
    headers.remove("x-powered-by");
    headers.remove("server");
    headers.remove("x-aspnet-version");
    headers.remove("x-aspnetmvc-version");
    headers.remove("x-aspnet-version");
    headers.remove("via");

    // Replace with unified Rust signature
    headers.insert("server", HeaderValue::from_static("QuantumShield-Rust/1.0"));
    headers.insert(
        "x-quantum-shield",
        HeaderValue::from_static("perimeter-gateway"),
    );

    // Security headers
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'"),
    );
}
