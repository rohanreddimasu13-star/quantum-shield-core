//! Bounded request/response body gate.
//! Fail closed. Never log matched secret values.

// The proxy currently applies its body limits inline. This module is kept for
// the planned payload-inspection integration and is covered by unit tests.
#![allow(dead_code)]

use serde_json::Value;

pub const MAX_INSPECT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyDecision {
    Allow,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyClass {
    Json,
    Form,
    Opaque,
}

pub fn classify_content_type(content_type: Option<&str>) -> BodyClass {
    let Some(raw) = content_type else {
        return BodyClass::Opaque;
    };
    let base = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match base.as_str() {
        "application/json" | "application/json-seq" | "text/json" => BodyClass::Json,
        "application/x-www-form-urlencoded" => BodyClass::Form,
        _ => BodyClass::Opaque,
    }
}

/// Inspect a fully buffered body. Oversized input is rejected, not partially scanned.
/// `application/json` that does not parse is rejected. Opaque bodies are allowed through
/// this gate (WAF/size limits still apply elsewhere) so binary and signed payloads are not corrupted.
pub fn inspect_buffered_body(class: BodyClass, body: &[u8]) -> BodyDecision {
    if body.len() > MAX_INSPECT_BYTES {
        return BodyDecision::Reject;
    }
    if body.is_empty() {
        return BodyDecision::Allow;
    }
    match class {
        BodyClass::Opaque => BodyDecision::Allow,
        BodyClass::Json => match serde_json::from_slice::<Value>(body) {
            Ok(value) => {
                if json_contains_secret(&value) {
                    BodyDecision::Reject
                } else {
                    BodyDecision::Allow
                }
            }
            Err(_) => BodyDecision::Reject,
        },
        BodyClass::Form => match std::str::from_utf8(body) {
            Ok(text) => {
                if form_contains_secret(text) {
                    BodyDecision::Reject
                } else {
                    BodyDecision::Allow
                }
            }
            Err(_) => BodyDecision::Reject,
        },
    }
}

fn json_contains_secret(value: &Value) -> bool {
    match value {
        Value::String(text) => looks_like_secret(text),
        Value::Array(items) => items.iter().any(json_contains_secret),
        Value::Object(map) => map.values().any(json_contains_secret),
        _ => false,
    }
}

fn form_contains_secret(text: &str) -> bool {
    for pair in text.split('&') {
        let value = pair.split_once('=').map(|(_, v)| v).unwrap_or(pair);
        let decoded = value.replace('+', " ");
        if looks_like_secret(&decoded) {
            return true;
        }
    }
    false
}

fn looks_like_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("-----begin ")
        || lower.contains("private_key")
        || lower.contains("akid") && text.contains("AKIA")
        || text.contains("AKIA") && text.len() >= 20
        || lower.contains("ghp_")
        || lower.contains("xoxb-")
        || lower.contains("xoxp-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_without_scanning_a_prefix() {
        let body = vec![b'{'; MAX_INSPECT_BYTES + 1];
        assert_eq!(
            inspect_buffered_body(BodyClass::Json, &body),
            BodyDecision::Reject
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(
            inspect_buffered_body(BodyClass::Json, br#"{"a": }"#),
            BodyDecision::Reject
        );
    }

    #[test]
    fn allows_normal_json() {
        assert_eq!(
            inspect_buffered_body(BodyClass::Json, br#"{"user":"ada","n":1}"#),
            BodyDecision::Allow
        );
    }

    #[test]
    fn rejects_json_private_key_marker_without_echoing_it() {
        let body = br#"{"note":"-----BEGIN PRIVATE KEY-----\nMIIB"}"#;
        assert_eq!(
            inspect_buffered_body(BodyClass::Json, body),
            BodyDecision::Reject
        );
    }

    #[test]
    fn rejects_form_token_and_allows_plain_form() {
        assert_eq!(
            inspect_buffered_body(BodyClass::Form, b"name=ada&token=ghp_example"),
            BodyDecision::Reject
        );
        assert_eq!(
            inspect_buffered_body(BodyClass::Form, b"name=ada&ok=1"),
            BodyDecision::Allow
        );
    }

    #[test]
    fn does_not_rewrite_opaque_bytes() {
        let body = [0u8, 1, 2, 255, 10];
        assert_eq!(
            inspect_buffered_body(BodyClass::Opaque, &body),
            BodyDecision::Allow
        );
    }
}
